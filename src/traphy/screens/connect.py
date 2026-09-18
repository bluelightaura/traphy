"""Setting up a target and proving we can reach it.

The form edits a copy and only adopts it on the way out, so backing out of a
half-finished edit leaves the working target alone. Connecting is an explicit
verb rather than something that happens silently on every keystroke: it takes
seconds over SSH, and a person watching a progress bar they asked for is in a
different mood from one watching a screen freeze.

Once the connection is up the interfaces come from the target itself, so ports
are picked from what is there rather than typed from memory.
"""

from __future__ import annotations

import copy
import os

from traphy import engines, ui
from traphy.engines import ixia
from traphy.forms import Field, as_int, edit_form
from traphy.probe import Iface
from traphy.session import Session
from traphy.strings import t
from traphy.target import LINK_RATES, Target, host_key_known, probe_reachable


def target_screen(session: Session) -> None:
    """Edit the target, check it, pick its ports. Returns when backed out of."""
    draft = copy.deepcopy(session.target)
    status: dict[str, str] = {"line": ""}

    def check() -> str:
        result = _connect_with_progress(session, draft)
        status["line"] = result
        return result

    fields = _fields(session, draft)
    edit_form(
        t("form_title"), fields, width=ui.WIDE,
        keys_hint=t("keys_form"),
        header=[ui.c("  " + _summary(session, draft), "dim")],
        extra_keys={"c": check},
    )

    problems = draft.validate()
    if problems:
        ui.notice([ui.c(t("problems"), "bad"), ""]
                  + [ui.c(f"  • {p}", "warn") for p in problems]
                  + ["", ui.c("  " + t("keys_any"), "dim")], ui.WIDE)
    session.remember_target(draft)


def _summary(session: Session, draft: Target) -> str:
    """The line under the form title: where this goes and what answered."""
    if session.host and session.host.ok:
        info = session.host
        head = f"{info.hostname} · {info.kernel} · python {info.python}"
        if engines.get(draft.engine).uses_ifaces:
            return head + " · " + (f"scapy {info.scapy_version}"
                                   if info.has_scapy else "без scapy")
        if draft.engine == "ixia":
            return head + " · " + _ixia_summary(info)
        return head + " · " + _trex_summary(info)
    return draft.endpoint()


def _ixia_summary(info) -> str:
    """Only one thing has to be here; the chassis is checked by the run."""
    if not info.has_ixnetwork:
        return "нет ixnetwork-restpy"
    version = f" {info.ixnetwork_version}" if info.ixnetwork_version else ""
    return f"ixnetwork-restpy{version}"


def _trex_summary(info) -> str:
    """What the target has of TRex, in the order it has to be fixed."""
    if not info.has_trex:
        return "TRex не найден"
    where = info.trex_dir or "TRex"
    version = f" {info.trex_version}" if info.trex_version else ""
    if not info.has_trex_stl:
        return f"{where}{version} - без control plane"
    return f"TRex{version} в {where} · " + ("демон отвечает" if info.trex_daemon
                                            else "демон не поднят")


def _fields(session: Session, d: Target) -> list[Field]:
    """The target form. Setters validate and return a reason on refusal."""
    def name_set(v: str) -> str:
        d.name = v.strip()
        return ""

    def host_set(v: str) -> str:
        d.host = v.strip()
        session.disconnect()
        return ""

    def port_set(v: str) -> str:
        n, err = as_int(v, 1, 65535, t("f_ssh_port"))
        if err:
            return err
        d.ssh_port = n
        return ""

    def link_set(v: str) -> str:
        n, err = as_int(v, 1, 400000, t("f_link"))
        if err:
            return err
        d.link_mbit = n
        return ""

    def ssh_toggle(_v: str) -> str:
        d.use_ssh = not d.use_ssh
        session.disconnect()
        return ""

    def strict_toggle(_v: str) -> str:
        d.strict_host_key = not d.strict_host_key
        if not d.strict_host_key:
            return ("! строгая проверка снята - ключ хоста не сверяется, "
                    "по пути может встать кто угодно")
        return ""

    def sudo_toggle(_v: str) -> str:
        d.use_sudo = not d.use_sudo
        return ""

    def tx_set(_v: str) -> str:
        return _pick_iface(session, d, "tx")

    def rx_set(_v: str) -> str:
        return _pick_iface(session, d, "rx")

    def trex_dir_set(v: str) -> str:
        d.trex_dir = v.strip() or "/opt/trex"
        return ""

    def trex_server_set(v: str) -> str:
        d.trex_server = v.strip() or "127.0.0.1"
        return ""

    def trex_sync_set(v: str) -> str:
        n, err = as_int(v, 1, 65535, t("f_trex_sync"))
        if err:
            return err
        d.trex_sync_port = n
        return ""

    def trex_tx_set(v: str) -> str:
        n, err = as_int(v, 0, 63, t("f_trex_tx"))
        if err:
            return err
        d.trex_port_tx = n
        return ""

    def trex_rx_set(v: str) -> str:
        """-1 is a real answer here: "nobody is counting the receive side"."""
        if v.strip() in ("-", "-1", "нет"):
            d.trex_port_rx = -1
            return "! приём не измеряется - потери считать будет нечем"
        n, err = as_int(v, 0, 63, t("f_trex_rx"))
        if err:
            return err
        d.trex_port_rx = n
        if n == d.trex_port_tx:
            return ("! тот же порт, что и отправка - счётчик поймает "
                    "собственную отправку, а не то, что вернулось")
        return ""

    def ixia_api_set(v: str) -> str:
        d.ixia_api_host = v.strip()
        session.disconnect()
        return ""

    def ixia_api_port_set(v: str) -> str:
        n, err = as_int(v, 1, 65535, t("f_ixia_api_port"))
        if err:
            return err
        d.ixia_api_port = n
        return ""

    def ixia_user_set(v: str) -> str:
        """Empty means a server that wants no login at all, which is the
        ordinary Windows case - so clearing it has to be possible."""
        d.ixia_api_user = "" if v.strip() in ("-", "нет") else v.strip()
        if d.ixia_api_user and not os.environ.get(ixia.PASSWORD_ENV):
            return f"! пароль возьмётся из {ixia.PASSWORD_ENV} - его там нет"
        return ""

    def ixia_chassis_set(v: str) -> str:
        d.ixia_chassis = v.strip()
        return ""

    def ixia_port_set(which: str):
        def setter(v: str) -> str:
            if ixia.parse_port(v) is None:
                return "! порт задаётся как карта/порт, например 1/2"
            setattr(d, f"ixia_port_{which}", v.strip().replace(":", "/"))
            if ixia.parse_port(d.ixia_port_tx) == ixia.parse_port(d.ixia_port_rx):
                return "! тот же порт, что и вторая сторона - принимать некуда"
            return ""
        return setter

    def ixia_force_toggle(_v: str) -> str:
        d.ixia_force = not d.ixia_force
        if d.ixia_force:
            return ("! порт будет отобран у владельца - если на нём сейчас "
                    "чей-то замер, он сломается и человек не узнает почему")
        return ""

    remote = lambda: d.use_ssh
    by_iface = lambda: engines.get(d.engine).uses_ifaces
    by_trex = lambda: d.engine == "trex"
    by_ixia = lambda: d.engine == "ixia"

    def engine_set(v: str) -> str:
        d.engine = v
        session.disconnect()
        engine = engines.get(v)
        return "" if engine.ready else f"! {engine.title} {engine.status}"

    return [
        Field("name", t("f_name"), lambda: d.name, name_set),
        Field("engine", t("f_engine"), lambda: _engine_label(d), engine_set,
              kind="pick", options=engines.options(),
              hint="Scapy - L2-L4 своими кадрами; остальные пока заявлены"),
        Field("use_ssh", t("f_use_ssh"), lambda: _yn(d.use_ssh), ssh_toggle,
              kind="toggle",
              hint="выключено - трафик уходит с этой машины"),
        Field("host", t("f_host"), lambda: d.host or t("unset"), host_set,
              visible=remote),
        Field("ssh_user", t("f_ssh_user"), lambda: d.ssh_user or t("unset"),
              lambda v: (setattr(d, "ssh_user", v.strip()), "")[1], visible=remote),
        Field("ssh_port", t("f_ssh_port"), lambda: str(d.ssh_port), port_set,
              visible=remote),
        Field("ssh_key", t("f_ssh_key"), lambda: d.ssh_key or "агент/по умолчанию",
              lambda v: (setattr(d, "ssh_key", v.strip()), "")[1], visible=remote),
        Field("strict", t("f_strict"), lambda: _yn(d.strict_host_key),
              strict_toggle, kind="toggle", visible=remote,
              hint="хост должен уже быть в known_hosts"),
        Field("python", t("f_python"), lambda: d.python,
              lambda v: (setattr(d, "python", v.strip() or "python3"), "")[1]),
        Field("sudo", t("f_sudo"), lambda: _yn(d.use_sudo), sudo_toggle,
              kind="toggle", visible=by_iface,
              hint="сырой сокет без root не открыть"),
        Field("tx", t("f_tx"), lambda: _iface_label(session, d.tx_iface), tx_set,
              visible=by_iface, hint="↵ - список интерфейсов с цели"),
        Field("rx", t("f_rx"),
              lambda: _iface_label(session, d.rx_iface) if d.rx_iface else t("rx_unset"),
              rx_set, visible=by_iface,
              hint="без него счётчик потерь ничего не значит"),

        # TRex owns its NICs through DPDK, so they are gone from
        # /sys/class/net and there is no interface list to pick from - the
        # port is an index and the release has to be named.
        Field("trex_dir", t("f_trex_dir"), lambda: d.trex_dir, trex_dir_set,
              visible=by_trex, hint="распакованный релиз, внутри automation/"),
        Field("trex_server", t("f_trex_server"), lambda: d.trex_server,
              trex_server_set, visible=by_trex,
              hint="адрес с точки зрения самой цели - обычно тут же"),
        Field("trex_sync", t("f_trex_sync"), lambda: str(d.trex_sync_port),
              trex_sync_set, visible=by_trex),
        Field("trex_tx", t("f_trex_tx"), lambda: str(d.trex_port_tx),
              trex_tx_set, visible=by_trex, hint="индекс порта, не имя NIC"),
        Field("trex_rx", t("f_trex_rx"),
              lambda: (str(d.trex_port_rx) if d.trex_port_rx >= 0
                       else t("trex_rx_unset")),
              trex_rx_set, visible=by_trex,
              hint="«-» чтобы не мерить приём вовсе"),

        # Ixia is an address in a rack rather than a machine: an API server to
        # configure through, a chassis the cards live in, and a card/port pair
        # for each side. There is nothing here to log into.
        Field("ixia_api", t("f_ixia_api"),
              lambda: d.ixia_api_host or t("unset"), ixia_api_set,
              visible=by_ixia, hint="Windows GUI или Linux API server"),
        Field("ixia_api_port", t("f_ixia_api_port"),
              lambda: str(d.ixia_api_port), ixia_api_port_set, visible=by_ixia,
              hint="11009 у Windows, 443 у Linux"),
        Field("ixia_user", t("f_ixia_user"),
              lambda: d.ixia_api_user or "без авторизации", ixia_user_set,
              visible=by_ixia,
              hint=f"пароль не хранится - берётся из {ixia.PASSWORD_ENV}"),
        Field("ixia_chassis", t("f_ixia_chassis"),
              lambda: d.ixia_chassis or t("unset"), ixia_chassis_set,
              visible=by_ixia),
        Field("ixia_tx", t("f_ixia_tx"), lambda: d.ixia_port_tx,
              ixia_port_set("tx"), visible=by_ixia),
        Field("ixia_rx", t("f_ixia_rx"), lambda: d.ixia_port_rx,
              ixia_port_set("rx"), visible=by_ixia,
              hint="обязателен: без него traffic item не собрать"),
        Field("ixia_force", t("f_ixia_force"), lambda: _yn(d.ixia_force),
              ixia_force_toggle, kind="toggle", visible=by_ixia,
              hint="шасси общее - по умолчанию чужой порт не трогаем"),
        Field("link", t("f_link"), lambda: str(d.link_mbit), link_set,
              kind="pick", options=rate_options(),
              hint="нужно только чтобы посчитать «% от линии»"),
    ]


def _engine_label(d: Target) -> str:
    engine = engines.get(d.engine)
    return engine.title if engine.ready else f"{engine.title} ⊘ {engine.status}"


def _yn(value: bool) -> str:
    return t("yes") if value else t("no")


def _iface_label(session: Session, name: str) -> str:
    """An interface name plus what the target said about it, when we know."""
    if not name:
        return t("unset")
    found = _find(session, name)
    return f"{name}  ({found.describe()})" if found else name


def _find(session: Session, name: str) -> Iface | None:
    if not session.host:
        return None
    return next((i for i in session.host.ifaces if i.name == name), None)


def _pick_iface(session: Session, d: Target, which: str) -> str:
    """Choose an interface from the target's own list, or type one in.

    Without a live connection there is nothing to list, so this falls back to
    a prompt rather than pretending: the operator may well know the name and
    be setting the target up before the box is even powered.
    """
    label = t("f_tx") if which == "tx" else t("f_rx")
    if not (session.host and session.host.ok and session.host.ifaces):
        typed = ui.ask_line(f"{label}: ")
        if typed:
            _assign(d, which, typed.strip())
        return "! связи с целью нет - список интерфейсов не получен" if not typed else ""

    ifaces = session.host.usable_ifaces()
    options = [(i.name, i.describe()) for i in ifaces]
    if which == "rx":
        options.insert(0, (t("unset"), "потери не измеряются"))
    now = _current(d, which)
    current = next((n for n, (name, _hint) in enumerate(options) if name == now), 0)
    picked = ui.choose(label, options, cursor=current,
                       keys_hint=t("keys_pick"), width=ui.WIDE)
    if picked is None:
        return ""
    chosen = options[picked][0]
    _assign(d, which, "" if chosen == t("unset") else chosen)
    return _iface_warning(session, d, which)


def _current(d: Target, which: str) -> str:
    return d.tx_iface if which == "tx" else d.rx_iface


def _assign(d: Target, which: str, value: str) -> None:
    if which == "tx":
        d.tx_iface = value
    else:
        d.rx_iface = value


def _iface_warning(session: Session, d: Target, which: str) -> str:
    """Say the awkward thing now rather than after a run comes back empty."""
    name = _current(d, which)
    if not name:
        return ""
    found = _find(session, name)
    if found and not found.is_up:
        return f"! {name} не поднят - трафик по нему не пойдёт"
    if which == "rx" and name == d.tx_iface:
        return ("! приём и отправка на одном интерфейсе - "
                "посчитается собственный трафик, а не то, что вернулось")
    return ""


# --------------------------------------------------------------------------- #
# Connecting
# --------------------------------------------------------------------------- #
def _connect_with_progress(session: Session, draft: Target) -> str:
    """Reach the target, showing what stage it is at. Returns a status line.

    Three stages, and each one is a different failure to report: the address
    does not answer, the login does not work, or the box answers but has no
    Scapy. Collapsing them into "failed" would leave the operator guessing.
    """
    problems = draft.validate()
    if problems:
        return "! " + problems[0]

    session.target = draft
    if not draft.is_local and draft.strict_host_key and not host_key_known(
            draft.host, draft.ssh_port):
        answer = ui.notice([
            ui.c(f"  Ключа {draft.host} нет в known_hosts", "warn"), "",
            "  Строгая проверка откажет в соединении. Подключись один раз",
            f"  вручную - ssh {draft.ssh_user}@{draft.host} - и вернись сюда.",
            "", ui.c("  " + t("keys_any"), "dim"),
        ], ui.WIDE)
        del answer
        return "! ключ хоста не известен"

    _progress(draft, 0.1, "открываю соединение")
    reachable, why = probe_reachable(draft, on_progress=None)
    if not reachable:
        session.host = None
        return f"! {why}"

    _progress(draft, 0.5, "опрашиваю цель")
    ok, message = session.connect()
    if not ok:
        return f"! {message}"

    _progress(draft, 1.0, "готово")
    blockers = session.host.blockers() if session.host else []
    if blockers:
        return "! " + blockers[0]
    return message


def _progress(target: Target, fraction: float, stage: str) -> None:
    """One frame of the connect bar, drawn on its own so the wait has a face."""
    ui.draw(ui.panel([
        ui.c(t("checking", host=target.endpoint()), "title"), "",
        "  " + ui.bar(fraction, 40),
        ui.c(f"  {stage}", "dim"),
    ], ui.WIDE))


def rate_options() -> list[tuple[str, str]]:
    """The link rates the form offers, for the "% of line" arithmetic."""
    return [(str(r), f"{r // 1000} Гбит/с" if r >= 1000 else f"{r} Мбит/с")
            for r in LINK_RATES]
