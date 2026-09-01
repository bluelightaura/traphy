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

from traphy import engines, ui
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
        return (f"{info.hostname} · {info.kernel} · python {info.python} · "
                + (f"scapy {info.scapy_version}" if info.has_scapy else "без scapy"))
    return draft.endpoint()


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

    remote = lambda: d.use_ssh

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
              kind="toggle", hint="сырой сокет без root не открыть"),
        Field("tx", t("f_tx"), lambda: _iface_label(session, d.tx_iface), tx_set,
              hint="↵ - список интерфейсов с цели"),
        Field("rx", t("f_rx"),
              lambda: _iface_label(session, d.rx_iface) if d.rx_iface else t("rx_unset"),
              rx_set,
              hint="без него счётчик потерь ничего не значит"),
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
