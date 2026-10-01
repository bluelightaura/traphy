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


# Заголовки групп формы цели. Порядок полей задают сами поля; карта только
# говорит, к какой группе относится каждое.
#
# Почему приём назван «где ловим», а не «куда шлём»: кадры уходят в устройство
# под тестом, а этот порт - второй порт того же генератора, куда они
# возвращаются. Назвать его «куда шлём» значило бы описать не ту топологию, и
# человек пошёл бы искать на нём адрес получателя. Адрес получателя - в кадре,
# на экране сборки.
SEND = "ОТКУДА ШЛЁМ - машина и доступ к ней"
GEN = "ГЕНЕРАТОР НА НЕЙ"
TX = "ЧЕМ ШЛЁМ"
RX = "ГДЕ ЛОВИМ - второй порт генератора, между ними устройство под тестом"
LINE = "ЛИНИЯ"

SECTIONS = {
    "use_ssh": SEND, "host": SEND, "ssh_user": SEND, "ssh_port": SEND,
    "ssh_key": SEND, "ssh_password": SEND, "strict": SEND,
    "fingerprint": SEND, "python": SEND, "sudo": SEND,

    "trex_dir": GEN, "trex_server": GEN, "trex_sync": GEN,
    "ixia_api": GEN, "ixia_api_port": GEN, "ixia_user": GEN,
    "ixia_chassis": GEN,

    "tx": TX, "trex_tx": TX, "ixia_tx": TX,

    "rx": RX, "trex_rx": RX, "ixia_rx": RX,
    "trex_force": RX, "ixia_force": RX,

    "link": LINE,
}


def target_screen(session: Session) -> None:
    """Edit the target, check it, pick its ports. Returns when backed out of."""
    draft = copy.deepcopy(session.target)
    status: dict[str, str] = {"line": ""}

    # Наблюдатель один на программу и уже работает - он живёт в сеансе. Пока
    # форма открыта, он смотрит на ЧЕРНОВИК: правят обычно именно адрес, и
    # индикатор, описывающий сохранённую цель, отвечал бы не на тот вопрос.
    session.watching = draft

    def link_line() -> list[str]:
        text, role = session.link_line()
        return [ui.c("  " + text, role)]

    def check() -> str:
        result = _connect_with_progress(session, draft)
        # Машина только что рассказала о себе - сверить с тем, что записано в
        # цели, надо здесь же. Иначе человек узнаёт о расхождении, когда прогон
        # уже не пошёл, и ищет причину в стенде.
        if session.host and session.host.ok:
            apart = draft.disagrees_with(session.host)
            if apart:
                result = (f"{result}  ·  машина говорит иначе: "
                          f"{'; '.join(apart)} — p подхватит")
        status["line"] = result
        return result

    def pick() -> str:
        """Взять другую сохранённую цель, не перенабирая её поля.

        Два режима Scapy - «шлём отсюда» и «шлём с той машины» - это две
        разные цели, и переключаться между ними приходится постоянно. Пока
        выбора не было, каждое переключение означало перенабор адреса,
        логина и обоих интерфейсов, то есть шанс ошибиться в них.
        """
        names = session.store.list()
        if not names:
            return "сохранённых целей нет"
        options = []
        for name in names:
            saved = session.store.try_load(name)
            options.append((name, saved.endpoint() if saved else "не читается"))
        chosen = ui.choose(t("pick_target"), options,
                           keys_hint=t("keys_pick"), width=ui.WIDE)
        if chosen is None:
            return ""
        saved = session.store.try_load(names[chosen])
        if saved is None:
            return f"цель «{names[chosen]}» не читается"
        # Поля формы смотрят в этот самый объект, поэтому его наполняют, а не
        # подменяют: подмена оставила бы форму показывать прежнюю цель.
        draft.__dict__.update(copy.deepcopy(saved).__dict__)
        session.disconnect()
        status["line"] = ""
        return f"цель: {draft.name} · {draft.endpoint()}"

    def adopt() -> str:
        """Подтянуть с цели то, что она может рассказать о себе сама.

        Требует связи: подхватывать нечего, пока никто не ответил. Поэтому при
        закрытой связи сначала подключаемся - это ровно то же, что делает «c».
        """
        if not (session.host and session.host.ok):
            problem = _connect_with_progress(session, draft)
            status["line"] = problem
            if not (session.host and session.host.ok):
                return problem or "! связи с целью нет - подхватывать нечего"
        changed = draft.adopt(session.host)
        if not changed:
            return "цель уже описывает то, что на машине"
        return "подхвачено — " + "; ".join(changed)

    fields = _fields(session, draft)
    for f in fields:
        f.section = SECTIONS.get(f.key, "")
    session.start_watch()
    try:
        edit_form(
            t("form_title"), fields, width=ui.WIDE,
            keys_hint=t("keys_form"),
            # Функцией, а не списком: цель на этом экране меняется - её можно
            # выбрать заново или отредактировать поля, - и шапка, посчитанная
            # один раз при открытии, после этого описывает уже не то, что в форме.
            header=lambda: [ui.c("  " + _summary(session, draft), "dim"),
                            *link_line()],
            extra_keys={"c": check, "t": pick, "p": adopt},
            # Полсекунды: индикатор должен двигаться заметно, но перерисовка
            # чаще этого - работа впустую, проверка всё равно раз в две секунды.
            tick=0.5,
        )
    finally:
        # Наблюдателя не останавливаем - он общий и нужен главному экрану;
        # возвращаем ему цель вместо нашего черновика.
        session.watching = None

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

    def password_set(v: str) -> str:
        """Пароль живёт в сеансе и только в нём.

        В файл цели он не попадает никогда - это тот же принцип, по которому
        пароль Ixia читается из окружения: файл цели лежит в каталоге состояния
        и его легко скопировать, показать, приложить к письму.
        """
        typed = v.strip()
        if typed == "-":
            session.password, session.password_from = "", ""
            session.disconnect()
            return "пароль убран - вход пойдёт ключом или агентом"
        if not typed:
            return ""
        session.password, session.password_from = typed, "typed"
        session.disconnect()
        return "пароль принят на этот сеанс"

    def password_label() -> str:
        if not session.password:
            return t("pw_unset")
        # "env" здесь - откуда пароль взялся, а не сам пароль.
        if session.password_from == "env":  # nosec B105
            return t("pw_env")
        return t("pw_set")

    def where_set(v: str) -> str:
        want = v == "ssh"
        if want != d.use_ssh:
            d.use_ssh = want
            session.disconnect()
        return ""

    def ssh_toggle(_v: str) -> str:
        d.use_ssh = not d.use_ssh
        session.disconnect()
        return ""

    def host_key_toggle(_v: str) -> str:
        """Cycle the two modes. There is no third, and that is the point.

        The old toggle had an off position that accepted whatever answered and
        wrote nothing down, so the next connection was just as blind. What
        replaced it accepts a new host once and remembers it - after which a
        changed key is refused, which is the case the off position could never
        notice.
        """
        d.host_key = "accept-new" if d.host_key == "strict" else "strict"
        if d.host_key == "accept-new":
            return ("! незнакомый ключ будет принят один раз и записан в "
                    "known_hosts; изменившийся ключ отвергнут в любом режиме")
        return ""

    def sudo_toggle(_v: str) -> str:
        d.use_sudo = not d.use_sudo
        return ""

    def iface_set(which: str):
        def go(v: str) -> str:
            value = v.strip()
            _assign(d, which, "" if value == t("unset") else value)
            return _iface_warning(session, d, which)
        return go

    def iface_suggest(which: str):
        """Интерфейсы, которые назвала сама цель, когда её опрашивали.

        Пока опроса не было, предлагать нечего - и врать тоже: список берётся с
        железки, а не из догадки. Тогда выборка покажет то, что вводилось
        раньше, и ручной ввод: цель заводят и до того, как коробку включили.
        """
        def go() -> list[tuple[str, str]]:
            out: list[tuple[str, str]] = []
            if which == "rx":
                out.append((t("unset"), "потери не измеряются"))
            host = session.host
            if host and host.ok:
                out += [(i.name, i.describe()) for i in host.usable_ifaces()]
            return out
        return go

    def iface_hint(which: str):
        def go() -> str:
            host = session.host
            if host and host.ok and host.ifaces:
                return f"список с цели: {len(host.usable_ifaces())} шт."
            if which == "rx":
                return "без него счётчик потерь ничего не значит"
            return "связи нет - опроси цель (c), тогда список придёт с неё"
        return go

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

    def trex_force_toggle(_v: str) -> str:
        d.trex_force = not d.trex_force
        if d.trex_force:
            return ("! порты будут отобраны у владельца - если на них сейчас "
                    "чей-то замер, он сломается и человек не узнает почему")
        return ""

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
        # Два названных варианта вместо «да/нет»: вопрос тут не «включить SSH»,
        # а «откуда уходят кадры», и ответ «нет» на него не отвечает.
        Field("use_ssh", t("f_use_ssh"),
              lambda: t("w_ssh") if d.use_ssh else t("w_local"),
              where_set, kind="pick", raw=lambda: "ssh" if d.use_ssh else "local",
              options=[("local", t("w_local"), t("w_local_hint")),
                       ("ssh", t("w_ssh"), t("w_ssh_hint"))]),
        Field("host", t("f_host"), lambda: d.host or t("unset"), host_set,
              visible=remote, raw=lambda: d.host),
        Field("ssh_user", t("f_ssh_user"), lambda: d.ssh_user or t("unset"),
              lambda v: (setattr(d, "ssh_user", v.strip()), "")[1], visible=remote,
              raw=lambda: d.ssh_user, suggest=("root",)),
        Field("ssh_port", t("f_ssh_port"), lambda: str(d.ssh_port), port_set,
              visible=remote, suggest=("22",)),
        Field("ssh_key", t("f_ssh_key"), lambda: d.ssh_key or "агент/по умолчанию",
              lambda v: (setattr(d, "ssh_key", v.strip()), "")[1], visible=remote,
              raw=lambda: d.ssh_key),
        # Пароль - в сеансе, не в цели. Показывается словом, вводится скрыто,
        # не запоминается и не предлагается: список прошлых паролей на экране -
        # ровно то, чего быть не должно.
        Field("ssh_password", t("f_ssh_password"), password_label,
              password_set, secret=True, remember=False, visible=remote,
              hint="вводится скрыто, в файл цели не пишется; «-» чтобы убрать"),
        Field("strict", t("f_strict"), lambda: d.host_key,
              host_key_toggle, kind="toggle", visible=remote,
              hint="strict - хост обязан быть в known_hosts; "
                   "accept-new - принять незнакомый один раз и запомнить"),
        Field("fingerprint", t("f_fingerprint"),
              lambda: d.host_key_fingerprint or "не закреплён",
              lambda v: (setattr(d, "host_key_fingerprint", v.strip()), "")[1],
              visible=remote,
              hint="SHA256:... - машина обязана показать именно этот ключ"),
        Field("python", t("f_python"), lambda: d.python,
              lambda v: (setattr(d, "python", v.strip() or "python3"), "")[1],
              suggest=("python3", "python3.11", "python3.9")),
        Field("sudo", t("f_sudo"), lambda: _yn(d.use_sudo), sudo_toggle,
              kind="toggle", visible=by_iface,
              hint="сырой сокет без root не открыть"),
        Field("tx", t("f_tx"), lambda: _iface_label(session, d.tx_iface),
              iface_set("tx"), visible=by_iface, raw=lambda: d.tx_iface,
              suggest=iface_suggest("tx"), hint=iface_hint("tx")),
        Field("rx", t("f_rx"),
              lambda: _iface_label(session, d.rx_iface) if d.rx_iface else t("rx_unset"),
              iface_set("rx"), visible=by_iface, raw=lambda: d.rx_iface,
              suggest=iface_suggest("rx"), hint=iface_hint("rx")),

        # TRex owns its NICs through DPDK, so they are gone from
        # /sys/class/net and there is no interface list to pick from - the
        # port is an index and the release has to be named.
        Field("trex_dir", t("f_trex_dir"), lambda: d.trex_dir, trex_dir_set,
              visible=by_trex, hint="распакованный релиз, внутри automation/",
              # Один обычный путь и всё: каталог релиза у каждого свой, и
              # вводившийся раньше окажется в списке сам.
              suggest=("/opt/trex",)),
        Field("trex_server", t("f_trex_server"), lambda: d.trex_server,
              trex_server_set, visible=by_trex,
              hint="адрес с точки зрения самой цели - обычно тут же",
              suggest=("127.0.0.1",)),
        Field("trex_sync", t("f_trex_sync"), lambda: str(d.trex_sync_port),
              trex_sync_set, visible=by_trex, suggest=("4501",)),
        Field("trex_tx", t("f_trex_tx"), lambda: str(d.trex_port_tx),
              trex_tx_set, visible=by_trex,
              hint="индекс из trex_cfg.yaml, не имя карты - p спросит у демона",
              suggest=("0", "1")),
        Field("trex_rx", t("f_trex_rx"),
              lambda: (str(d.trex_port_rx) if d.trex_port_rx >= 0
                       else t("trex_rx_unset")),
              trex_rx_set, visible=by_trex,
              hint="«-» чтобы не мерить приём вовсе",
              suggest=(("1", "обычно второй порт"), ("-", "не мерить приём"))),
        Field("trex_force", t("f_trex_force"), lambda: _yn(d.trex_force),
              trex_force_toggle, kind="toggle", visible=by_trex,
              hint="выключено - занятый чужим прогоном порт не отбирается"),

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
    if not draft.is_local and draft.host_key == "strict" and not host_key_known(
            draft.host, draft.ssh_port):
        answer = ui.notice([
            ui.c(f"  Ключа {draft.host} нет в known_hosts", "warn"), "",
            "  Строгий режим откажет в соединении. Либо подключись один раз",
            f"  вручную - ssh {draft.ssh_user}@{draft.host} - либо поставь",
            "  режим accept-new: он примет ключ однажды и запомнит его.",
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
    # Спрашивать надо у ТОГО движка, которым будем гнать. Без этого берётся
    # умолчание - Scapy, - и цель с TRex получала «на цели нет Scapy, поставь
    # pip install scapy», хотя клиенту демона он не нужен вовсе. В CLI движок
    # передавался, в меню нет.
    blockers = session.host.blockers(draft.engine) if session.host else []
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
