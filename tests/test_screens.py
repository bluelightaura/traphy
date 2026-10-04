"""Каждый экран обязан собираться. Не «выглядеть хорошо» - именно собираться.

Проверка дешёвая и намеренно тупая: отрисовка в этом интерфейсе - чистая
функция, значит кадр можно получить строкой без терминала и без нажатий. Она не
заменяет живой проход и не проверяет ни одной клавиши; она ловит то, что иначе
ловится только собой на стенде - экран, разваливающийся на поле, которого в
этом сочетании не бывает.

Поводом был настоящий случай: форма цели для TRex показывала поля, посчитанные
один раз при открытии, и после смены движка описывала уже не то. Такие вещи
видно, только если собрать все сочетания разом.
"""

from __future__ import annotations

import pytest

from traphy import engines, forms, menu, presets, ui
from traphy.runner import RunResult
from traphy.forms import Field
from traphy.models import RateType
from traphy.screens import compose, connect, execute
from traphy.session import Session
from traphy.target import Target

ENGINES = ("scapy", "trex", "ixia")
SOURCES = ("flow_stats", "flow_stats_blind", "flow_stats_unverified",
           "flow_stats_tainted", "port_counter", "mixed", "partial", "marker",
           "none")


@pytest.fixture
def session() -> Session:
    s = Session(version="0.1.0")
    s.load()
    s.profile = presets.build("l3_ip")
    return s


def framed(text: str) -> list[str]:
    """Строки кадра без управляющих последовательностей."""
    import re

    return [re.sub(r"\x1b\[[0-9;]*m", "", line) for line in text.splitlines()]


# --------------------------------------------------------------------------- #
# Главное меню
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cursor", range(len(menu.ROWS)))
def test_the_launcher_draws_with_the_cursor_anywhere(session, cursor):
    lines = framed(menu._render(session, cursor))
    assert lines[0].startswith("╭") and lines[-1].startswith("╰")
    marked = [ln for ln in lines if "▸" in ln]
    assert len(marked) == 1, "курсор обязан стоять ровно в одной строке"


def test_every_launcher_row_belongs_to_a_section():
    """Строка без раздела провалилась бы под чужой заголовок - и читалась бы
    как часть не той работы."""
    assert all(row.section for row in menu.ROWS)


# --------------------------------------------------------------------------- #
# Форма цели: все движки, локально и по SSH
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("ssh", [False, True])
def test_the_target_form_draws_for_every_engine(session, engine, ssh):
    draft = Target(name="цель", engine=engine, use_ssh=ssh, host="10.0.0.9")
    session.target = draft
    rows = [f for f in connect._fields(session, draft) if f.shown()]
    assert rows, f"{engine}: форма пустая"
    for f in rows:
        f.section = connect.SECTIONS.get(f.key, "")
        f.get()                      # значение читается без связи с целью
    framed(forms._render("Цель", rows, 0, "", ui.WIDE, None, "", 26))


@pytest.mark.parametrize("engine", ENGINES)
def test_every_shown_field_is_filed_under_a_section(session, engine):
    """Поле без раздела печатается под заголовком предыдущего - то есть
    оказывается в группе, к которой не относится."""
    draft = Target(name="цель", engine=engine, use_ssh=True, host="10.0.0.9")
    session.target = draft
    missing = [f.key for f in connect._fields(session, draft)
               if f.shown() and f.key not in connect.SECTIONS
               and f.key not in ("name", "engine")]
    assert not missing, f"{engine}: без раздела остались {missing}"


def test_a_local_target_hides_what_only_makes_sense_over_ssh(session):
    draft = Target(name="цель", engine="scapy", use_ssh=False)
    session.target = draft
    shown = {f.key for f in connect._fields(session, draft) if f.shown()}
    assert not shown & {"host", "ssh_user", "ssh_port", "ssh_password",
                        "strict", "fingerprint"}


# --------------------------------------------------------------------------- #
# Сборка кадра
# --------------------------------------------------------------------------- #
def test_the_packet_and_rate_forms_draw(session):
    stream = session.profile.streams[0]
    engine = engines.get(session.target.engine)
    for title, fields in (("Кадр", compose.packet_fields(stream)),
                          ("Скорость", compose.rate_fields(
                              stream, engine, session.target.link_mbit))):
        rows = [f for f in fields if f.shown()]
        assert rows
        framed(forms._render(title, rows, 0, "", ui.WIDE, None, "", 26))


@pytest.mark.parametrize("key", list(presets.keys()))
def test_every_preset_can_be_described_and_previewed(key):
    """Пресет, который нельзя показать, нельзя и выбрать осмысленно."""
    for stream in presets.build(key).streams:
        assert compose._describe(stream)
        assert compose._preview(stream)


# --------------------------------------------------------------------------- #
# Итог прогона
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("source", SOURCES)
def test_every_receive_source_has_something_to_say(source):
    """Источник без своей формулировки проваливался бы в чужую ветку - именно
    так отчёт однажды советовал задать уже заданный порт приёма."""
    r = RunResult(engine="trex", rx_source=source, reliable=False,
                  tx_pkts=1000, rx_pkts=995, seconds=5.0,
                  requested_pps=1000, achieved_pps=990)
    assert r.summary()
    for line in r.warnings():
        assert line and line.strip() == line


def test_a_trustworthy_run_says_the_loss_plainly():
    r = RunResult(engine="trex", rx_source="flow_stats", reliable=True,
                  tx_pkts=1000, rx_pkts=995, seconds=5.0)
    assert "потери 0.50%" in r.summary()


def test_the_blockers_are_asked_of_the_engine_that_will_actually_send():
    """Найдено живым проходом 2026-10-01. Цель с TRex сообщала «на цели нет
    Scapy - поставь pip install scapy», хотя клиенту демона Scapy не нужен:
    блокеры спрашивались у движка по умолчанию, а не у выбранного."""
    from traphy.probe import HostInfo

    info = HostInfo(ok=True, hostname="tgen", has_scapy=False, is_root=False,
                    has_trex=True, has_trex_stl=True, trex_daemon=True,
                    trex_rpc=True, trex_dir="/opt/trex-3.08")
    assert info.blockers("trex") == []
    assert any("Scapy" in b for b in info.blockers("scapy"))


def test_a_long_status_wraps_instead_of_losing_its_tail():
    """Сообщение несёт не «что случилось», а «что делать», и эта часть стоит в
    конце - обрезка съедала единственное полезное."""
    long = ("машина говорит иначе: демон: 127.0.0.1 (он на самой цели); "
            "скорость линии: 25000 Мбит/с — p подхватит")
    rows = [Field("a", "Поле", lambda: "1", lambda _v: "")]
    out = framed(forms._render("Т", rows, 0, long, 74, None, "", 20))
    assert any("p подхватит" in ln for ln in out), "хвост сообщения потерян"
    assert all(len(ln) <= 78 for ln in out), "строка вылезла из панели"


def _recv_row(result) -> str:
    """Строка «принято» с экрана итога."""
    from traphy.screens import execute

    drawn: list[str] = []
    import traphy.ui as ui_mod

    real = ui_mod.notice
    ui_mod.notice = lambda lines, width=80, wait=True: drawn.extend(
        framed("\n".join(x for x in lines if isinstance(x, str))))
    try:
        execute.result_screen(result)
    finally:
        ui_mod.notice = real
    return next(ln for ln in drawn if "принято" in ln)


def test_a_measured_but_untrustworthy_receive_is_not_called_unmeasured():
    """Найдено живым проходом 2026-10-01: экран писал «принято: не мерялось», а
    строкой ниже стояло «принято больше, чем отправлено (142 250 747)»."""
    r = RunResult(engine="trex", rx_source="flow_stats", reliable=False,
                  tx_pkts=4001, rx_pkts=142_250_747, seconds=4.3)
    row = _recv_row(r)
    assert "не мерялось" not in row
    assert "142 250 747" in row
    assert "приблизительно" in row


def test_a_receive_that_really_was_not_measured_still_says_so():
    r = RunResult(engine="trex", rx_source="none", reliable=False, tx_pkts=100)
    assert "не мерялось" in _recv_row(r)


def test_neither_engine_calls_an_empty_capture_proof_of_loss():
    """Обе генерируемые стороны обязаны говорить это одинаково: пустая запись -
    свойство записи, а не приговор линку. Рядом с ней стоит ноль приёма, и
    вместе они читаются как доказательство потерь, которым не являются."""
    from traphy import codegen, codegen_stl, presets

    for source in (codegen.generate(presets.build("l3_ip")),
                   codegen_stl.generate(presets.build("l3_ip"))):
        # Ищем именно сообщение, а не пояснение рядом с ним: в комментарии
        # фраза стоит нарочно, со словом «НЕ» перед ней.
        assert "пуста - кадров не было" not in source
        assert "НЕЛЬЗЯ судить о потерях" in source


def test_the_routing_trap_is_named_where_the_mac_is_edited():
    """Самая дорогая ловушка для новичка: l3-профиль уходит с выдуманным MAC
    назначения. Через коммутатор это нормально, через роутер кадр не поднимется
    на L3 - и честный ноль приёма выглядит поломкой инструмента. Сказано это
    должно быть там, где MAC правят, а не только в BENCH.md."""
    from traphy import presets
    from traphy.screens.compose import packet_fields

    def hint_for(key: str) -> str:
        stream = presets.build(key).streams[0]
        field = next(f for f in packet_fields(stream) if f.key == "eth_dst")
        return field.hint() if callable(field.hint) else field.hint

    routed = hint_for("l3_ip")
    assert "роутера" in routed and "нулевой" in routed

    switched = hint_for("l2_ethernet")
    assert "коммутация" in switched
    assert "роутера" not in switched, "на L2 это предупреждение только путает"


def test_a_long_hint_wraps_instead_of_losing_its_warning():
    """Грозное в подсказке стоит в конце - обрезка съедала именно его."""
    from traphy import presets
    from traphy.screens.compose import packet_fields

    stream = presets.build("l3_ip").streams[0]
    rows = [f for f in packet_fields(stream) if f.shown()]
    at = next(i for i, f in enumerate(rows) if f.key == "eth_dst")
    out = framed(forms._render("Кадр", rows, at, "", ui.WIDE, None, "", 26))
    assert any("приём будет нулевой" in ln for ln in out)


# --------------------------------------------------------------------------- #
# Скорость: чьими словами она объясняется и от какой линии считается
# --------------------------------------------------------------------------- #
def _hint(field: Field) -> str:
    """Подсказка поля строкой: она бывает и функцией."""
    return field.hint() if callable(field.hint) else field.hint


def _under_the_rate(stream, engine, link_mbit: int, typed: str) -> str:
    """Всё, что форма говорит под полем скорости: подсказка и ответ на ввод."""
    field = next(f for f in compose.rate_fields(stream, engine, link_mbit)
                 if f.key == "rate")
    return f"{_hint(field)}\n{field.set(typed)}"


def _one_number(text: str) -> str:
    """Тот же текст со склеенными разрядами: «10 279 605» → «10279605»."""
    import re

    return re.sub(r"(?<=\d)[\s  ,](?=\d)", "", text)


@pytest.mark.parametrize("key", list(engines.REGISTRY))
def test_the_rate_field_names_no_engine_but_the_one_that_will_send(key):
    """Найдено живым проходом 2026-10-01: на цели с TRex под скоростью стояло
    «Scapy это цель, а не гарантия». Совет про чужой путь читается как про этот
    и заставляет занижать скорость там, где её держит железо."""
    engine = engines.REGISTRY[key]
    stream = presets.build("l3_ip").streams[0]
    said = _under_the_rate(stream, engine, 25000, "500000").lower()
    strangers = [other.title for other_key, other in engines.REGISTRY.items()
                 if other_key != key]
    named = [title for title in strangers if title.lower() in said]
    assert not named, f"цель с {engine.title}: под скоростью назван {named}"


def test_a_percent_of_the_line_is_counted_against_the_targets_link():
    """Найдено живым проходом 2026-10-01: «50% линии» на цели 25G считались от
    зашитого гигабита. Форма обещала 411 тысяч pps там, где поток выдаёт десять
    миллионов - то есть цифру, по которой решают «хватит ли», занижало в 25 раз.
    """
    engine = engines.REGISTRY["scapy"]
    stream = presets.build("l3_ip").streams[0]
    stream.rate_type = RateType.PERCENT

    on_25g = _under_the_rate(stream, engine, 25000, "50")
    on_1g = _under_the_rate(stream, engine, 1000, "50")
    assert on_25g != on_1g, "скорость линии цели на счёт не влияет"
    assert str(round(stream.pps(25000))) in _one_number(on_25g), \
        f"не цифра 25 Гбит/с: {on_25g}"
    assert str(round(stream.pps(1000))) not in _one_number(on_25g), \
        "посчитано от зашитого гигабита"


# --------------------------------------------------------------------------- #
# Шапка экрана и поля под ней
# --------------------------------------------------------------------------- #
HEADER_SCREENS = ("_ask_fields", "_ask_rate", "_edit_range", "stream_editor")


@pytest.fixture
def opened_form(monkeypatch):
    """Чем экран позвал форму, вместо того чтобы её открыть."""
    seen: list[dict] = []

    def instead(title, fields, **kw):
        seen.append(kw)

    monkeypatch.setattr(compose, "edit_form", instead)
    return seen


def _header_now(header) -> list[str]:
    """Шапка, посчитанная сейчас, а не когда-то."""
    lines = header() if callable(header) else list(header)
    return framed("\n".join(lines))


def _open_screen(func, **available):
    """Позвать экран, подставив по имени только то, что он просит.

    Экраны берут разное - шаг мастера, диапазон, движок цели, - а тест смотрит
    на одно: с какой шапкой каждый из них открыл форму.
    """
    import inspect

    params = inspect.signature(func).parameters
    missing = [name for name, p in params.items()
               if p.default is p.empty and name not in available]
    assert not missing, f"{func.__name__} просит {missing} - допиши в тест"
    return func(**{k: v for k, v in available.items() if k in params})


@pytest.mark.parametrize("screen", HEADER_SCREENS)
def test_the_header_says_what_the_fields_under_it_say_now(screen, opened_form):
    """Этот дефект уже был на форме цели, и там его починили лямбдой - а в
    четырёх экранах сборки шапка по-прежнему считается один раз при открытии.
    Правишь размер кадра и скорость, а над полями до самого выхода стоит
    прежнее «Eth/IP 128B, 1000 pps»: это читается как «правка не взялась»."""
    stream = presets.build("port_sweep").streams[0]
    _open_screen(getattr(compose, screen), stream=stream, step=1,
                 vf=stream.vm_fields[0], engine=engines.REGISTRY["trex"],
                 link_mbit=25000, title="")
    header = opened_form[0]["header"]

    before = _header_now(header)
    stream.packet.frame_size = 60
    stream.rate_value = 10_000
    assert _header_now(header) != before, "шапка осталась от прежних значений"


# --------------------------------------------------------------------------- #
# Предпросмотр, сохранение и предупреждения движка
# --------------------------------------------------------------------------- #
@pytest.fixture
def trex_session(session, tmp_path) -> Session:
    """Сеанс с целью на TRex. Все параметры выдуманные - стенда тут нет."""
    session.target = Target(name="генератор", engine="trex",
                            trex_port_tx=0, trex_port_rx=1, link_mbit=25000)
    session.script_dir = tmp_path / "scripts"
    return session


def _drawn(monkeypatch, call) -> str:
    """Кадр, который экран нарисовал: один проход и сразу выход."""
    frames: list[str] = []
    keys = iter(["q"])
    monkeypatch.setattr(ui, "draw", frames.append)
    monkeypatch.setattr(ui, "read_key", lambda timeout=None: next(keys))
    call()
    return "\n".join(framed("\n".join(frames)))


def test_the_script_screen_shows_the_artefact_of_the_engine_that_will_send(
        trex_session, monkeypatch):
    """Найдено живым проходом 2026-10-01: на цели с TRex «показать скрипт»
    печатал скрипт Scapy, хотя уезжает и исполняется управляющий скрипт TRex.
    Предпросмотр, показывающий не то, что уедет, хуже отсутствующего: его
    читают вместо чтения настоящего файла."""
    page = _drawn(monkeypatch, lambda: execute.script_screen(trex_session))
    assert "--trex-dir" in page, "это не управляющий скрипт TRex"
    assert "--iface eth0" not in page, "показан скрипт Scapy"


def test_saving_the_script_writes_and_names_what_the_engine_produces(
        trex_session, monkeypatch):
    """То же расхождение на выходе: сохранялся скрипт Scapy под именем от
    генератора Scapy - и на цели запускали заведомо не тот файл."""
    # Имя артефакта у Scapy и TRex сейчас совпадает, поэтому движок называет
    # его по-своему: иначе проверка прошла бы и на чужом генераторе.
    monkeypatch.setattr(engines.REGISTRY["trex"], "script_name",
                        lambda profile: "поток_для_trex.py", raising=False)
    monkeypatch.setattr(ui, "ask_line", lambda *a, **kw: "")

    status = execute.save_script(trex_session)
    saved = trex_session.script_dir / "поток_для_trex.py"
    assert saved.exists(), f"сохранено не туда: {status}"
    text = saved.read_text(encoding="utf-8")
    assert "--trex-dir" in text, "записан не артефакт TRex"
    assert "--iface eth0" not in text, "записан скрипт Scapy"


def test_the_streams_screen_passes_on_what_the_engine_warns_about(session):
    """Найдено живым проходом 2026-10-01: TRex метит группы полем IP ID, то есть
    потери по кадру без IP не посчитает. Движок про это говорит, а экран его не
    спрашивал - и человек, взявший L2-пресет, узнавал об этом из нулевой строки
    приёма в отчёте, то есть когда прогон уже сделан."""
    session.target = Target(name="генератор", engine="trex")
    session.profile = presets.build("l2_ethernet")
    expected = engines.REGISTRY["trex"].warnings(session.profile)
    assert expected, "кадр без IP обязан вызвать предупреждение движка"

    lines = framed(compose._render_streams(session, session.profile, 0, ""))
    head = expected[0][:30]
    assert any(head in line for line in lines), f"не сказано: {expected[0]}"
