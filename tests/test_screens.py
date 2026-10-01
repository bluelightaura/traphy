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

from traphy import forms, menu, presets, ui
from traphy.runner import RunResult
from traphy.forms import Field
from traphy.screens import compose, connect
from traphy.session import Session
from traphy.target import Target

ENGINES = ("scapy", "trex", "ixia")
SOURCES = ("flow_stats", "flow_stats_blind", "flow_stats_unverified",
           "port_counter", "mixed", "partial", "marker", "none")


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
    for title, fields in (("Кадр", compose.packet_fields(stream)),
                          ("Скорость", compose.rate_fields(stream))):
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
