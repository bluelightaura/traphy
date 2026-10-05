"""Порты генератора TRex: линк, скорость и кто их держит.

До этого про порты TRex было известно ровно одно - сколько их. Номер порта там
индекс в конфигурации демона, карту забрал DPDK, из ``/sys/class/net`` она
исчезла, и человек вбивал цифру на память: «занят коллегой» и «линк опущен»
выяснялись отказом посреди прогона либо прогоном, вернувшимся как «потери
100%». Опрос спрашивает об этом демона и ничего не захватывает - испортить
чужой замер опросом было бы хуже, чем не ответить.

Отдельный предел, который надо называть вслух: подделка демона тут знает те же
имена, что и вызовы, потому что писались вместе. Сверка имён с настоящим
релизом - в ``tests/test_trex_release.py``, и без распакованного релиза её
никто не делает.
"""

from __future__ import annotations

import json

import pytest

from traphy import engines, probe
from traphy.probe import HostInfo, TrexPort, inspect
from traphy.screens import connect
from traphy.session import Session
from traphy.target import Target, TargetStore
from traphy.transport import Completed, Transport


# --------------------------------------------------------------------------- #
# Демон, которого нет
# --------------------------------------------------------------------------- #
class Daemon:
    """Демон, отвечающий про порты то, что ему велел тест."""

    def __init__(self, attrs: list[dict], owners: dict | None = None):
        self.attrs = attrs
        self.owners = owners or {}
        self.asked: list[int] = []

    def get_port_attr(self, port=None):
        self.asked.append(port)
        value = self.attrs[port]
        if isinstance(value, Exception):
            raise value
        return value

    def get_owner(self, port):
        return self.owners.get(port, "")


class PositionalOnly(Daemon):
    """Релиз, у которого параметр зовётся иначе - то есть ``port=`` не пройдёт."""

    def get_port_attr(self, index):
        self.asked.append(index)
        return self.attrs[index]


class Fixed(Transport):
    """Транспорт, отдающий заранее заготовленный ответ опроса."""

    def __init__(self, payload):
        self.payload = payload

    def run_stream(self, script, args, on_line, timeout=300, sudo=False,
                   secret=""):
        line = "@traphy " + json.dumps(self.payload)
        on_line(line)
        return Completed(0, line, "")


@pytest.fixture(scope="module")
def script() -> dict:
    """Сам опросный скрипт, исполненный здесь.

    Он написан так, чтобы идти под любым python на цели и ничего не
    импортировать сверх стандартной библиотеки, - поэтому его функции
    проверяются прямым вызовом, а не через подделку транспорта.
    """
    namespace: dict = {"__name__": "probe_script"}
    exec(compile(probe.PROBE_SCRIPT, "probe_script.py", "exec"), namespace)
    return namespace


# --------------------------------------------------------------------------- #
# Что опрос спрашивает у демона
# --------------------------------------------------------------------------- #
def test_every_port_the_daemon_has_is_asked_about(script):
    daemon = Daemon([
        {"driver": "net_ice", "speed": 40, "link": "UP", "owner": ""},
        {"driver": "net_ice", "speed": 40, "link": "DOWN", "owner": "olga"},
    ])
    rows = script["port_rows"](daemon, 2)

    assert [r["index"] for r in rows] == [0, 1]
    assert rows[0]["link"] == "up" and rows[0]["speed_mbit"] == 40000
    assert rows[0]["driver"] == "net_ice" and rows[0]["owner"] == ""
    # Владелец - единственное в этом опросе, что про людей: генератор общий.
    assert rows[1]["link"] == "down" and rows[1]["owner"] == "olga"


def test_a_release_that_names_the_argument_differently_is_still_asked(script):
    """``get_port_attr(port=)`` против ``get_port_attr(index)``: отказ по
    имени параметра не повод показать порт без подробностей."""
    daemon = PositionalOnly([{"link": "UP", "speed": 25}])
    rows = script["port_rows"](daemon, 1)
    assert rows[0]["link"] == "up" and rows[0]["speed_mbit"] == 25000


def test_a_port_the_daemon_will_not_describe_comes_back_blank_not_guessed(
        script):
    """Врать тут можно в обе стороны: выдуманный «линк up» посылает искать
    поломку в коробке, выдуманный «занят» - искать владельца, которого нет."""
    daemon = Daemon([RuntimeError("порт не отвечает")])
    rows = script["port_rows"](daemon, 1)

    assert rows[0] == {"index": 0, "link": "", "speed_mbit": 0, "driver": "",
                       "owner": "", "state": "", "service": None}


def test_the_owner_is_asked_separately_when_the_attributes_do_not_say(script):
    """Часть релизов владельца в атрибутах порта не отдаёт вовсе."""
    daemon = Daemon([{"link": "UP"}], owners={0: "сосед"})
    assert script["port_rows"](daemon, 1)[0]["owner"] == "сосед"


@pytest.mark.parametrize(("said", "mbit"), [
    (40, 40000),        # TRex говорит гигабитами
    (25, 25000),
    (1000, 1000),       # а порт на 1000 Мбит/с бывает сплошь
    (10000, 10000),
    (0, 0),             # «не сказал» - это не скорость
    ("", 0),
    (None, 0),
])
def test_gigabits_and_megabits_are_told_apart(script, said, mbit):
    assert script["speed_mbit"](said) == mbit


def test_service_mode_left_on_is_reported_however_it_is_named(script):
    """Порт, забытый в сервисном режиме, снижает потолок скорости следующему
    прогону - и это самая дорогая недоделка на общей машине."""
    daemon = Daemon([{"service": True}, {"is_service_mode": "on"},
                     {"link": "UP"}])
    rows = script["port_rows"](daemon, 3)
    assert [r["service"] for r in rows] == [True, True, None]


# --------------------------------------------------------------------------- #
# Как это доезжает до человека
# --------------------------------------------------------------------------- #
def test_the_rows_reach_the_host_info():
    info = inspect(Fixed({
        "ev": "host", "ok": True, "hostname": "gen", "python": "3.9.18",
        "trex_rpc": True, "trex_rpc_ports": 2,
        "trex_port_rows": [
            {"index": 0, "link": "up", "speed_mbit": 40000,
             "driver": "net_ice", "owner": "", "state": "IDLE",
             "service": False},
            {"index": 1, "link": "down", "speed_mbit": 0, "driver": "net_ice",
             "owner": "olga", "state": "DOWN", "service": None},
        ],
    }))

    assert [p.index for p in info.trex_port_info] == [0, 1]
    assert info.trex_port_info[0].free and info.trex_port_info[0].is_up
    assert info.trex_port_info[1].owner == "olga"
    assert info.trex_port_info[1].link_known


def test_a_port_nobody_asked_about_does_not_claim_a_link():
    """«Линк не сказан» и «линк опущен» ведут к разным следующим шагам, и
    показывать их одинаково значит однажды послать человека к стойке зря."""
    port = TrexPort(index=3)
    assert port.link_known is False and port.is_up is False
    assert "не сказан" in port.describe()


def test_the_description_names_link_speed_and_holder():
    text = TrexPort(index=1, link="up", speed_mbit=40000, driver="net_ice",
                    owner="olga", service=True).describe()
    assert "порт 1" in text and "40G" in text and "линк up" in text
    assert "olga" in text and "сервисный режим" in text


def test_the_state_word_is_dropped_when_it_only_repeats_the_link():
    """Найдено живым прогоном: порт с упавшим линком описывался как
    «линк down · занят: olga · down». Второе «down» - состояние словами
    демона, и оно ничего не уточняет, а читается как вторая беда."""
    said = TrexPort(index=1, link="down", owner="olga", state="DOWN").describe()
    assert said == "порт 1 · линк down · занят: olga"
    # А состояние, которое добавляет новое, остаётся: порт, который прямо
    # сейчас шлёт, - это не то же самое, что порт с поднятым линком.
    busy = TrexPort(index=0, link="up", state="TX").describe()
    assert busy.endswith("· tx")


def test_the_summary_line_counts_ports_and_free_ones():
    host = HostInfo(ok=True, has_trex=True, has_trex_stl=True,
                    trex_daemon=True, trex_dir="/opt/trex-3.08",
                    trex_version="v3.08", trex_port_info=[
                        TrexPort(index=0, link="up"),
                        TrexPort(index=1, link="down", owner="olga")])

    said = engines.get("trex").describe_host(host)

    assert "портов 2, свободно 1" in said
    assert "линк опущен: 1" in said


# --------------------------------------------------------------------------- #
# Форма цели: порт выбирают из того, что сказал демон
# --------------------------------------------------------------------------- #
@pytest.fixture
def session(tmp_path) -> Session:
    s = Session(store=TargetStore(tmp_path / "targets"))
    s.target = Target(name="gen", engine="trex", use_ssh=True,
                      host="192.0.2.10", ssh_user="tester",
                      trex_port_tx=0, trex_port_rx=1)
    return s


def fields(session: Session) -> dict:
    return {f.key: f for f in connect._fields(session, session.target)}


def hint_of(field) -> str:
    return field.hint() if callable(field.hint) else field.hint


def suggest_of(field) -> list:
    return list(field.suggest() if callable(field.suggest) else field.suggest)


def with_ports(session: Session, *ports: TrexPort) -> None:
    session.host = HostInfo(ok=True, hostname="gen", python="3.9.18",
                            trex_daemon=True, trex_rpc=True,
                            trex_port_info=list(ports))


def test_until_the_target_is_asked_nothing_is_offered_as_fact(session):
    """Список берётся с машины либо не берётся: выдуманные порты на генераторе
    с одной картой - это совет вбить номер, которого там нет."""
    row = fields(session)["trex_tx"]
    assert "p спросит у демона" in hint_of(row)
    assert suggest_of(row) == [("0", "обычно первый порт")]


def test_the_ports_the_daemon_named_become_the_list(session):
    with_ports(session,
               TrexPort(index=0, link="up", speed_mbit=40000, driver="net_ice"),
               TrexPort(index=1, link="up", speed_mbit=40000, driver="net_ice"))

    row = fields(session)["trex_tx"]

    assert hint_of(row) == "с демона: портов 2, свободно 2"
    assert [value for value, _why in suggest_of(row)] == ["0", "1"]
    # Номер сам по себе не говорит ни о чём - рядом с ним то, по чему человек
    # узнаёт, тот ли это порт.
    assert "40G" in row.get()


def test_the_receive_row_still_offers_not_measuring_at_all(session):
    with_ports(session, TrexPort(index=0, link="up"), TrexPort(index=1))
    assert suggest_of(fields(session)["trex_rx"])[0] == ("-", "не мерить приём")


def test_a_port_held_by_somebody_else_is_said_before_the_run(session):
    """Иначе это выясняется отказом посреди прогона - и ровно тогда, когда
    человек уже считает, что мерит."""
    with_ports(session, TrexPort(index=0, link="up", owner="olga"),
               TrexPort(index=1, link="up"))

    said = fields(session)["trex_tx"].set("0")

    assert said.startswith("!") and "olga" in said


def test_a_port_with_the_link_down_is_said_before_the_run(session):
    """Прогон на порту с упавшим линком возвращается как «потери 100%» - та
    самая цифра, за которой идут проверять коробку."""
    with_ports(session, TrexPort(index=0, link="up"),
               TrexPort(index=1, link="down"))

    said = fields(session)["trex_rx"].set("1")

    assert said.startswith("!") and "кабель" in said


def test_a_port_the_daemon_does_not_have_is_said_before_the_run(session):
    """Номер - индекс в конфигурации демона, а не надпись на коробке: на
    машине с одной картой «1» не существует."""
    with_ports(session, TrexPort(index=0, link="up"))

    said = fields(session)["trex_tx"].set("1")

    assert "порта 1 там нет" in said


def test_a_port_left_in_service_mode_is_said_before_the_run(session):
    with_ports(session, TrexPort(index=0, link="up", service=True),
               TrexPort(index=1, link="up"))

    said = fields(session)["trex_tx"].set("0")

    assert "сервисном режиме" in said


def test_a_good_port_is_accepted_without_a_word(session):
    with_ports(session, TrexPort(index=0, link="up"), TrexPort(index=1, link="up"))
    assert fields(session)["trex_tx"].set("0") == ""


def test_an_unasked_target_does_not_object_to_any_port(session):
    """Пока демона не спрашивали, возражать нечем - и молчание тут честнее
    догадки: цель заводят и до того, как генератор включили."""
    assert fields(session)["trex_tx"].set("3") == ""
# --------------------------------------------------------------------------- #
# Опрос из командной строки
# --------------------------------------------------------------------------- #
def test_the_cli_probe_prints_the_generator_ports(monkeypatch, capsys):
    """`traphy probe` - то, чем смотрят на генератор перед выездом: свободен
    ли он и поднят ли линк. Карт этих в `/sys/class/net` нет вовсе, так что
    без этой строки опрос про них молчал."""
    from traphy.cli import commands

    info = HostInfo(ok=True, hostname="gen", kernel="linux", python="3.9.18",
                    trex_port_info=[
                        TrexPort(index=0, link="up", speed_mbit=40000,
                                 driver="net_ice"),
                        TrexPort(index=1, link="down", owner="olga")])

    class FakeTransport:
        def close(self):
            pass

    monkeypatch.setattr(commands, "open_transport",
                        lambda target, password="": FakeTransport())
    monkeypatch.setattr(commands, "inspect",
                        lambda transport, trex_dir="": info)
    store = commands.TargetStore()
    store.save(Target(name="gen", engine="trex", use_ssh=True,
                      host="192.0.2.10", ssh_user="tester"))

    rc = commands.cmd_probe(commands.argparse.Namespace(
        target="gen", json=False, password=None))

    said = capsys.readouterr().out
    assert rc == 0
    assert "порт 0 · net_ice · 40G · линк up" in said
    assert "занят: olga" in said
