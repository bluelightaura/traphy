"""Пункты журнала стенда, которые проверяются без стенда.

`BENCH.md` держит список уровней, и часть его пунктов про железо: линк, потери,
коробка посередине. Но несколько обещаний оттуда железа не требуют вовсе - они
про то, что прогон говорит и что после себя оставляет, и проверить их можно
подделкой. Пока они стояли непроверенными, в журнале это выглядело так же, как
непроверенное на железе, - то есть список не отличал «не ездили на стенд» от
«не написали тест».

Здесь закрыты именно такие: отказ по `--count` (1.6), состав архива прогона
(1.7) и пустая запись кадров, которую нельзя принимать за потери (1.10).
Прогон с трафиком это не заменяет и не делает вид, что заменяет.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traphy import codegen_stl, presets, ui
from traphy.models import Profile
from traphy.runner import RunResult, RunSpec, apply_events, execute, run_dir_root
from traphy.target import Target
from traphy.transport import Completed, Transport

from test_trex import FakeClient, events, fake_trex, run_stl  # noqa: F401


class Scripted(Transport):
    """Транспорт, отдающий заранее записанные события вместо прогона."""

    def __init__(self, lines: list[str], rc: int = 0, stderr: str = ""):
        self.lines, self.rc, self.stderr = lines, rc, stderr
        self.script = ""

    def describe(self) -> str:
        return "подделка"

    def run_stream(self, script, args, on_line, timeout=300, sudo=False,
                   secret=""):
        self.script = script
        for line in self.lines:
            on_line(line)
        return Completed(self.rc, "\n".join(self.lines), self.stderr)


def newest_run() -> Path:
    return sorted(Path(run_dir_root()).iterdir())[-1]


# --------------------------------------------------------------------------- #
# 1.6 - счёт кадров, которого у TRex нет
# --------------------------------------------------------------------------- #
@pytest.mark.usefixtures("fake_trex")
def test_a_run_asked_for_a_frame_count_refuses_and_sends_nothing(capsys):
    """TRex шлёт по времени. «Длительность, которая выходит примерно в N
    кадров» - это не N кадров, и подстановка одного вместо другого отравляет
    доверие ко всем остальным цифрам заодно.

    Проверяется не только отказ, но и то, что до демона дело не дошло: отказ,
    успевший захватить порты общего генератора, хуже отказа."""
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        ["--trex-dir", "/nowhere", "--tx-port", "0",
                         "--rx-port", "1", "--duration", "1", "--count", "500"])

    assert namespace["_rc"] == 2
    said = [e for e in events(capsys) if e["ev"] == "error"]
    assert said and "по времени" in said[0]["msg"]
    # Ни подключения, ни захвата: клиент не создавался вовсе.
    assert FakeClient.last is None


@pytest.mark.usefixtures("fake_trex")
def test_the_refusal_names_the_way_to_get_what_was_asked(capsys):
    """Отказ без выхода - это тупик. Ровное число кадров у TRex получается
    режимом очереди, и сказать об этом дешевле, чем дать человеку искать."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--count", "500"])
    said = next(e for e in events(capsys) if e["ev"] == "error")
    assert "очеред" in said["msg"]


# --------------------------------------------------------------------------- #
# 1.7 - архив прогона
# --------------------------------------------------------------------------- #
def test_a_finished_run_leaves_profile_script_events_and_result():
    """Через неделю от прогона остаётся каталог, и в нём должно быть всё, чем
    цифру можно перепроверить: чем слали, каким скриптом, что он говорил по
    ходу и чем кончил. Проверялось это до сих пор только на оборванном
    прогоне - то есть на пути, которым прогон обычно не идёт."""
    lines = ['@traphy {"ev": "ready", "frames": 1}',
             '@traphy {"ev": "tick", "t": 1.0, "tx": 10, "rx": 10}',
             '@traphy {"ev": "done", "tx": 10, "rx": 10, "seconds": 1.0, '
             '"rx_source": "flow_stats", "reliable": true}']
    result = execute(presets.build("l3_ip"), Target(tx_iface="eth0"),
                     RunSpec(duration=1), transport=Scripted(lines))

    folder = newest_run()
    assert result.run_dir == str(folder)
    assert sorted(p.name for p in folder.iterdir()) == [
        "events.jsonl", "profile.json", "result.json", "script.py"]

    # Профиль читается обратно как профиль, а не как текст про профиль.
    saved = Profile.from_json((folder / "profile.json").read_text(
        encoding="utf-8"))
    assert saved.name == "l3_ip" and saved.streams

    # Скрипт - тот, который и ушёл на цель.
    assert (folder / "script.py").read_text(encoding="utf-8").startswith("#!")

    # События - все, по одному на строку, в том порядке, в котором пришли.
    log = [json.loads(line) for line in
           (folder / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [e["ev"] for e in log] == ["ready", "tick", "done"]

    # Результат - машинно читаемый и с тем же приговором, что на экране.
    done = json.loads((folder / "result.json").read_text(encoding="utf-8"))
    assert done["rx_source"] == "flow_stats" and done["rc"] == 0
    assert done["loss_pct"] == 0.0 and done["measurement_valid"] is True


def test_the_archive_keeps_the_per_group_numbers_the_run_reported():
    """Разбивка по группам нужна именно в архиве: по ней через неделю видно,
    какая группа была отравлена, - а это и был разбор, который делали диффом
    сгенерированных скриптов."""
    lines = ['@traphy {"ev": "done", "tx": 100, "rx": 100, "seconds": 1.0, '
             '"rx_source": "flow_stats", "reliable": true, "flow_err_rx": 3, '
             '"groups": {"7": {"tx": 100, "rx": 100, "rx_port": 100, '
             '"rx_foreign": 0, "port_seen": true}}}']
    execute(presets.build("l3_ip"), Target(tx_iface="eth0"),
            RunSpec(duration=1), transport=Scripted(lines))

    done = json.loads((newest_run() / "result.json").read_text(encoding="utf-8"))
    assert done["rx_per_group"]["7"]["rx_port"] == 100
    assert done["flow_err_rx"] == 3
    # И недостача учёта снимает годность замера, а не только пометку.
    assert done["measurement_valid"] is False


def test_a_dry_run_archive_says_the_receive_side_was_never_measured():
    """1.5 в журнале: холостой прогон обязан говорить «приём не измерялся», а
    не ноль принятых. Ноль - это цифра, и в колонке потерь он читается как
    100%."""
    lines = ['@traphy {"ev": "done", "tx": 0, "rx": 0, "seconds": 0.0, '
             '"rx_source": "none"}']
    result = execute(presets.build("l3_ip"), Target(tx_iface="eth0"),
                     RunSpec(duration=1, dry_run=True),
                     transport=Scripted(lines))

    done = json.loads((newest_run() / "result.json").read_text(encoding="utf-8"))
    assert done["loss_pct"] is None and done["loss_measured"] is False
    assert "в кабель не ушло" in result.summary()


# --------------------------------------------------------------------------- #
# 1.10 - пустая запись кадров
# --------------------------------------------------------------------------- #
def test_an_empty_recording_is_not_loss():
    """Наблюдалось на живом железе: счётчик приёма ненулевой, а L2-захват
    пустой. Запись отвечает на вопрос «что именно было в кабеле», и когда она
    молчит - она молчит; про потери судят по счётчику.

    Цена записи при этом названа всё равно: сервисный режим прогон заплатил
    независимо от того, попал ли в файл хоть один кадр."""
    result = RunResult(engine="trex", recorded=["rx"])
    apply_events(result, [
        {"ev": "capture", "name": "rx", "frames": 0},
        {"ev": "done", "tx": 1000, "rx": 1000, "seconds": 1.0,
         "rx_source": "flow_stats", "reliable": True},
    ])

    assert result.rx_pkts == 1000 and result.loss_pkts == 0
    assert result.valid_measurement()
    said = " ".join(result.warnings())
    assert "кадры записаны" in said and "сервисном режиме" in said
    assert "потер" not in said.replace("потолок", "")


def test_an_empty_recording_does_not_cancel_a_real_loss_figure():
    """Обратная сторона того же: пустой файл не повод списать настоящие
    потери на запись."""
    result = RunResult(engine="trex", recorded=["rx"])
    apply_events(result, [
        {"ev": "capture", "name": "rx", "frames": 0},
        {"ev": "done", "tx": 1000, "rx": 400, "seconds": 1.0,
         "rx_source": "flow_stats", "reliable": True},
    ])

    assert result.loss_pkts == 600
    assert result.loss_countable
# --------------------------------------------------------------------------- #
# Недостача учёта видна живьём, а не только в отчёте
# --------------------------------------------------------------------------- #
def test_the_run_screen_shows_frames_filed_under_no_group():
    """Эту цифру нельзя складывать с двумя соседними: это кадры, про которые
    демон сознался, что не посчитал их никак. Пока её не показывают, ровно
    столько же выглядит потерями устройства - и смотреть идут коробку."""
    from traphy.screens import execute as execute_screen
    from traphy.session import Session

    session = Session()
    session.target = Target(name="gen", engine="trex", trex_port_tx=0,
                            trex_port_rx=1)
    live = execute_screen._Live(session, RunSpec(duration=1))
    live.on_event({"ev": "tick", "t": 1.0, "tx": 100, "rx": 90,
                   "rx_port": 95, "rx_groups": 90, "rx_err": 5})

    rows = ui.strip_ansi("\n".join(
        execute_screen._honesty_rows(session, live.state)))

    assert "мимо групп" in rows and "5" in rows


def test_a_run_without_an_accounting_shortfall_says_nothing_about_it():
    """Строка, которая стоит всегда, перестаёт читаться - и первая настоящая
    недостача проезжает мимо вместе с ней."""
    from traphy.screens import execute as execute_screen
    from traphy.session import Session

    session = Session()
    session.target = Target(name="gen", engine="trex")
    live = execute_screen._Live(session, RunSpec(duration=1))
    live.on_event({"ev": "tick", "t": 1.0, "tx": 100, "rx": 100,
                   "rx_port": 100, "rx_groups": 100, "rx_err": 0})

    rows = ui.strip_ansi("\n".join(
        execute_screen._honesty_rows(session, live.state)))

    assert "мимо групп" not in rows
# --------------------------------------------------------------------------- #
# Противоречие двух счётчиков - не «приблизительно», а «мерить нечем»
# --------------------------------------------------------------------------- #
def test_blind_groups_contradicted_by_the_port_are_not_a_measurement():
    """Найдено живым прогоном 2026-10-05 на генераторе стенда: группы в нуле,
    порт принял пять кадров (все - STP и LLDP коробки, ни одного нашего),
    потери 99.99%. Экран говорил «приблизительно», а в `result.json` уезжало
    `measurement_valid: true` с пустым `disqualified` - то есть кто читает JSON
    скриптом, получал «замер годен» ровно по тому прогону, от которого
    инструмент защищает на экране.

    Цифру потерь это не отменяет: вычитать есть из чего, и она остаётся."""
    result = RunResult(engine="trex", tx_pkts=50001, rx_pkts=5,
                       rx_source="flow_stats_blind", reliable=False,
                       seconds=5.1, achieved_pps=9891.0, requested_pps=10000.0)

    assert result.valid_measurement() is False
    assert result.disqualified(), "противоречие счётчиков обязано быть названо"
    assert result.loss_countable and round(result.loss_pct, 2) == 99.99
    assert result.to_dict()["measurement_valid"] is False
    # И в одну строку истории это тоже обязано попасть: иначе прогон со
    # слепыми группами выглядит там как честный приблизительный.
    assert "ЗАМЕР НЕ ГОДИТСЯ" in result.summary()


def test_a_zero_nothing_could_contradict_is_not_a_measurement_either():
    """Группы в нуле, а счётчик порта приёма не прочитался: сверить было
    нечем. Ноль может быть и правдой, но установить этого нельзя."""
    result = RunResult(engine="trex", tx_pkts=1000, rx_pkts=0,
                       rx_source="flow_stats_unverified", reliable=False)
    assert result.valid_measurement() is False


def test_a_port_counter_on_its_own_stays_a_measurement():
    """Обратная сторона, и её нельзя ломать заодно: там, где аппаратного счёта
    не заказывали вовсе, счётчик порта - единственный источник и законный.
    Дисквалифицировать его значит сказать, что на Scapy измерений не бывает."""
    result = RunResult(engine="scapy", tx_pkts=1000, rx_pkts=990,
                       rx_source="port_counter", reliable=False)
    assert result.valid_measurement() is True
    assert "ЗАМЕР НЕ ГОДИТСЯ" not in result.summary()
