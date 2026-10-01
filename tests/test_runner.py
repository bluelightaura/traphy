"""One run end to end, and the honesty rules the result has to keep."""

from __future__ import annotations

import json

import pytest

from traphy import presets
from traphy.models import Profile, Stream
from traphy.runner import (
    RunResult,
    RunSpec,
    execute,
    parse_event,
    recent_runs,
    run_dir_root,
)
from traphy.target import Target
from traphy.transport import Completed, Transport


class ScriptedTransport(Transport):
    """Replays a fixed set of lines instead of running anything."""

    def __init__(self, lines: list[str], rc: int = 0, stderr: str = ""):
        self.lines, self.rc, self.stderr = lines, rc, stderr
        self.script = ""
        self.args: list[str] = []
        self.sudo = False

    def describe(self) -> str:
        return "тест"

    def run_stream(self, script, args, on_line, timeout=300, sudo=False,
                   secret=""):
        self.script, self.args, self.sudo = script, list(args), sudo
        for line in self.lines:
            on_line(line)
        return Completed(self.rc, "\n".join(self.lines), self.stderr)


def event(**fields) -> str:
    return "@traphy " + json.dumps(fields)


DONE = dict(ev="done", tx=1000, rx=990, tx_bytes=64000, seconds=1.0,
            achieved_pps=1000.0, rx_source="marker", reliable=True)


def test_parse_event_ignores_everything_that_is_not_ours():
    assert parse_event(event(ev="tick", tx=1)) == {"ev": "tick", "tx": 1}
    assert parse_event("обычная строка вывода") is None
    assert parse_event("@traphy это не json") is None
    assert parse_event("@traphy [1,2]") is None      # a list is not an event


def test_events_fold_into_the_result():
    transport = ScriptedTransport([
        event(ev="ready", frames=3, truncated=[]),
        event(ev="tick", t=1.0, tx=500, rx=498),
        event(**DONE),
    ])
    result = execute(presets.build("l3_ip"), Target(tx_iface="eth0",
                                                    rx_iface="eth1"),
                     RunSpec(archive=False), transport=transport)
    assert result.tx_pkts == 1000 and result.rx_pkts == 990
    assert result.loss_pkts == 10
    assert result.loss_pct == pytest.approx(1.0)
    assert result.reliable is True


def test_a_run_with_no_receive_side_never_claims_zero_loss():
    """The single most misleading number a traffic tool can print."""
    transport = ScriptedTransport([
        event(ev="done", tx=1000, rx=0, tx_bytes=64000, seconds=1.0,
              achieved_pps=1000.0, rx_source="none", reliable=False),
    ])
    result = execute(presets.build("l3_ip"), Target(tx_iface="eth0"),
                     RunSpec(archive=False), transport=transport)
    assert result.reliable is False
    assert any("не измерялся" in w for w in result.warnings())


def test_falling_short_of_the_requested_rate_is_called_out():
    transport = ScriptedTransport([event(**{**DONE, "achieved_pps": 300.0})])
    result = execute(presets.build("l3_ip"), Target(tx_iface="eth0",
                                                    rx_iface="eth1"),
                     RunSpec(archive=False, pps=1000), transport=transport)
    assert result.rate_shortfall == pytest.approx(70.0)
    assert any("Scapy упёрся" in w for w in result.warnings())


def test_a_broken_profile_comes_back_as_a_result_not_an_exception():
    profile = Profile(streams=[Stream(enabled=False)])
    result = execute(profile, Target(tx_iface="eth0"), RunSpec(archive=False),
                     transport=ScriptedTransport([]))
    assert result.rc == 2 and "выключены" in result.note


def test_a_broken_target_is_refused_before_anything_ships():
    transport = ScriptedTransport([])
    result = execute(presets.build("l3_ip"), Target(tx_iface=""),
                     RunSpec(archive=False), transport=transport)
    assert result.rc == 2
    assert transport.script == "", "скрипт не должен уезжать на кривую цель"


def test_a_failing_script_carries_its_reason_forward():
    transport = ScriptedTransport([event(ev="error", msg="нет прав на сырой сокет")],
                                  rc=13)
    result = execute(presets.build("l3_ip"), Target(tx_iface="eth0"),
                     RunSpec(archive=False), transport=transport)
    assert result.rc == 13
    assert "сырой сокет" in result.note
    assert any("кодом 13" in w for w in result.warnings())


def test_the_arguments_match_the_spec():
    transport = ScriptedTransport([event(**DONE)])
    execute(presets.build("l3_ip"),
            Target(tx_iface="ens1", rx_iface="ens2", use_sudo=True),
            RunSpec(duration=7, pps=2500, archive=False), transport=transport)
    assert transport.args[:2] == ["--iface", "ens1"]
    assert "--rx-iface" in transport.args and "ens2" in transport.args
    assert "--duration" in transport.args and "7" in transport.args
    assert "--pps" in transport.args and "2500" in transport.args
    assert transport.sudo is True


def test_a_dry_run_never_asks_for_root():
    """Building frames needs no privilege, and asking for it would be a lie."""
    transport = ScriptedTransport([event(**DONE)])
    execute(presets.build("l3_ip"), Target(tx_iface="eth0", use_sudo=True),
            RunSpec(dry_run=True, archive=False), transport=transport)
    assert transport.sudo is False
    assert "--dry-run" in transport.args


def test_each_run_ships_a_fresh_marker():
    """Otherwise a sniffer counts the previous run's stragglers as this one's."""
    tags = []
    for _ in range(2):
        transport = ScriptedTransport([event(**DONE)])
        execute(presets.build("l3_ip"), Target(tx_iface="eth0"),
                RunSpec(archive=False), transport=transport)
        line = next(ln for ln in transport.script.splitlines() if ln.startswith("TAG"))
        tags.append(line)
    assert tags[0] != tags[1]


def test_an_archived_run_keeps_the_script_that_produced_it():
    transport = ScriptedTransport([event(ev="ready", truncated=[]), event(**DONE)])
    result = execute(presets.build("ip_sweep"), Target(tx_iface="eth0",
                                                       rx_iface="eth1"),
                     RunSpec(), transport=transport)
    from pathlib import Path

    archive = Path(result.run_dir)
    assert (archive / "script.py").read_text(encoding="utf-8") == transport.script
    assert json.loads((archive / "profile.json").read_text())["name"] == "ip_sweep"
    saved = json.loads((archive / "result.json").read_text())
    assert saved["tx_pkts"] == 1000 and saved["loss_pct"] == 1.0
    assert (archive / "events.jsonl").read_text().count("\n") == 2

    listed = recent_runs(5)
    assert listed and listed[0]["profile"] == "ip_sweep"
    assert run_dir_root().exists()


def test_summary_reads_differently_when_nothing_was_measured():
    measured = RunResult(tx_pkts=10, rx_pkts=9, seconds=1, reliable=True)
    assert "потери" in measured.summary()
    blind = RunResult(tx_pkts=10, seconds=1, reliable=False)
    assert "не измерялся" in blind.summary()


def test_a_dry_run_does_not_complain_about_the_receive_port():
    """"Приём не измерялся" is what a dry run is *for*. Advising the operator
    to set a port they already set is how warnings stop being read."""
    dry = RunResult(dry_run=True, engine="trex", rx_source="none", reliable=False)
    assert not any("порт приёма" in w for w in dry.warnings())
    wet = RunResult(dry_run=False, engine="trex", rx_source="none", reliable=False)
    assert any("порт приёма" in w for w in wet.warnings())


def test_a_dry_run_says_so_instead_of_reporting_zero_traffic():
    assert "в кабель не ушло" in RunResult(dry_run=True).summary()


def test_a_dry_run_still_reports_a_failing_script():
    dry = RunResult(dry_run=True, rc=1, note="библиотека не нашлась")
    assert any("кодом 1" in w for w in dry.warnings())


def test_a_measured_but_unreliable_figure_is_shown_rather_than_denied():
    """Calling a number on the screen "не измерялся" teaches the reader to
    stop believing the line it is on."""
    r = RunResult(tx_pkts=8000, rx_pkts=8001, seconds=8.0,
                  rx_source="flow_stats_blind", reliable=False)
    assert "rx=8001" in r.summary()
    assert "приблизительно" in r.summary()


def test_a_sniffer_count_carries_its_own_caveat():
    """It sees only our frames, which beats a port counter - and it is still
    software, so at rate the losses it reports are its own."""
    warned = " ".join(RunResult(rx_source="marker", reliable=False,
                                tx_pkts=1000, rx_pkts=990).warnings())
    assert "сниффером по метке" in warned
    assert "теряет их сам" in warned
    assert "интерфейс приёма" not in warned   # it was measured, just softly


def test_an_unmeasured_figure_still_says_so_plainly():
    r = RunResult(tx_pkts=8000, rx_source="none", reliable=False)
    assert "приём не измерялся" in r.summary()


def test_a_recorded_run_says_what_the_recording_cost_it():
    """Frames are copied through the software path to be captured, so the rate
    ceiling drops. A throughput figure taken with recording on is a figure
    about the recording - and somebody will otherwise blame the device."""
    r = RunResult(engine="trex", reliable=True,
                  captures={"tx": "/runs/x/tx.pcap", "rx": "/runs/x/rx.pcap"})
    warned = " ".join(r.warnings())
    assert "сервисном режиме" in warned
    assert "tx, rx" in warned


def test_a_run_without_recording_says_nothing_about_it():
    assert not any("сервисном" in w for w in RunResult(reliable=True).warnings())


def test_the_recording_caveat_names_the_cost_this_engine_actually_paid():
    """Service mode is a TRex thing. Telling a Scapy operator about it sends
    them looking for a setting their engine does not have."""
    from traphy.runner.result import RunResult

    captures = {"tx": "/x/tx.pcap", "rx": "/x/rx.pcap"}
    scapy = RunResult(engine="scapy", captures=captures, tx_pkts=10,
                      rx_pkts=10, reliable=True)
    trex = RunResult(engine="trex", captures=captures, tx_pkts=10,
                     rx_pkts=10, reliable=True)

    said = "\n".join(scapy.warnings())
    assert "сервисном режиме" not in said
    assert "сниффер" in said
    assert "сервисном режиме" in "\n".join(trex.warnings())


def test_the_recording_caveat_lists_sending_before_receiving():
    from traphy.runner.result import RunResult

    result = RunResult(engine="scapy", tx_pkts=1, rx_pkts=1, reliable=True,
                       captures={"rx": "/x/rx.pcap", "tx": "/x/tx.pcap"})
    assert "(tx, rx)" in "\n".join(result.warnings())


def test_receiving_more_than_was_sent_is_never_silently_fine():
    """Найдено на петле: tx=200, rx=400, «потери 0.00%».

    Отрицательные потери обрезаются в ноль, и прогон, по которому мерить
    нечего, выглядел безупречным.
    """
    r = RunResult(engine="scapy", tx_pkts=200, rx_pkts=400,
                  rx_source="marker", reliable=True)
    said = " ".join(r.warnings())
    assert "больше, чем отправлено" in said
    assert "400" in said and "200" in said


def test_an_ordinary_run_says_nothing_about_it():
    r = RunResult(engine="scapy", tx_pkts=200, rx_pkts=200,
                  rx_source="marker", reliable=True)
    assert not any("больше, чем отправлено" in w for w in r.warnings())


def test_sample_frames_do_not_borrow_the_caveat_that_belongs_to_a_recording():
    """Образцы кадров (по одному на поток, собранные до field engine) приезжают
    в тот же архив, что и запись трафика. Но сервисного режима они не стоили, и
    объяснять цену, которой не было, - тот же обман, что и молчать о настоящей.
    """
    r = RunResult(engine="trex", rx_source="flow_stats", reliable=True,
                  tx_pkts=10, rx_pkts=10,
                  captures={"streams": "/runs/x/streams.pcap"})
    assert r.recorded_traffic() == []
    assert not any("сервисн" in w for w in r.warnings())

    r.captures["rx"] = "/runs/x/rx.pcap"
    assert r.recorded_traffic() == ["rx"]
    said = [w for w in r.warnings() if "сервисн" in w]
    assert said and "streams" not in said[0]


def test_more_received_than_sent_prints_no_loss_percentage():
    """Найдено на стенде 2026-09-30: приёмный счётчик набрал 30 млн против
    50 тысяч отправленных, и сводка сообщала «потери 0.00%». Арифметически
    так и есть, и означает это ровно ничего - а выглядит как отличный прогон.
    """
    r = RunResult(engine="trex", rx_source="flow_stats_blind", reliable=False,
                  tx_pkts=50_000, rx_pkts=30_627_011, seconds=5.0)
    said = r.summary()
    assert "потери не считаются" in said
    assert "0.00%" not in said
    assert any("больше, чем отправлено" in w for w in r.warnings())


def test_a_configured_receive_port_is_never_advised_to_be_configured():
    """Найдено на стенде 2026-09-30. Аппаратный счёт потерял доверие из-за
    чужого трафика - и отчёт советовал «задай порт приёма», при заданном порте
    и измеренном приёме. Совет настроить уже настроенное - ровно то, после чего
    предупреждения перестают читать."""
    r = RunResult(engine="trex", rx_source="flow_stats", reliable=False,
                  tx_pkts=20_001, rx_pkts=140_301_868)
    said = r.warnings()
    assert not any("задай порт приёма" in w for w in said)
    assert any("больше, чем отправлено" in w for w in said)


def test_a_run_that_really_measured_nothing_still_says_what_to_do():
    r = RunResult(engine="trex", rx_source="none", reliable=False, tx_pkts=100)
    assert any("задай порт приёма" in w for w in r.warnings())


def test_an_unverifiable_zero_explains_itself():
    r = RunResult(engine="trex", rx_source="flow_stats_unverified",
                  reliable=False, tx_pkts=100, rx_pkts=0)
    assert any("сверить было нечем" in w for w in r.warnings())
