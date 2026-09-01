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

    def run_stream(self, script, args, on_line, timeout=300, sudo=False):
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
