"""The engine seam: what is wired in, what is only declared, and the difference."""

from __future__ import annotations

import pytest

from traphy import engines, presets
from traphy.probe import HostInfo, Iface
from traphy.runner import execute
from traphy.runspec import RunSpec
from traphy.target import Target
from traphy.transport import Transport


class Refusing(Transport):
    """A transport that fails the test if anything is ever shipped through it."""

    def run_stream(self, script, args, on_line, timeout=300, sudo=False):
        raise AssertionError("на неготовом движке ничего уезжать не должно")


def test_the_registry_offers_every_declared_engine():
    assert set(engines.REGISTRY) == {"scapy", "trex", "jmeter"}
    assert engines.get("scapy").ready is True
    assert engines.get("trex").ready is False
    assert engines.get("jmeter").ready is False


def test_an_unknown_engine_falls_back_rather_than_breaking_the_menu():
    """A target written by a later version must still open here."""
    assert engines.get("нечто").key == engines.DEFAULT


def test_the_picker_says_which_engines_are_not_ready():
    labels = {key: hint for key, _title, hint in engines.options()}
    assert "не реализован" in labels["trex"]
    assert "не реализован" in labels["jmeter"]
    assert "не реализован" not in labels["scapy"]


def test_a_not_ready_engine_refuses_before_anything_is_generated():
    engine = engines.get("jmeter")
    with pytest.raises(engines.EngineNotReady, match="JMeter"):
        engine.generate(presets.build("l3_ip"), tag="X")


def test_a_run_on_a_not_ready_engine_stops_at_validation():
    result = execute(presets.build("l3_ip"),
                     Target(engine="trex", tx_iface="ens1"),
                     RunSpec(archive=False), transport=Refusing())
    assert result.rc == 2
    assert "TRex" in result.note


def test_the_scapy_engine_builds_the_arguments_a_run_needs():
    engine = engines.get("scapy")
    target = Target(tx_iface="ens1", rx_iface="ens2")
    args = engine.args(target, RunSpec(duration=5, pps=1000), None)
    assert args[:2] == ["--iface", "ens1"]
    assert "--rx-iface" in args and "--pps" in args


def test_only_a_real_send_asks_for_root():
    engine = engines.get("scapy")
    assert engine.needs_root(RunSpec()) is True
    assert engine.needs_root(RunSpec(dry_run=True)) is False


def test_each_engine_reports_what_its_host_is_missing():
    bare = HostInfo(ok=True, ifaces=[Iface("ens1", state="up")])
    assert any("Scapy" in b for b in bare.blockers("scapy"))
    assert any("java" in b for b in bare.blockers("jmeter"))
    assert any("TRex" in b for b in bare.blockers("trex"))


def test_a_ready_scapy_host_has_nothing_blocking_it():
    ready = HostInfo(ok=True, has_scapy=True, is_root=True,
                     ifaces=[Iface("ens1", state="up")])
    assert ready.blockers("scapy") == []


def test_declared_engines_still_name_their_artefact():
    """The seam is real: each one already knows what file it will produce."""
    assert engines.get("trex").file_suffix == ".py"
    assert engines.get("jmeter").file_suffix == ".jmx"
    assert engines.get("jmeter").layers == "L7"
