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

    def run_stream(self, script, args, on_line, timeout=300, sudo=False,
                   secret=""):
        raise AssertionError("на неготовом движке ничего уезжать не должно")


def test_the_registry_offers_every_declared_engine():
    assert set(engines.REGISTRY) == {"scapy", "trex", "ixia", "jmeter"}
    assert engines.get("scapy").ready is True
    assert engines.get("trex").ready is True
    assert engines.get("ixia").ready is True
    assert engines.get("jmeter").ready is False


def test_an_unknown_engine_falls_back_rather_than_breaking_the_menu():
    """A target written by a later version must still open here."""
    assert engines.get("нечто").key == engines.DEFAULT


def test_the_picker_says_which_engines_are_not_ready():
    labels = {key: hint for key, _title, hint in engines.options()}
    assert "не реализован" in labels["jmeter"]
    assert "не реализован" not in labels["scapy"]
    assert "не реализован" not in labels["trex"]
    assert "не реализован" not in labels["ixia"]


def test_a_not_ready_engine_refuses_before_anything_is_generated():
    engine = engines.get("jmeter")
    with pytest.raises(engines.EngineNotReady, match="JMeter"):
        engine.generate(presets.build("l3_ip"), tag="X")


def test_a_run_on_a_not_ready_engine_stops_at_validation():
    result = execute(presets.build("l3_ip"),
                     Target(engine="jmeter", tx_iface="ens1"),
                     RunSpec(archive=False), transport=Refusing())
    assert result.rc == 2
    assert "JMeter" in result.note


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
    assert any("ixnetwork-restpy" in b for b in bare.blockers("ixia"))


def test_a_ready_scapy_host_has_nothing_blocking_it():
    ready = HostInfo(ok=True, has_scapy=True, is_root=True,
                     ifaces=[Iface("ens1", state="up")])
    assert ready.blockers("scapy") == []


def test_a_declared_engine_still_names_its_artefact():
    """The seam is real: even the unfinished one knows what it will produce."""
    assert engines.get("jmeter").file_suffix == ".jmx"
    assert engines.get("jmeter").layers == "L7"


def test_only_the_engines_that_think_in_nic_names_ask_for_one():
    """TRex's NICs are gone from /sys/class/net - DPDK took them."""
    assert engines.get("scapy").uses_ifaces is True
    assert engines.get("trex").uses_ifaces is False
    assert engines.get("ixia").uses_ifaces is False


def test_scapy_capture_is_a_flag_not_a_path_on_this_machine():
    """The script runs on the target; the archive is a directory here.

    Handing it ``--pcap <local archive>/tx.pcap`` wrote the dump into a
    directory the sending machine does not have, so nothing came back.
    """
    from pathlib import Path

    from traphy.engines.scapy_engine import ScapyEngine
    from traphy.runspec import RunSpec
    from traphy.target import Target

    target = Target(name="стенд", tx_iface="ens19", rx_iface="ens20")
    args = ScapyEngine().args(target, RunSpec(capture=True, capture_limit=250),
                              Path("/home/кто-то/.local/state/traphy/runs/x"))
    assert "--capture" in args
    assert args[args.index("--capture-limit") + 1] == "250"
    assert not any("runs/x" in a for a in args)


def test_a_dry_run_records_nothing():
    from traphy.engines.scapy_engine import ScapyEngine
    from traphy.runspec import RunSpec
    from traphy.target import Target

    args = ScapyEngine().args(Target(name="стенд", tx_iface="ens19"),
                              RunSpec(capture=True, dry_run=True), None)
    assert "--capture" not in args
    assert "--dry-run" in args


def test_both_engines_ship_frames_home_the_same_way():
    """One piece of generated code, so a capture cannot work on one and not
    the other - which is exactly what had happened."""
    from traphy import codegen, codegen_stl, presets

    profile = presets.build("l3_ip")
    for module in (codegen, codegen_stl):
        source = module.generate(profile, tag="TRAPHY0")
        compile(source, module.__name__, "exec")
        assert "def ship_pcap(" in source
        assert source.count("CHUNK = 48000") == 1


def test_every_engine_answers_what_the_screens_ask_of_it():
    """Экраны спрашивают подсказку, пояснение и предупреждения у выбранного
    движка, а не у Scapy. Движок, забывший одно из этого, валит не свой тест, а
    экран - и обычно на цели, которую собирают первый раз в жизни."""
    from traphy.models import FieldTarget, VMField

    profile = presets.build("l3_ip")
    stream = profile.streams[0]
    vf = VMField(target=FieldTarget.IP_DST, min_value="10.0.0.1",
                 max_value="10.0.0.9")
    host = HostInfo(ok=True, ifaces=[Iface("ens1", state="up")])

    for key, engine in engines.REGISTRY.items():
        assert engine.script_name(profile).endswith(engine.file_suffix), key
        assert isinstance(engine.rate_hint, str), key
        assert isinstance(engine.rate_note(stream, 25000), str), key
        assert isinstance(engine.range_note(vf), str), key
        assert isinstance(engine.describe_host(host), str), key
        assert isinstance(engine.warnings(profile), list), key

    raw = [key for key, engine in engines.REGISTRY.items()
           if engine.opens_raw_socket]
    assert raw == ["scapy"], "сырой сокет открывает только Scapy"
