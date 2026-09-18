"""The TRex engine: what it generates, and what one run of it reports.

The generated script is exercised against a stand-in for the release's control
plane - a module with the same names that records what it was handed and a
client that answers with counters a test chose. That covers the parts worth
covering without a bench: which numbers the script believes, what it says when
it cannot believe them, and that it never opens a connection it should not.
"""

from __future__ import annotations

import json
import sys
import types

import pytest
import scapy.all as scapy

from traphy import codegen, codegen_stl, engines, presets
from traphy.models import FieldTarget, L4Proto, Profile, Stream, VMField, VMOp
from traphy.probe import HostInfo
from traphy.runner import RunResult
from traphy.runspec import RunSpec
from traphy.target import Target


# --------------------------------------------------------------------------- #
# A TRex that never existed
# --------------------------------------------------------------------------- #
class Recorded:
    """Keeps whatever it was constructed with, so a test can look."""

    def __init__(self, **kw):
        self.kw = kw


class STLVmFlowVar(Recorded):
    pass


class STLVmWrFlowVar(Recorded):
    pass


class STLVmFixIpv4(Recorded):
    pass


class STLFlowStats(Recorded):
    pass


class STLTXCont(Recorded):
    pass


class STLTXSingleBurst(Recorded):
    pass


class STLTXMultiBurst(Recorded):
    pass


class STLScVmRaw:
    def __init__(self, commands):
        self.commands = list(commands)


class STLPktBuilder:
    def __init__(self, pkt=None, vm=None):
        self.pkt = pkt
        self.vm = vm


class STLStream:
    def __init__(self, name="", packet=None, mode=None, flow_stats=None):
        self.name = name
        self.packet = packet
        self.mode = mode
        self.flow_stats = flow_stats


class FakeClient:
    """A server that reports what the test told it to report."""

    last: FakeClient | None = None
    active_polls = 5          # ~1.25 s of run loop, enough for one tick
    tx = 1000
    rx = 995

    def __init__(self, server="", sync_port=0):
        self.server = server
        self.sync_port = sync_port
        self.calls: list = []
        self.streams: list = []
        self.polls = 0
        FakeClient.last = self

    def connect(self):
        self.calls.append("connect")

    def reset(self, ports=None):
        self.calls.append(("reset", tuple(ports or ())))

    def add_streams(self, streams, ports=None):
        self.streams = list(streams)
        self.calls.append(("add_streams", tuple(ports or ())))

    def clear_stats(self):
        self.calls.append("clear_stats")

    def start(self, ports=None, duration=0, mult="1", force=False):
        self.calls.append(("start", tuple(ports or ()), duration, mult))

    def is_traffic_active(self, ports=None):
        self.polls += 1
        return self.polls <= FakeClient.active_polls

    def wait_on_traffic(self, ports=None, timeout=0):
        self.calls.append("wait")

    def stop(self, ports=None):
        self.calls.append("stop")

    def disconnect(self):
        self.calls.append("disconnect")

    def get_stats(self):
        groups = {}
        counted = [s for s in self.streams if s.flow_stats is not None]
        for s in counted:
            groups[s.flow_stats.kw["pg_id"]] = {
                "tx_pkts": {"total": FakeClient.tx // len(counted)},
                "rx_pkts": {"total": FakeClient.rx // len(counted)},
            }
        return {
            0: {"opackets": FakeClient.tx, "obytes": FakeClient.tx * 64,
                "tx_pps": 1000.0},
            1: {"ipackets": FakeClient.rx},
            "flow_stats": groups,
        }


@pytest.fixture
def fake_trex(monkeypatch):
    """Stand in for ``trex.stl.api`` from an unpacked release."""
    module = types.ModuleType("trex.stl.api")
    for name in ("Ether", "Dot1Q", "IP", "TCP", "UDP"):
        setattr(module, name, getattr(scapy, name))
    for cls in (STLVmFlowVar, STLVmWrFlowVar, STLVmFixIpv4, STLScVmRaw,
                STLPktBuilder, STLStream, STLFlowStats, STLTXCont,
                STLTXSingleBurst, STLTXMultiBurst):
        setattr(module, cls.__name__, cls)
    module.STLClient = FakeClient
    FakeClient.last = None
    FakeClient.tx, FakeClient.rx = 1000, 995
    monkeypatch.setitem(sys.modules, "trex.stl.api", module)
    yield module
    FakeClient.last = None


def run_stl(source: str, argv: list[str]) -> dict:
    """Execute a generated control script and call its main."""
    namespace: dict = {"__name__": "generated"}
    exec(compile(source, "generated_stl.py", "exec"), namespace)
    namespace["_rc"] = namespace["main"](argv)
    return namespace


def build_only(source: str) -> tuple:
    """Load a generated script and build its streams without running."""
    namespace: dict = {"__name__": "generated"}
    exec(compile(source, "generated_stl.py", "exec"), namespace)
    api = namespace["load_api"]("/nowhere")
    return namespace["build_streams"](api, namespace["layers"](api), True)


def events(capsys) -> list[dict]:
    out = capsys.readouterr().out
    return [json.loads(line[len("@traphy "):]) for line in out.splitlines()
            if line.startswith("@traphy ")]


def sweep(**kw) -> Profile:
    """One stream walking destination addresses across a range."""
    stream = Stream(name="s1", vm_fields=[VMField(
        target=kw.get("target", FieldTarget.IP_DST),
        op=kw.get("op", VMOp.INC),
        min_value=kw.get("lo", "10.0.0.1"),
        max_value=kw.get("hi", "10.0.0.254"))])
    if "proto" in kw:
        stream.packet.l4_proto = kw["proto"]
    if "layer" in kw:
        stream.packet.layer = kw["layer"]
    return Profile(name="sweep", streams=[stream])


# --------------------------------------------------------------------------- #
# What gets generated
# --------------------------------------------------------------------------- #
def test_a_range_is_field_engine_setup_rather_than_a_pile_of_frames():
    """The whole reason to reach for TRex: the range never becomes memory."""
    source = codegen_stl.generate(sweep())
    assert source.count("STLVmFlowVar") == 1
    assert "VM_FRAMES = {'s1': 254}" in source


def test_the_scapy_engine_caps_a_wide_sweep_and_this_one_has_nothing_to_cap():
    wide = sweep(lo="10.0.0.0", hi="10.0.255.255")
    assert codegen.frame_count(wide) == codegen.EXPAND_CAP
    assert codegen_stl.frame_count(wide) == 65536


def test_range_ends_are_numbers_because_not_every_release_takes_the_dotted_form():
    source = codegen_stl.generate(sweep(lo="10.0.0.1", hi="10.0.0.2"))
    assert "min_value=167772161, max_value=167772162" in source


def test_a_backwards_range_is_put_the_right_way_round_for_the_server():
    source = codegen_stl.generate(sweep(lo="10.0.0.9", hi="10.0.0.1"))
    assert "min_value=167772161, max_value=167772169" in source


def test_walking_an_address_recomputes_the_header_checksum():
    assert 'STLVmFixIpv4(offset="IP")' in codegen_stl.generate(sweep())


def test_walking_only_ports_leaves_the_ip_checksum_alone():
    source = codegen_stl.generate(sweep(target=FieldTarget.DPORT,
                                        lo="1000", hi="2000"))
    assert "STLVmFixIpv4" not in source


def test_walking_udp_ports_sends_no_checksum_rather_than_a_wrong_one():
    """Zero is the legal way to say "not computed"; a stale number is a lie."""
    source = codegen_stl.generate(sweep(target=FieldTarget.DPORT,
                                        lo="1000", hi="2000"))
    assert "chksum=0" in source


def test_walking_tcp_ports_has_no_such_escape_and_is_warned_about():
    profile = sweep(target=FieldTarget.DPORT, lo="1000", hi="2000",
                    proto=L4Proto.TCP)
    said = codegen_stl.warnings(profile)
    assert any("контрольная сумма TCP" in w for w in said)
    assert "chksum=0" not in codegen_stl.generate(profile)


def test_a_frame_without_ip_cannot_be_counted_and_the_profile_says_so():
    """TRex tags a stream group in the IPv4 id field. No IP, no counter."""
    profile = Profile(name="l2", streams=[Stream(name="s1")])
    profile.streams[0].packet.layer = "l2"
    said = codegen_stl.warnings(profile)
    assert any("без IP" in w for w in said)

    source = codegen_stl.generate(profile)
    assert "    pg = None" in source          # no group id is even attempted
    assert "pg_next" not in source.split("def build_streams")[1].split(
        "return streams")[0].replace("pg_next = 0", "")


def test_the_warnings_travel_inside_the_saved_script():
    """A script taken to a bench on a stick has to say this without us."""
    profile = Profile(name="l2", streams=[Stream(name="s1")])
    profile.streams[0].packet.layer = "l2"
    assert "без IP" in codegen_stl.generate(profile)


def test_the_tx_mode_becomes_the_call_that_builds_it():
    from traphy.models import TxMode

    profile = presets.build("l3_ip")
    profile.streams[0].tx_mode = TxMode.MULTI_BURST
    profile.streams[0].number_of_bursts = 7
    assert "STLTXMultiBurst(pkts_per_burst=" in codegen_stl.generate(profile)
    assert "count=7" in codegen_stl.generate(profile)


def test_a_disabled_stream_is_named_in_the_header_and_left_out():
    profile = presets.build("l3_ip")
    profile.streams.append(Stream(name="off", enabled=False))
    source = codegen_stl.generate(profile)
    assert "Выключенные потоки не вошли: off" in source
    assert 'name="off"' not in source


def test_the_generated_script_is_valid_python_for_every_preset():
    import ast

    every = presets.keys()
    assert every
    for key in every:
        ast.parse(codegen_stl.generate(presets.build(key)))


# --------------------------------------------------------------------------- #
# The two engines have to agree on the wire
# --------------------------------------------------------------------------- #
def test_one_profile_puts_the_same_bytes_on_the_wire_on_either_engine(fake_trex):
    """Otherwise the two engines are not comparable and having both is moot.

    trex-tui padded to ``frame_size - 4`` on the theory that the size includes
    the FCS; TRaphy's model says the size excludes it, the same as the Scapy
    engine assumes. Left alone, the same profile would have gone out four bytes
    shorter here than there - and nobody would have noticed until two runs of
    "the same" 64-byte test disagreed.
    """
    profile = presets.build("l3_ip")
    _streams, frames, _pg, _un = build_only(codegen_stl.generate(profile))

    namespace: dict = {"__name__": "generated"}
    exec(compile(codegen.generate(profile), "generated.py", "exec"), namespace)
    scapy_frames = namespace["build_0"]()

    assert len(bytes(frames[0])) == len(bytes(scapy_frames[0]))
    assert len(bytes(frames[0])) == profile.streams[0].packet.frame_size


# --------------------------------------------------------------------------- #
# One run
# --------------------------------------------------------------------------- #
def test_a_run_counts_loss_in_hardware_and_says_that_is_what_it_did(
        fake_trex, capsys):
    source = codegen_stl.generate(presets.build("l3_ip"), tag="T1")
    namespace = run_stl(source, ["--trex-dir", "/nowhere", "--tx-port", "0",
                                 "--rx-port", "1", "--duration", "1"])
    assert namespace["_rc"] == 0

    seen = events(capsys)
    done = [e for e in seen if e["ev"] == "done"][-1]
    assert done["rx_source"] == "flow_stats"
    assert done["reliable"] is True
    assert (done["tx"], done["rx"]) == (1000, 995)
    assert any(e["ev"] == "tick" for e in seen)


def test_the_receiving_port_is_acquired_too_or_its_counter_is_nobodys(fake_trex):
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    reset = next(c for c in FakeClient.last.calls
                 if isinstance(c, tuple) and c[0] == "reset")
    assert reset[1] == (0, 1)


def test_without_a_receive_port_nothing_pretends_to_have_counted(
        fake_trex, capsys):
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        ["--trex-dir", "/nowhere", "--tx-port", "0",
                         "--duration", "1"])
    assert namespace["_rc"] == 0
    done = [e for e in events(capsys) if e["ev"] == "done"][-1]
    assert done["rx_source"] == "none"
    assert done["reliable"] is False
    assert done["rx"] == 0
    assert "не измерялся" in done["note"]


def test_a_stream_that_cannot_be_counted_drops_the_run_to_mixed(
        fake_trex, capsys):
    """One L2 stream beside an IP one: the loss figure covers only part."""
    profile = presets.build("l3_ip")
    bare = Stream(name="l2only")
    bare.packet.layer = "l2"
    profile.streams.append(bare)

    run_stl(codegen_stl.generate(profile),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = [e for e in events(capsys) if e["ev"] == "done"][-1]
    assert done["rx_source"] == "mixed"
    assert done["reliable"] is False
    assert "l2only" in done["note"]


def test_counting_frames_is_refused_with_the_way_to_get_what_was_wanted(
        fake_trex, capsys):
    """TRex sends for a time. Turning N frames into "about N" quietly is how a
    tool loses the right to be believed about anything else."""
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        ["--trex-dir", "/nowhere", "--count", "100"])
    assert namespace["_rc"] == 2
    assert FakeClient.last is None
    error = [e for e in events(capsys) if e["ev"] == "error"][-1]
    assert "очереди" in error["msg"]


def test_a_dry_run_never_opens_a_connection(fake_trex, capsys):
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        ["--trex-dir", "/nowhere", "--dry-run"])
    assert namespace["_rc"] == 0
    assert FakeClient.last is None
    done = [e for e in events(capsys) if e["ev"] == "done"][-1]
    assert "сухой прогон" in done["note"]


def test_a_missing_release_names_the_directory_it_looked_in(capsys):
    """No fake api installed: this is what a wrong --trex-dir looks like."""
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        ["--trex-dir", "/nowhere", "--duration", "1"])
    assert namespace["_rc"] == 3
    error = [e for e in events(capsys) if e["ev"] == "error"][-1]
    assert "/nowhere" in error["msg"]
    assert "trex_control_plane" in error["msg"]


def test_an_aggregate_rate_override_reaches_the_server_as_a_multiplier(
        fake_trex):
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--duration", "1",
             "--mult", "5000pps"])
    start = next(c for c in FakeClient.last.calls
                 if isinstance(c, tuple) and c[0] == "start")
    assert start[3] == "5000pps"


# --------------------------------------------------------------------------- #
# The seam
# --------------------------------------------------------------------------- #
def test_the_engine_builds_the_arguments_one_run_needs():
    engine = engines.get("trex")
    target = Target(engine="trex", trex_port_tx=0, trex_port_rx=1,
                    trex_dir="/opt/trex")
    args = engine.args(target, RunSpec(duration=5, pps=5000), None)
    assert "--tx-port" in args and "--rx-port" in args
    assert args[args.index("--mult") + 1] == "5000pps"


def test_driving_the_daemon_does_not_need_root():
    """It was started with root long ago; we are an ordinary client."""
    engine = engines.get("trex")
    assert engine.needs_root(RunSpec()) is False
    assert engine.needs_root(RunSpec(dry_run=True)) is False


def test_the_three_ways_a_trex_host_can_be_unready_are_three_answers():
    engine = engines.get("trex")
    assert any("каталог" in b for b in engine.blockers(HostInfo(ok=True)))

    unpacked = HostInfo(ok=True, has_trex=True, trex_dir="/opt/trex")
    assert any("trex_control_plane" in b for b in engine.blockers(unpacked))

    ready_but_down = HostInfo(ok=True, has_trex=True, has_trex_stl=True,
                              trex_dir="/opt/trex")
    assert any("демон" in b for b in engine.blockers(ready_but_down))

    running = HostInfo(ok=True, has_trex=True, has_trex_stl=True,
                       trex_daemon=True, trex_dir="/opt/trex")
    assert running.blockers("trex") == []


def test_a_trex_target_is_judged_on_ports_not_on_interface_names():
    target = Target(engine="trex", tx_iface="", trex_port_tx=0, trex_port_rx=1)
    assert target.validate() == []
    assert target.tx_label() == "порт 0"
    assert target.measures_rx() is True


def test_receiving_on_the_sending_port_is_refused():
    target = Target(engine="trex", trex_port_tx=1, trex_port_rx=1)
    assert any("совпадает" in p for p in target.validate())


def test_no_receive_port_means_loss_is_not_measured():
    assert Target(engine="trex", trex_port_rx=-1).measures_rx() is False


def test_trex_settings_survive_being_saved(tmp_path):
    from traphy.target import TargetStore

    store = TargetStore(tmp_path)
    original = Target(name="bench", engine="trex", trex_dir="/opt/trex/v3.04",
                      trex_sync_port=4507, trex_port_tx=2, trex_port_rx=3)
    store.save(original)
    assert store.load("bench").to_dict() == original.to_dict()


def test_a_result_says_which_of_the_four_counts_produced_it():
    hardware = RunResult(engine="trex", rx_source="flow_stats", reliable=True)
    assert hardware.warnings() == []

    port = RunResult(engine="trex", rx_source="port_counter", tx_pkts=10)
    assert any("прилетело" in w for w in port.warnings())

    part = RunResult(engine="trex", rx_source="mixed", tx_pkts=10)
    assert any("не по всему прогону" in w for w in part.warnings())

    nothing = RunResult(engine="trex", rx_source="none", tx_pkts=10)
    assert any("порт приёма" in w for w in nothing.warnings())


def test_falling_short_of_the_rate_does_not_blame_scapy_on_a_trex_run():
    result = RunResult(engine="trex", requested_pps=100000, achieved_pps=30000,
                       rx_source="flow_stats", reliable=True)
    said = " ".join(result.warnings())
    assert "Scapy" not in said
    assert "TRex" in said


# --------------------------------------------------------------------------- #
# From the command line
# --------------------------------------------------------------------------- #
def test_gen_builds_the_artefact_of_the_engine_that_was_asked_for(capsys):
    from traphy.cli import main

    assert main(["gen", "ip_sweep", "--engine", "trex"]) == 0
    out = capsys.readouterr().out
    assert "STLVmFlowVar" in out
    assert "AsyncSniffer" not in out          # that is the other engine's script


def test_gen_counts_the_sweep_the_way_the_chosen_engine_will_walk_it(
        tmp_path, capsys):
    """The same profile, two engines, two honest and different numbers."""
    wide = tmp_path / "wide.json"
    wide.write_text(sweep(lo="10.0.0.0", hi="10.0.255.255").to_json(),
                    encoding="utf-8")

    assert main_out(["gen", str(wide), "-o", str(tmp_path / "s.py")], capsys) \
        .endswith("(1024 кадров)\n")
    assert main_out(["gen", str(wide), "--engine", "trex",
                     "-o", str(tmp_path / "t.py")], capsys) \
        .endswith("(65536 кадров)\n")


def main_out(argv: list[str], capsys) -> str:
    from traphy.cli import main

    assert main(argv) == 0
    return capsys.readouterr().out


def test_gen_on_an_unfinished_engine_refuses_instead_of_writing_a_stub(capsys):
    from traphy.cli import main

    assert main(["gen", "l3_ip", "--engine", "jmeter"]) == 2
    assert "JMeter" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# The form a person actually sees
# --------------------------------------------------------------------------- #
def _form_keys(target: Target) -> list[str]:
    from traphy.screens.connect import _fields
    from traphy.session import Session

    session = Session(target=target)
    return [f.key for f in _fields(session, target) if f.shown()]


def test_the_target_form_asks_for_ports_on_trex_and_interfaces_on_scapy():
    """There is no interface list to pick from on a TRex box - DPDK took them."""
    scapy_keys = _form_keys(Target(engine="scapy"))
    assert "tx" in scapy_keys and "trex_tx" not in scapy_keys

    trex_keys = _form_keys(Target(engine="trex"))
    assert "trex_tx" in trex_keys and "trex_rx" in trex_keys
    assert "tx" not in trex_keys and "rx" not in trex_keys


def test_a_trex_target_is_not_asked_about_sudo():
    """Nothing here needs root, so asking about it would be asking for a
    privilege the work does not use."""
    assert "sudo" not in _form_keys(Target(engine="trex"))


def test_the_launcher_line_names_the_port_not_a_stale_interface():
    from traphy.session import Session

    session = Session(target=Target(engine="trex", trex_port_tx=2))
    session.host = HostInfo(ok=True, hostname="bench")
    from traphy.transport import Transport

    session.transport = Transport()
    text, role = session.status_line()
    assert "порт 2" in text and role == "ok"
