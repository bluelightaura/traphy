"""The Ixia engine: what it configures on the chassis, and what it refuses.

The generated script is exercised against a stand-in for ``ixnetwork-restpy`` -
objects with the same names that record what they were handed. That makes the
API contract explicit: the fake knows which packet fields each protocol layer
has, so a script that asks for a field the stack does not carry fails here the
same way it would on real gear.
"""

from __future__ import annotations

import json
import sys
import types
from typing import ClassVar

import pytest

from traphy import codegen_ixnet, engines, presets
from traphy.engines.ixia import PASSWORD_ENV, parse_port
from traphy.models import FieldTarget, Profile, RateType, Stream, VMField, VMOp
from traphy.probe import HostInfo
from traphy.runner import RunResult
from traphy.runspec import RunSpec
from traphy.target import Target, TargetStore


# --------------------------------------------------------------------------- #
# A chassis that never existed
# --------------------------------------------------------------------------- #
# Which packet fields each protocol layer carries. The script addresses fields
# by these ids; a release that named one differently is exactly the failure
# this lets a test reproduce.
KNOWN_FIELDS = {
    "ethernet": {"ethernet.header.destinationAddress",
                 "ethernet.header.sourceAddress"},
    "vlan": {"vlan.header.vlanTag.vlanID", "vlan.header.vlanTag.priority"},
    "ipv4": {"ipv4.header.srcIp", "ipv4.header.dstIp", "ipv4.header.ttl"},
    "udp": {"udp.header.srcPort", "udp.header.dstPort"},
    "tcp": {"tcp.header.srcPort", "tcp.header.dstPort"},
}


class FakeField:
    def __init__(self, field_id):
        self.field_id = field_id
        self.Auto = True
        self.ValueType = ""
        self.SingleValue = None
        self.StartValue = None
        self.StepValue = None
        self.CountValue = None


class FakeFieldFinder:
    def __init__(self, stack):
        self.stack = stack

    def find(self, FieldTypeId=""):
        if FieldTypeId in FakeStack.unknown:
            return []
        for protocol in self.stack.protocols:
            if FieldTypeId in KNOWN_FIELDS.get(protocol, ()):
                return [self.stack.fields.setdefault(
                    FieldTypeId, FakeField(FieldTypeId))]
        return []


class FakeStack:
    """The protocol stack of one traffic item, and the fields on it."""

    unknown: ClassVar[set[str]] = set()

    def __init__(self):
        self.protocols = ["ethernet"]
        self.fields: dict[str, FakeField] = {}

    @property
    def Field(self):
        return FakeFieldFinder(self)

    def find(self, StackTypeId=""):
        return self

    def AppendProtocol(self, template):
        self.protocols.append(template.name)
        return template.name

    def read(self, href):
        return self


class FakeTemplate:
    def __init__(self, name):
        self.name = name


class FakeUpdatable:
    def __init__(self):
        self.applied: dict = {}
        self.Rate = 0

    def update(self, **kw):
        self.applied.update(kw)
        if "Rate" in kw:
            self.Rate = kw["Rate"]


class FakeTracking:
    def __init__(self):
        self.TrackBy: list[str] = []


class FakeConfigElement:
    def __init__(self):
        self.stack = FakeStack()
        self.FrameSize = FakeUpdatable()
        self.FrameRate = FakeUpdatable()
        self.TransmissionControl = FakeUpdatable()

    @property
    def Stack(self):
        return self.stack

    def find(self):
        return [self]


class FakeEndpointSet:
    def __init__(self):
        self.added: list = []

    def add(self, Sources=None, Destinations=None):
        self.added.append((Sources, Destinations))


class FakeTrafficItem:
    def __init__(self, name):
        self.name = name
        self.element = FakeConfigElement()
        self.EndpointSet = FakeEndpointSet()
        self.tracking = FakeTracking()

    @property
    def ConfigElement(self):
        return _Finder([self.element])

    @property
    def Tracking(self):
        return _Finder([self.tracking])


class _Finder:
    def __init__(self, items):
        self.items = items

    def find(self, **_kw):
        return self.items


class FakeTrafficItemFactory:
    def __init__(self, traffic):
        self.traffic = traffic

    def add(self, name="", trafficType="", biDirectional=False):
        item = FakeTrafficItem(name)
        self.traffic.items.append(item)
        return item

    def find(self, **_kw):
        return self.traffic.items


class FakeTraffic:
    """Traffic on the chassis: applied, started, and eventually stopped."""

    stop_after = 1          # how many state reads before it reports stopped

    def __init__(self):
        self.items: list[FakeTrafficItem] = []
        self.calls: list[str] = []
        self.reads = 0

    @property
    def TrafficItem(self):
        return FakeTrafficItemFactory(self)

    @property
    def ProtocolTemplate(self):
        return _TemplateFinder()

    @property
    def State(self):
        self.reads += 1
        return "started" if self.reads <= FakeTraffic.stop_after else "stopped"

    def Apply(self):
        self.calls.append("apply")

    def Start(self):
        self.calls.append("start")

    def Stop(self):
        self.calls.append("stop")


class _TemplateFinder:
    def find(self, StackTypeId=""):
        name = StackTypeId.strip("^$")
        return [FakeTemplate(name)] if name in KNOWN_FIELDS else []


class FakeProtocols:
    def add(self):
        return "protocol-href"


class FakeVport:
    def __init__(self, name):
        self.name = name
        self.Protocols = FakeProtocols()


class FakeIxNetwork:
    def __init__(self):
        self.Traffic = FakeTraffic()
        self.vports = [FakeVport("traphy-tx"), FakeVport("traphy-rx")]

    @property
    def Vport(self):
        return _VportFinder(self.vports)


class _VportFinder:
    def __init__(self, vports):
        self.vports = vports

    def find(self, Name=""):
        return [v for v in self.vports if v.name == Name]


class FakePortMap:
    def __init__(self, session):
        self.session = session

    def Map(self, IpAddress="", CardId=0, PortId=0, Name=""):
        self.session.mapped.append((IpAddress, CardId, PortId, Name))

    def Connect(self, ForceOwnership=False):
        self.session.forced = ForceOwnership
        if FakeSession.busy and not ForceOwnership:
            raise RuntimeError("port is in use, owner another-session")


class FakeStatView:
    def __init__(self, name, Timeout=0):
        self.name = name

    @property
    def Rows(self):
        return [{"Traffic Item": name, "Tx Frames": str(tx),
                 "Rx Frames": str(rx)}
                for name, tx, rx in FakeSession.rows]


class FakeSessionHandle:
    def __init__(self, session):
        self.session = session

    def remove(self):
        self.session.removed = True


class FakeSession:
    """A SessionAssistant that answers with whatever the test arranged."""

    last: FakeSession | None = None
    busy = False
    rows: ClassVar[list[tuple[str, int, int]]] = [("s1", 1000, 995)]

    def __init__(self, IpAddress="", RestPort=0, UserName=None, Password=None,
                 LogLevel="", ClearConfig=False):
        self.ip = IpAddress
        self.rest_port = RestPort
        self.user = UserName
        self.password = Password
        self.mapped: list = []
        self.forced = None
        self.removed = False
        self.Ixnetwork = FakeIxNetwork()
        self.Session = FakeSessionHandle(self)
        FakeSession.last = self

    def PortMapAssistant(self):
        return FakePortMap(self)

    def StatViewAssistant(self, name, Timeout=0):
        return FakeStatView(name, Timeout)


@pytest.fixture
def fake_ixia(monkeypatch):
    module = types.ModuleType("ixnetwork_restpy")
    module.__version__ = "1.2.3"
    module.SessionAssistant = FakeSession
    FakeSession.last = None
    FakeSession.busy = False
    FakeSession.rows = [("s1", 1000, 995)]
    FakeStack.unknown = set()
    FakeTraffic.stop_after = 1
    monkeypatch.setitem(sys.modules, "ixnetwork_restpy", module)
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    yield module
    FakeSession.last = None
    FakeStack.unknown = set()


def run_ixia(source: str, argv: list[str]) -> dict:
    """Run a generated script. The fake chassis settles instantly, so the two
    seconds the real one is given do not become two seconds of test."""
    namespace: dict = {"__name__": "generated"}
    exec(compile(source, "generated_ixnet.py", "exec"), namespace)
    namespace["STATS_SETTLE"] = 0.0
    namespace["_rc"] = namespace["main"](argv)
    return namespace


def test_the_real_chassis_is_given_time_to_finish_counting():
    """The knob the helper above turns down has to exist and be real."""
    assert "STATS_SETTLE = 2.0" in codegen_ixnet.generate(presets.build("l3_ip"))


def events(capsys) -> list[dict]:
    out = capsys.readouterr().out
    return [json.loads(line[len("@traphy "):]) for line in out.splitlines()
            if line.startswith("@traphy ")]


BASE_ARGS = ["--api-host", "10.0.0.1", "--chassis", "10.0.0.2",
             "--tx-port", "1/1", "--rx-port", "1/2"]


def cli(*extra: str) -> list[str]:
    """The addressing every run needs, plus whatever this test adds."""
    return [*BASE_ARGS, *extra]


def sweep(**kw) -> Profile:
    stream = Stream(name="s1", vm_fields=[VMField(
        target=kw.get("target", FieldTarget.IP_DST),
        op=kw.get("op", VMOp.INC),
        min_value=kw.get("lo", "10.0.0.1"),
        max_value=kw.get("hi", "10.0.0.254"),
        step=kw.get("step", 1))])
    return Profile(name="sweep", streams=[stream])


# --------------------------------------------------------------------------- #
# What gets generated
# --------------------------------------------------------------------------- #
def test_every_packet_field_is_set_explicitly():
    """What is left at the chassis default is not the frame that was composed."""
    source = codegen_ixnet.generate(presets.build("l4_udp"))
    for field_id in ("ethernet.header.destinationAddress",
                     "ethernet.header.sourceAddress",
                     "ipv4.header.srcIp", "ipv4.header.dstIp",
                     "ipv4.header.ttl",
                     "udp.header.srcPort", "udp.header.dstPort"):
        assert field_id in source


def test_a_range_becomes_a_field_increment_with_a_count():
    source = codegen_ixnet.generate(sweep())
    assert "'type': 'increment'" in source
    assert "'count': 254" in source
    assert "VM_FRAMES = {'s1': 254}" in source


def test_a_descending_range_starts_from_the_top():
    source = codegen_ixnet.generate(sweep(op=VMOp.DEC))
    assert "'type': 'decrement'" in source
    assert "'start': '10.0.0.254'" in source


def test_an_address_step_is_written_as_an_address():
    """IxNetwork wants the step in the units of the field it walks."""
    source = codegen_ixnet.generate(sweep(step=4))
    assert "'step': '0.0.0.4'" in source


def test_a_port_step_stays_a_plain_number():
    source = codegen_ixnet.generate(
        sweep(target=FieldTarget.DPORT, lo="100", hi="200", step=5))
    assert "'step': '5'" in source


def test_a_tcp_frame_asks_for_tcp_fields_and_an_l2_one_asks_for_neither():
    tcp = codegen_ixnet.generate(presets.build("l4_tcp"))
    assert "tcp.header.dstPort" in tcp and "udp.header.dstPort" not in tcp

    bare = Profile(name="l2", streams=[Stream(name="s1")])
    bare.streams[0].packet.layer = "l2"
    source = codegen_ixnet.generate(bare)
    assert "ipv4.header" not in source and "udp.header" not in source


def test_a_vlan_frame_stacks_the_tag_between_ethernet_and_ip():
    source = codegen_ixnet.generate(presets.build("l2_vlan"))
    assert "'vlan'" in source
    assert "vlan.header.vlanTag.vlanID" in source


def test_the_profile_is_told_what_it_gives_up_here():
    random_walk = sweep(op=VMOp.RANDOM)
    assert any("повторить её дословно нельзя" in w
               for w in codegen_ixnet.warnings(random_walk))


def test_a_rate_that_cannot_be_scaled_says_so_in_the_script():
    mixed = presets.build("l3_ip")
    mixed.streams[0].rate_type = RateType.PERCENT
    assert "ALL_PPS = False" in codegen_ixnet.generate(mixed)
    assert "ALL_PPS = True" in codegen_ixnet.generate(presets.build("l3_ip"))


def test_the_generated_script_is_valid_python_for_every_preset():
    import ast

    every = presets.keys()
    assert every
    for key in every:
        ast.parse(codegen_ixnet.generate(presets.build(key)))


# --------------------------------------------------------------------------- #
# One run
# --------------------------------------------------------------------------- #
def test_a_run_configures_the_frame_that_was_composed_and_counts_by_item(
        fake_ixia, capsys):
    profile = sweep()
    profile.streams[0].packet.eth_src = "00:11:22:33:44:55"

    namespace = run_ixia(codegen_ixnet.generate(profile),
                         cli("--duration", "1"))
    assert namespace["_rc"] == 0

    done = [e for e in events(capsys) if e["ev"] == "done"][-1]
    assert done["rx_source"] == "traffic_item"
    assert done["reliable"] is True
    assert (done["tx"], done["rx"]) == (1000, 995)

    element = FakeSession.last.Ixnetwork.Traffic.items[0].element
    fields = element.stack.fields
    assert fields["ethernet.header.sourceAddress"].SingleValue == \
        "00:11:22:33:44:55"
    walked = fields["ipv4.header.dstIp"]
    assert walked.ValueType == "increment"
    assert walked.CountValue == 254
    assert walked.Auto is False


def test_the_frame_size_the_chassis_gets_includes_the_fcs(fake_ixia):
    """IxNetwork counts the CRC, the TRaphy model does not. Same wire either
    way, which is the only reason the three engines are comparable."""
    profile = presets.build("l3_ip")
    run_ixia(codegen_ixnet.generate(profile), cli("--duration", "1"))

    element = FakeSession.last.Ixnetwork.Traffic.items[0].element
    assert element.FrameSize.applied["FixedSize"] == \
        profile.streams[0].packet.frame_size + codegen_ixnet.FCS_BYTES


def test_per_item_statistics_need_tracking_and_it_is_switched_on(fake_ixia):
    run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
             cli("--duration", "1"))
    item = FakeSession.last.Ixnetwork.Traffic.items[0]
    assert item.tracking.TrackBy == ["trackingenabled0"]


def test_counters_missing_for_a_stream_drop_the_run_to_partial(
        fake_ixia, capsys):
    profile = presets.build("l3_ip")
    profile.streams.append(Stream(name="second"))
    FakeSession.rows = [("s1", 1000, 995)]      # nothing came back for "second"

    run_ixia(codegen_ixnet.generate(profile), cli("--duration", "1"))
    done = [e for e in events(capsys) if e["ev"] == "done"][-1]
    assert done["rx_source"] == "partial"
    assert done["reliable"] is False
    assert "не по всему прогону" in done["note"]


def test_a_busy_port_is_not_taken_and_the_owner_is_named(fake_ixia, capsys):
    """A chassis is shared. Someone is mid-measurement on that port."""
    FakeSession.busy = True
    namespace = run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
                         cli("--duration", "1"))
    assert namespace["_rc"] == 4
    error = [e for e in events(capsys) if e["ev"] == "error"][-1]
    assert "занят" in error["msg"] and "another-session" in error["msg"]
    assert "--force" in error["msg"]


def test_taking_it_is_possible_but_has_to_be_asked_for(fake_ixia):
    FakeSession.busy = True
    namespace = run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
                         cli("--duration", "1", "--force"))
    assert namespace["_rc"] == 0
    assert FakeSession.last.forced is True


def test_a_field_this_release_does_not_know_stops_the_run(fake_ixia, capsys):
    """Better no traffic than traffic whose TTL quietly stayed at default."""
    FakeStack.unknown = {"ipv4.header.ttl"}
    namespace = run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
                         cli("--duration", "1"))
    assert namespace["_rc"] == 4
    error = [e for e in events(capsys) if e["ev"] == "error"][-1]
    assert "ipv4.header.ttl" in error["msg"]


def test_a_login_without_a_password_anywhere_is_caught_before_the_chassis(
        fake_ixia, capsys):
    namespace = run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
                         cli("--api-user", "admin"))
    assert namespace["_rc"] == 4
    error = [e for e in events(capsys) if e["ev"] == "error"][-1]
    assert PASSWORD_ENV in error["msg"]


def test_the_password_comes_from_the_environment_not_the_command_line(
        fake_ixia, monkeypatch):
    monkeypatch.setenv(PASSWORD_ENV, "s3cret")
    run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
             cli("--api-user", "admin", "--duration", "1"))
    assert FakeSession.last.password == "s3cret"
    assert FakeSession.last.user == "admin"


def test_counting_frames_is_refused_with_the_way_to_get_what_was_wanted(
        fake_ixia, capsys):
    namespace = run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
                         cli("--count", "100"))
    assert namespace["_rc"] == 2
    assert FakeSession.last is None
    assert "очередь" in [e for e in events(capsys)
                         if e["ev"] == "error"][-1]["msg"]


def test_an_aggregate_rate_over_a_mixed_profile_is_refused_rather_than_invented(
        fake_ixia, capsys):
    mixed = presets.build("l3_ip")
    mixed.streams[0].rate_type = RateType.PERCENT
    namespace = run_ixia(codegen_ixnet.generate(mixed),
                         cli("--pps", "1000"))
    assert namespace["_rc"] == 2
    assert FakeSession.last is None


def test_a_dry_run_never_touches_the_chassis(fake_ixia, capsys):
    namespace = run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
                         cli("--dry-run"))
    assert namespace["_rc"] == 0
    assert FakeSession.last is None
    done = [e for e in events(capsys) if e["ev"] == "done"][-1]
    assert "сухой прогон" in done["note"]


def test_a_missing_client_library_says_what_to_install(capsys):
    namespace = run_ixia(codegen_ixnet.generate(presets.build("l3_ip")),
                         cli("--duration", "1"))
    assert namespace["_rc"] == 3
    assert "ixnetwork-restpy" in [e for e in events(capsys)
                                  if e["ev"] == "error"][-1]["msg"]


# --------------------------------------------------------------------------- #
# The seam
# --------------------------------------------------------------------------- #
def test_ports_are_read_the_way_people_write_them():
    assert parse_port("1/2") == (1, 2)
    assert parse_port("1:2") == (1, 2)
    assert parse_port("2") is None
    assert parse_port("0/1") is None
    assert parse_port("карта") is None


def test_the_engine_builds_the_arguments_one_run_needs():
    engine = engines.get("ixia")
    target = Target(engine="ixia", ixia_api_host="10.0.0.1",
                    ixia_chassis="10.0.0.2", ixia_port_tx="1/1",
                    ixia_port_rx="1/2")
    args = engine.args(target, RunSpec(duration=5), None)
    assert args[args.index("--chassis") + 1] == "10.0.0.2"
    assert "--force" not in args
    assert "--api-user" not in args

    target.ixia_force = True
    assert "--force" in engine.args(target, RunSpec(), None)


def test_configuring_a_chassis_does_not_need_root():
    assert engines.get("ixia").needs_root(RunSpec()) is False


def test_a_target_is_judged_on_chassis_and_slots():
    good = Target(engine="ixia", tx_iface="", ixia_api_host="10.0.0.1",
                  ixia_chassis="10.0.0.2")
    assert good.validate() == []
    assert good.tx_label() == "10.0.0.2 1/1"
    assert good.measures_rx() is True

    assert any("API-сервер" in p for p in
               Target(engine="ixia", ixia_chassis="10.0.0.2").validate())
    assert any("карта/порт" in p for p in
               Target(engine="ixia", ixia_api_host="a", ixia_chassis="b",
                      ixia_port_tx="первый").validate())
    assert any("совпадает" in p for p in
               Target(engine="ixia", ixia_api_host="a", ixia_chassis="b",
                      ixia_port_tx="1/1", ixia_port_rx="1/1").validate())


def test_a_login_with_no_password_in_the_environment_is_a_target_problem(
        monkeypatch):
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    target = Target(engine="ixia", ixia_api_host="a", ixia_chassis="b",
                    ixia_api_user="admin")
    assert any(PASSWORD_ENV in p for p in target.validate())

    monkeypatch.setenv(PASSWORD_ENV, "x")
    assert target.validate() == []


def test_the_client_library_is_the_only_thing_the_host_has_to_have():
    engine = engines.get("ixia")
    assert any("ixnetwork-restpy" in b for b in engine.blockers(HostInfo(ok=True)))
    assert engine.blockers(HostInfo(ok=True, has_ixnetwork=True)) == []


def test_ixia_settings_survive_being_saved(tmp_path):
    store = TargetStore(tmp_path)
    original = Target(name="rack", engine="ixia", ixia_api_host="10.0.0.1",
                      ixia_api_port=443, ixia_api_user="admin",
                      ixia_chassis="10.0.0.2", ixia_port_tx="2/3",
                      ixia_port_rx="2/4", ixia_force=True)
    store.save(original)
    assert store.load("rack").to_dict() == original.to_dict()


def test_no_password_is_ever_written_to_the_target_file(tmp_path, monkeypatch):
    monkeypatch.setenv(PASSWORD_ENV, "s3cret")
    store = TargetStore(tmp_path)
    store.save(Target(name="rack", engine="ixia", ixia_api_user="admin"))
    assert "s3cret" not in store.path_for("rack").read_text(encoding="utf-8")


def test_a_partial_count_is_named_in_the_result_warnings():
    result = RunResult(engine="ixia", rx_source="partial", tx_pkts=10)
    assert any("не по всем потокам" in w for w in result.warnings())


def test_falling_short_of_the_rate_blames_the_chassis_not_scapy():
    result = RunResult(engine="ixia", requested_pps=100000, achieved_pps=30000,
                       rx_source="traffic_item", reliable=True)
    said = " ".join(result.warnings())
    assert "Scapy" not in said and "шасси" in said


def test_the_target_form_asks_for_slots_on_ixia():
    from traphy.screens.connect import _fields
    from traphy.session import Session

    target = Target(engine="ixia")
    keys = [f.key for f in _fields(Session(target=target), target) if f.shown()]
    assert "ixia_chassis" in keys and "ixia_tx" in keys
    assert "tx" not in keys and "trex_tx" not in keys
    assert "sudo" not in keys
