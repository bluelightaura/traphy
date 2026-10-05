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
from typing import ClassVar

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
        self._idle_reads = 0
        FakeClient.last = self

    def connect(self):
        self.calls.append("connect")

    # When set, acquire refuses the way a server refuses a port somebody else
    # holds - with the owner in the message.
    owner = ""

    def acquire(self, ports=None, force=False):
        if FakeClient.owner and not force:
            raise RuntimeError(f"Port 0 is owned by '{FakeClient.owner}'")
        self.calls.append(("acquire", tuple(ports or ()), force))

    def release(self, ports=None):
        self.calls.append(("release", tuple(ports or ())))

    def remove_all_streams(self, ports=None):
        self.calls.append(("remove_all_streams", tuple(ports or ())))

    # ---------------------------------------------------- recording frames
    # What the recording side does, which is where the ports get put into
    # service mode - the mode that costs rate. A run leaving them in it makes
    # every later run on this machine slow for reasons nobody connects to a
    # capture taken hours earlier, so the tests watch it go off again.
    capture_bytes = b"\xd4\xc3\xb2\xa1rest-of-a-pcap"
    capture_fails = False
    stop_fails = False

    # Атрибуты порта, как их отдаёт демон. По ним прогон судит о двух разных
    # вещах: об остатке, который оставил кто-то до нас (сервисный режим забыли
    # выключить), и об обрыве посреди замера (линк упал). Обе проверки до этого
    # были написаны вслепую - подделка про атрибуты не знала вовсе.
    port_service = False
    port_link = "UP"

    # Счётчики ошибок портов, как их отдаёт драйвер: имя -> значение. Прогон
    # читает их до и после и смотрит прирост, поэтому в подделке это две
    # картины, а не одна.
    xstats_before: ClassVar[dict] = {}
    xstats_after: ClassVar[dict] = {}

    def get_xstats(self, port):
        if not getattr(self, "flowing", False):
            return dict(FakeClient.xstats_before)
        return dict(FakeClient.xstats_after)

    def get_port_attr(self, port):
        return {"service": FakeClient.port_service,
                "link": FakeClient.port_link}

    # Возврат сервисного режима может не удаться - и это самый дорогой отказ на
    # общей машине: она остаётся в состоянии, в котором не пускает трафик вообще.
    service_restore_fails = False

    def set_service_mode(self, ports=None, enabled=False):
        self.calls.append(("service_mode", tuple(ports or ()), enabled))
        if not enabled and FakeClient.service_restore_fails:
            raise RuntimeError("порты заняты, режим не снять")

    def set_port_attr(self, ports=None, promiscuous=None, **kw):
        self.calls.append(("port_attr", tuple(ports or ()), promiscuous))

    def start_capture(self, **spec):
        if FakeClient.capture_fails:
            raise RuntimeError("no room for another capture")
        self.calls.append(("start_capture", tuple(sorted(spec))))
        return {"id": len(self.calls)}

    def stop_capture(self, handle, output=""):
        self.calls.append(("stop_capture", handle))
        if FakeClient.stop_fails:
            raise RuntimeError("capture went away")
        with open(output, "wb") as fh:
            fh.write(FakeClient.capture_bytes)

    def add_streams(self, streams, ports=None):
        self.streams = list(streams)
        self.calls.append(("add_streams", tuple(ports or ())))

    # Две разные вещи, которые на стенде дают одинаково большую цифру и лечатся
    # по-разному, поэтому и знобки две.
    #
    # stale_rx - счётчик, не обнулившийся с прошлого раза: постоянное смещение.
    # Оно видно и в опорной точке, и потом, прирост от него нулевой - и
    # вычитание опорной точки обязано его снять, оставив замер замером.
    #
    # idle_rx - живой чужой приток между опорной точкой и стартом: его в
    # опорной точке ещё нет, он появляется за паузу. Это уже не смещение, а
    # отравленная группа, и верить ей нельзя.
    stale_rx = 0
    idle_rx = 0

    def clear_stats(self):
        self.calls.append("clear_stats")
        # Обнуление - не декорация: между ним и стартом счётчики реально стоят
        # в нуле, и холостой замер прогона читает именно это окно. Подделка,
        # отдающая итоговые цифры всегда, показывала бы грязный сегмент в
        # каждом тесте и делала бы проверку бессмысленной.
        self.flowing = False

    def start(self, ports=None, duration=0, mult="1", force=False):
        self.calls.append(("start", tuple(ports or ()), duration, mult, force))
        self.flowing = True

    # Остался ли на портах трафик от прогона, который за собой не убрал.
    # Подделка обязана отличать «до старта» от «во время»: предстартовая
    # проверка остатка спрашивает то же самое и до старта обязана слышать
    # «нет», иначе чистая машина выглядит грязной.
    traffic_before_start = False

    def is_traffic_active(self, ports=None):
        if not getattr(self, "flowing", False):
            return FakeClient.traffic_before_start
        self.polls += 1
        return self.polls <= FakeClient.active_polls

    def wait_on_traffic(self, ports=None, timeout=0):
        self.calls.append("wait")

    def stop(self, ports=None):
        self.calls.append("stop")

    def disconnect(self):
        self.calls.append("disconnect")

    # When set, what the hardware groups report on the receive side, apart
    # from what the port counter saw. Real cards do disagree: some count
    # transmission per group and never the reception.
    group_rx = None
    # Releases have keyed port counters both ways, and one release simply has
    # no entry for a port it was not asked about.
    str_keys = False
    drop_rx_port = False
    # Порт, на котором группа считает приём, - тот же, что тесты задают в
    # --rx-port. Плюс два состояния, которые на стенде и наблюдались: кадры с
    # нашей меткой пришли мимо этого порта, и разбивки по порту нет вовсе.
    rx_port_index = 1
    group_rx_foreign = 0
    group_rx_no_port = False
    # Что демон знает о своём же счёте: помеченные кадры, которые он не отнёс
    # ни к одной группе. Подделка про это не знала вовсе, а на живом железе
    # это единственная цифра, которой групповой счёт опровергает сам себя.
    flow_err_rx = 0
    flow_err_tx = 0
    flow_err_port = 1

    def get_stats(self):
        if not getattr(self, "flowing", True):
            return self._idle_stats()
        groups = {}
        counted = [s for s in self.streams if s.flow_stats is not None]
        seen = FakeClient.rx if FakeClient.group_rx is None else FakeClient.group_rx
        for s in counted:
            mine = seen // len(counted)
            # Группа считает по портам, а не только итогом. Разбивка здесь не
            # украшение: именно по ней прогон отличает «наш кадр принят там, где
            # мы его ждём» от «кадр с нашей меткой пришёл куда-то ещё».
            rx = {"total": mine + FakeClient.group_rx_foreign}
            if not FakeClient.group_rx_no_port:
                rx[FakeClient.rx_port_index] = mine
            groups[s.flow_stats.kw["pg_id"]] = {
                "tx_pkts": {"total": FakeClient.tx // len(counted),
                            0: FakeClient.tx // len(counted)},
                "rx_pkts": rx,
            }
        if FakeClient.flow_err_rx or FakeClient.flow_err_tx:
            # Порт, на котором демон недосчитался. По умолчанию наш; тест,
            # который кладёт сюда чужой, проверяет, что соседний прогон не
            # отменяет наш замер.
            groups["global"] = {
                "rx_err": {FakeClient.flow_err_port: FakeClient.flow_err_rx},
                "tx_err": {0: FakeClient.flow_err_tx},
            }
        out = {
            0: {"opackets": FakeClient.tx, "obytes": FakeClient.tx * 64,
                "tx_pps": 1000.0},
            1: {"ipackets": FakeClient.rx},
            "flow_stats": groups,
        }
        if FakeClient.drop_rx_port:
            del out[1]
        if FakeClient.str_keys:
            out = {(str(k) if isinstance(k, int) else k): v
                   for k, v in out.items()}
        return out

    def _idle_stats(self):
        """Счётчики в окне между обнулением и стартом: наше молчание.

        Первое чтение - опорная точка: виден только несброшенный остаток.
        Следующие - уже после паузы, и в них добавляется то, что успело
        прилететь само.
        """
        seen = self._idle_reads
        self._idle_reads = seen + 1
        idle = FakeClient.stale_rx + (FakeClient.idle_rx if seen else 0)
        counted = [s for s in self.streams if s.flow_stats is not None]
        groups = {}
        for s in counted:
            share = idle // len(counted)
            groups[s.flow_stats.kw["pg_id"]] = {
                "tx_pkts": {"total": 0, 0: 0},
                "rx_pkts": {"total": share,
                            FakeClient.rx_port_index: share},
            }
        return {0: {"opackets": 0, "obytes": 0, "tx_pps": 0.0},
                1: {"ipackets": idle},
                "flow_stats": groups}


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
    FakeClient.group_rx = None
    FakeClient.owner = ""
    FakeClient.str_keys = False
    FakeClient.drop_rx_port = False
    FakeClient.idle_rx = 0
    FakeClient.stale_rx = 0
    FakeClient.port_service = False
    FakeClient.port_link = "UP"
    FakeClient.xstats_before = {}
    FakeClient.xstats_after = {}
    FakeClient.service_restore_fails = False
    FakeClient.traffic_before_start = False
    FakeClient.group_rx_foreign = 0
    FakeClient.group_rx_no_port = False
    FakeClient.flow_err_rx = 0
    FakeClient.flow_err_tx = 0
    FakeClient.flow_err_port = 1
    FakeClient.capture_fails = False
    FakeClient.stop_fails = False
    FakeClient.capture_bytes = b"\xd4\xc3\xb2\xa1rest-of-a-pcap"
    monkeypatch.setitem(sys.modules, "trex.stl.api", module)
    yield module
    FakeClient.last = None
    FakeClient.group_rx = None
    FakeClient.owner = ""
    FakeClient.str_keys = False
    FakeClient.drop_rx_port = False
    FakeClient.idle_rx = 0
    FakeClient.stale_rx = 0
    FakeClient.port_service = False
    FakeClient.port_link = "UP"
    FakeClient.xstats_before = {}
    FakeClient.xstats_after = {}
    FakeClient.service_restore_fails = False
    FakeClient.traffic_before_start = False
    FakeClient.group_rx_foreign = 0
    FakeClient.group_rx_no_port = False
    FakeClient.flow_err_rx = 0
    FakeClient.flow_err_tx = 0
    FakeClient.flow_err_port = 1
    FakeClient.capture_fails = False
    FakeClient.stop_fails = False


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
    got = next(c for c in FakeClient.last.calls
               if isinstance(c, tuple) and c[0] == "acquire")
    assert got[1] == (0, 1)


def test_ports_are_asked_for_politely_rather_than_taken(fake_trex):
    """``reset()`` is a force acquire. On a shared generator that is an
    eviction, so the script asks without force unless told otherwise."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--duration", "1"])
    calls = FakeClient.last.calls
    assert ("acquire", (0,), False) in calls
    assert not any(isinstance(c, tuple) and c[0] == "reset" for c in calls)
    start = next(c for c in calls if isinstance(c, tuple) and c[0] == "start")
    assert start[-1] is False          # force does not sneak in on start either


def test_recording_forces_the_start_over_our_own_service_mode(fake_trex):
    """Найдено на стенде 2026-09-30. Запись кадров ставит порты в сервисный
    режим, а стартовать на таком порту TRex без force отказывается - то есть
    неформированный старт ломал запись целиком.

    Отъёма чужого тут нет: порты уже захвачены, и захват вежливый. Продавливаем
    свой же режим.
    """
    run_stl(codegen_stl.generate(presets.build("l3_ip")), CAPTURE_ARGV)
    start = next(c for c in FakeClient.last.calls
                 if isinstance(c, tuple) and c[0] == "start")
    assert start[-1] is True


def test_without_recording_the_start_is_still_not_forced(fake_trex):
    """Чтобы TRex по-прежнему отказывался стартовать на упавшем линке: честный
    отказ лучше прогона, который вернётся как «потери 100%»."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    start = next(c for c in FakeClient.last.calls
                 if isinstance(c, tuple) and c[0] == "start")
    assert start[-1] is False


def test_a_port_somebody_else_holds_stops_the_run_and_names_the_owner(
        fake_trex, capsys):
    """The promise the Ixia engine already makes, now kept here too: a busy
    port is a reason to wait, not something to take while nobody is looking."""
    FakeClient.owner = "коллега"
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        ["--trex-dir", "/nowhere", "--tx-port", "0",
                         "--duration", "1"])
    assert namespace["_rc"] == 4
    said = [e for e in events(capsys) if e["ev"] == "error"]
    assert said and "коллега" in said[0]["msg"]
    assert "--force" in said[0]["msg"]
    assert not any(isinstance(c, tuple) and c[0] == "start"
                   for c in FakeClient.last.calls)


def test_force_takes_the_port_and_says_so(fake_trex):
    FakeClient.owner = "коллега"
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        ["--trex-dir", "/nowhere", "--tx-port", "0",
                         "--duration", "1", "--force"])
    assert namespace["_rc"] == 0
    assert ("acquire", (0,), True) in FakeClient.last.calls


def test_the_ports_are_handed_back_when_the_run_ends(fake_trex):
    """A release that happens only as a side effect of disconnecting is one
    that does not happen when the connection has already gone."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    calls = FakeClient.last.calls
    assert ("release", (0, 1)) in calls
    assert calls.index(("release", (0, 1))) < calls.index("disconnect")


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


def test_the_four_ways_a_trex_host_can_be_unready_are_four_answers():
    """Схлопывать их в «нет TRex» значит посылать чинить не то. Четвёртый
    появился после стенда: порт 4501 открыт, а демон на запросы не отвечает -
    «связь проверена» при этом зелёная, и прогон падает на первом же запросе.
    """
    engine = engines.get("trex")
    assert any("каталог" in b for b in engine.blockers(HostInfo(ok=True)))

    unpacked = HostInfo(ok=True, has_trex=True, trex_dir="/opt/trex")
    assert any("trex_control_plane" in b for b in engine.blockers(unpacked))

    port_closed = HostInfo(ok=True, has_trex=True, has_trex_stl=True,
                           trex_dir="/opt/trex")
    said = engine.blockers(port_closed)
    assert any("демон TRex не отвечает" in b for b in said)

    deaf = HostInfo(ok=True, has_trex=True, has_trex_stl=True,
                    trex_daemon=True, trex_rpc=False, trex_dir="/opt/trex-3.08",
                    trex_rpc_error="Failed to send message to server")
    said = engine.blockers(deaf)
    assert any("не отвечает на запросы" in b for b in said)
    assert any("Failed to send message" in b for b in said), "причина потеряна"
    assert any("/opt/trex-3.08" in b for b in said), "совет указывает не на тот каталог"

    running = HostInfo(ok=True, has_trex=True, has_trex_stl=True,
                       trex_daemon=True, trex_rpc=True, trex_dir="/opt/trex")
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


# --------------------------------------------------------------------------- #
# A zero from the hardware groups, contradicted by the port counter
# --------------------------------------------------------------------------- #
def test_groups_blind_to_the_receive_side_lose_to_the_port_counter(fake_trex,
                                                                   capsys):
    """Found on a live bench: the switch forwarded all 5000 frames, the port
    counter saw all 5000, and the flow-stat groups reported nothing at all.
    Trusting the group there turns a working link into "потери 100%" with
    reliable=True on it - a confident wrong answer, and the worst kind."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 5000, 5000, 0
    profile = presets.build("l3_ip")
    run_stl(codegen_stl.generate(profile, tag="t"),
            ["--trex-dir", "/nowhere", "--server", "127.0.0.1",
             "--tx-port", "0", "--rx-port", "1", "--duration", "1"])
    done = [e for e in events(capsys) if e.get("ev") == "done"][-1]
    assert done["rx"] == 5000
    assert done["rx_source"] == "flow_stats_blind"
    assert done["reliable"] is False


def test_a_genuine_zero_is_still_reported_as_a_hardware_zero(fake_trex, capsys):
    """Nothing arrived and nothing was counted: the groups and the port agree,
    so the zero stands as a hardware fact rather than being second-guessed."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 5000, 0, 0
    profile = presets.build("l3_ip")
    run_stl(codegen_stl.generate(profile, tag="t"),
            ["--trex-dir", "/nowhere", "--server", "127.0.0.1",
             "--tx-port", "0", "--rx-port", "1", "--duration", "1"])
    done = [e for e in events(capsys) if e.get("ev") == "done"][-1]
    assert done["rx"] == 0
    assert done["rx_source"] == "flow_stats"
    assert done["reliable"] is True


def test_groups_that_counted_something_are_left_alone(fake_trex, capsys):
    """A port counter is always >= the groups: it also sees traffic that is
    not ours. Only a group total of zero is treated as a contradiction."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 5000, 9000, 4990
    profile = presets.build("l3_ip")
    run_stl(codegen_stl.generate(profile, tag="t"),
            ["--trex-dir", "/nowhere", "--server", "127.0.0.1",
             "--tx-port", "0", "--rx-port", "1", "--duration", "1"])
    done = [e for e in events(capsys) if e.get("ev") == "done"][-1]
    assert done["rx"] == 4990
    assert done["rx_source"] == "flow_stats"
    assert done["reliable"] is True


def test_a_zero_nobody_could_contradict_is_not_sold_as_certain(
        fake_trex, capsys):
    """The safety net has its own failure mode. Groups reading zero is checked
    against the receiving port - but if that counter cannot be read at all, the
    check silently passes and a working link goes out as confident total loss.
    """
    FakeClient.group_rx = 0
    FakeClient.drop_rx_port = True
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = next(e for e in events(capsys) if e["ev"] == "done")
    assert done["rx_source"] == "flow_stats_unverified"
    assert done["reliable"] is False
    assert "сверить" in done["note"]


def test_port_counters_are_found_whichever_way_the_release_keys_them(
        fake_trex, capsys):
    """Miss the port entry and the contradiction that saves a blind driver
    never happens - so the lookup tries the string key too."""
    FakeClient.group_rx = 0
    FakeClient.str_keys = True
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = next(e for e in events(capsys) if e["ev"] == "done")
    assert done["rx_source"] == "flow_stats_blind"
    assert done["rx"] == 995


# --------------------------------------------------------------------------- #
# Поимённо по группам, и счёт самого счёта
# --------------------------------------------------------------------------- #
def test_each_group_reports_its_own_numbers_not_just_the_sum(fake_trex, capsys):
    """Сумма отвечает «сколько принято» и молчит про «какой именно группой».

    На стенде отравленной оказалась часть групп, и по одной общей цифре нельзя
    было сказать, какая именно, - разбирали диффом сгенерированных скриптов.
    IMIX - три потока, то есть три группы: ровно тот случай, где сумма скрывает
    расклад."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 3000, 2997, 2997
    run_stl(codegen_stl.generate(presets.build("imix")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    seen = events(capsys)
    done = next(e for e in seen if e["ev"] == "done")
    rows = done["groups"]
    assert len(rows) == 3, rows
    # Каждая строка - про свою группу, и сумма строк сходится с общей цифрой.
    assert sum(row["rx_port"] for row in rows.values()) == done["rx"]
    assert all(row["port_seen"] for row in rows.values())
    # И то же самое в каждом тике, а не только в итоге: по архиву должно быть
    # видно, КОГДА группа разъехалась со счётчиком порта.
    tick = next(e for e in seen if e["ev"] == "tick")
    assert len(tick["groups"]) == 3


def test_a_group_counting_frames_off_the_receive_port_says_so_by_name(
        fake_trex, capsys):
    """Кадры с нашей меткой, пришедшие мимо порта приёма, видны не только в
    общей цифре ``rx_foreign``, но и в строке той группы, которая их набрала."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 1000, 1000, 1000
    FakeClient.group_rx_foreign = 40
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = next(e for e in events(capsys) if e["ev"] == "done")
    row = next(iter(done["groups"].values()))
    assert row["rx_foreign"] == 40
    assert row["rx_port"] == 1000
    assert done["rx_source"] == "flow_stats_foreign"


def test_frames_the_daemon_never_filed_under_a_group_disqualify_the_count(
        fake_trex, capsys):
    """``flow_stats['global']['rx_err']`` - демон сознаётся, что часть
    помеченных кадров приехала и в группу не попала.

    Группа при этом выглядит ровно, недостача ложится в колонку потерь, и
    отличить её от кадров, съеденных устройством, больше нечем: группа молчит
    точно так же. Пока эта цифра не читалась, прогон уходил с пометкой
    «надёжно» - то есть с уверенным неверным ответом."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 5000, 4800, 4800
    FakeClient.flow_err_rx = 200
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    seen = events(capsys)
    done = next(e for e in seen if e["ev"] == "done")
    assert done["flow_err_rx"] == 200
    # Счёт сошёлся сам с собой - и всё равно не надёжен: недостача учёта
    # выглядит точно как потери.
    assert done["rx_source"] == "flow_stats"
    assert done["reliable"] is False
    said = " ".join(e.get("msg", "") for e in seen if e["ev"] == "note")
    assert "не отнёс" in said and "200" in said


def test_a_clean_global_counter_leaves_the_hardware_count_alone(fake_trex,
                                                                capsys):
    """Ноль ошибок учёта - не повод для оговорки: иначе предупреждения
    перестают читать, и первое настоящее проходит мимо."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 5000, 4800, 4800
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = next(e for e in events(capsys) if e["ev"] == "done")
    assert done["flow_err_rx"] == 0
    assert done["reliable"] is True


def test_an_accounting_shortfall_on_somebody_elses_port_is_not_ours(fake_trex,
                                                                    capsys):
    """Генератор общий. Недостача учёта на чужом порту - чужая новость, и
    сложить её со своей значит отказать своему замеру за соседний прогон."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 5000, 5000, 5000
    FakeClient.flow_err_rx = 900
    FakeClient.flow_err_port = 7          # не наш порт приёма
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = next(e for e in events(capsys) if e["ev"] == "done")
    assert done["flow_err_rx"] == 0
    assert done["reliable"] is True


def test_the_global_counter_is_read_as_a_difference_not_an_absolute(fake_trex,
                                                                    capsys):
    """Демон живёт неделями, и его счётчик ошибок учёта - такой же абсолют, как
    всё остальное. Прочитать его как есть значит однажды дисквалифицировать
    чистый прогон за чужую недостачу, случившуюся вчера."""
    FakeClient.tx, FakeClient.rx, FakeClient.group_rx = 5000, 5000, 5000
    FakeClient.flow_err_rx = 70
    # Подделка отдаёт ошибки учёта и в окне молчания - то есть они были ДО нас.
    base = FakeClient._idle_stats
    def with_global(self):
        out = base(self)
        out["flow_stats"]["global"] = {"rx_err": {1: FakeClient.flow_err_rx},
                                       "tx_err": {0: 0}}
        return out
    FakeClient._idle_stats = with_global
    try:
        run_stl(codegen_stl.generate(presets.build("l3_ip")),
                ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
                 "--duration", "1"])
    finally:
        FakeClient._idle_stats = base
    done = next(e for e in events(capsys) if e["ev"] == "done")
    assert done["flow_err_rx"] == 0
    assert done["reliable"] is True


# --------------------------------------------------------------------------- #
# Recording frames: on by default, and until now exercised by nothing
# --------------------------------------------------------------------------- #
CAPTURE_ARGV = ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
                "--duration", "1", "--capture", "--capture-limit", "10"]


def service_mode_calls(calls) -> list:
    return [c for c in calls if isinstance(c, tuple) and c[0] == "service_mode"]


def test_recording_puts_the_ports_in_service_mode_and_takes_them_out_again(
        fake_trex):
    """The mode is what makes recording possible and what costs the rate. Left
    on, it slows every later run on this machine for reasons nobody will
    connect to a capture taken hours earlier."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")), CAPTURE_ARGV)
    modes = service_mode_calls(FakeClient.last.calls)
    assert modes[0] == ("service_mode", (0, 1), True)
    assert modes[-1] == ("service_mode", (0, 1), False)


def test_the_rate_ceiling_is_said_out_loud_rather_than_discovered(
        fake_trex, capsys):
    run_stl(codegen_stl.generate(presets.build("l3_ip")), CAPTURE_ARGV)
    said = " ".join(e.get("msg", "") for e in events(capsys)
                    if e["ev"] == "note")
    assert "сервисном режиме" in said
    assert "потолок скорости" in said


def test_recorded_frames_travel_home_inside_the_event_stream(
        fake_trex, capsys):
    """Nothing is left on the generator: it is shared, and a tool that
    scatters pcaps across somebody else's box gets uninstalled."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")), CAPTURE_ARGV)
    seen = events(capsys)
    shipped = {e["name"] for e in seen if e["ev"] == "capture"}
    assert shipped == {"tx", "rx"}
    assert [e for e in seen if e["ev"] == "capture_data"]
    for e in (e for e in seen if e["ev"] == "capture"):
        assert e["bytes"] == len(FakeClient.capture_bytes)
        assert e["limit"] == 10


def test_the_sending_side_carries_its_checksum_caveat(fake_trex, capsys):
    """TX frames are copied before the card computes checksums. Shipping that
    without saying so means somebody opens the pcap and blames the device."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")), CAPTURE_ARGV)
    said = " ".join(e.get("msg", "") for e in events(capsys)
                    if e["ev"] == "note")
    assert "контрольные суммы" in said
    assert "по записи приёма" in said


def test_an_empty_capture_is_not_offered_as_proof_of_loss(fake_trex, capsys):
    """Observed on real hardware: a non-zero receive counter and an empty L2
    capture. Calling that "кадров не было" turns a property of the capture into
    a finding about the link."""
    FakeClient.capture_bytes = b""
    run_stl(codegen_stl.generate(presets.build("l3_ip")), CAPTURE_ARGV)
    said = " ".join(e.get("msg", "") for e in events(capsys)
                    if e["ev"] == "note")
    assert "НЕЛЬЗЯ судить о потерях" in said
    assert "кадров не было" not in said


def test_a_capture_that_will_not_start_does_not_take_the_run_with_it(
        fake_trex, capsys):
    """Recording is worth having, not worth failing a measurement over - but
    the ports still have to come out of service mode."""
    FakeClient.capture_fails = True
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        CAPTURE_ARGV)
    assert namespace["_rc"] == 0
    said = " ".join(e.get("msg", "") for e in events(capsys)
                    if e["ev"] == "note")
    assert "захват не начался" in said
    assert ("service_mode", (0, 1), False) in FakeClient.last.calls


def test_a_capture_that_dies_on_the_way_out_still_frees_the_ports(
        fake_trex, capsys):
    FakeClient.stop_fails = True
    run_stl(codegen_stl.generate(presets.build("l3_ip")), CAPTURE_ARGV)
    assert service_mode_calls(FakeClient.last.calls)[-1][2] is False
    said = " ".join(e.get("msg", "") for e in events(capsys)
                    if e["ev"] == "note")
    assert "не сохранилась" in said


def test_without_a_receive_port_the_engine_does_not_ask_for_recording():
    """Recording what left while nothing records what arrived answers half of
    every question, so the engine does not turn it on at all."""
    target = Target(name="t", engine="trex", trex_port_tx=0, trex_port_rx=-1)
    args = engines.get("trex").args(target, RunSpec(capture=True), None)
    assert "--capture" not in args


def test_the_engine_never_hands_the_target_a_path_from_this_machine():
    """Найдено на стенде 2026-09-30. Скрипт исполняется на машине-генераторе,
    а каталог прогона живёт на той, что его запустила. Переданный туда путь
    «~/.local/state/traphy/runs/…/streams.pcap» роняет прогон в write_pcap -
    до подключения к демону, то есть до единого кадра в кабеле."""
    from pathlib import Path

    archive = Path("/home/кто-то/.local/state/traphy/runs/20260930-144830_x")
    args = engines.get("trex").args(
        Target(name="t", engine="trex", trex_port_tx=0, trex_port_rx=1),
        RunSpec(save_pcap=True, dry_run=True), archive)
    assert "--ship-frames" in args
    assert not any(str(archive) in a for a in args), "путь отсюда уехал на цель"


def test_shipped_sample_frames_come_home_inside_the_event_stream(
        fake_trex, capsys):
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--duration", "1",
             "--dry-run", "--ship-frames"])
    seen = events(capsys)
    shipped = [e for e in seen if e["ev"] == "capture" and e["name"] == "streams"]
    assert shipped, "образцы кадров не поехали домой"
    assert shipped[0]["bytes"] > 0
    assert [e for e in seen if e["ev"] == "capture_data"]


def test_shipping_frames_leaves_nothing_on_the_generator(fake_trex, capsys,
                                                         tmp_path):
    """Генератор общий: инструмент, раскидывающий по нему файлы, перестают
    ставить."""
    before = set(tmp_path.iterdir())
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--duration", "1",
             "--dry-run", "--ship-frames"])
    assert set(tmp_path.iterdir()) == before


def test_a_hardware_count_bigger_than_what_was_sent_is_not_trusted(
        fake_trex, capsys):
    """Найдено на стенде 2026-09-30: в приёмный порт лился чужой трафик, группа
    насчитала 46 млн при 20 тысячах отправленных - и прогон уходил с пометкой
    «надёжно». Столько наших кадров вернуться не могло; это опровержение, а не
    хороший результат."""
    FakeClient.tx, FakeClient.rx = 20_000, 46_000_000
    FakeClient.group_rx = 46_000_000
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = next(e for e in events(capsys) if e["ev"] == "done")
    assert done["rx_source"] == "flow_stats"
    assert done["reliable"] is False, "опровергнутый счёт нельзя звать надёжным"
    assert "не только наше" in done["note"]


def test_a_hardware_count_within_what_was_sent_is_still_trusted(
        fake_trex, capsys):
    FakeClient.tx, FakeClient.rx = 1000, 995
    FakeClient.group_rx = 995
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
             "--duration", "1"])
    done = next(e for e in events(capsys) if e["ev"] == "done")
    assert done["reliable"] is True


def test_a_run_that_dies_still_puts_the_ports_back_in_the_fast_path(fake_trex):
    """Найдено на стенде 2026-09-30, и это отравляло машину всем.

    Сервисный режим включается ради записи кадров. Снимался он в stop_capture,
    до которого при отказе посреди прогона дело не доходило - и порты
    оставались в нём навсегда. Следующий прогон БЕЗ записи после этого не
    стартует вообще: TRex отказывается пускать трафик на порт в сервисном
    режиме. Связать это с записью, снятой часами раньше, не сможет никто.
    """
    class Boom(FakeClient):
        def start(self, ports=None, duration=0, mult="1", force=False):
            super().start(ports=ports, duration=duration, mult=mult, force=force)
            raise RuntimeError("порт не пустил")

    fake_trex.STLClient = Boom
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        CAPTURE_ARGV)
    assert namespace["_rc"] == 1
    calls = FakeClient.last.calls
    modes = service_mode_calls(calls)
    assert modes, "сервисный режим вообще не трогали"
    assert modes[-1][2] is False, "порты остались в сервисном режиме"
    # И запись снята ДО него: пока она жива, TRex режим выключать отказывается.
    stopped = [i for i, c in enumerate(calls)
               if isinstance(c, tuple) and c[0] == "stop_capture"]
    assert stopped, "запись осталась висеть на машине"
    assert max(stopped) < calls.index(modes[-1])
    # И отданы обратно, чтобы следующий не упёрся в мёртвого владельца.
    assert any(isinstance(c, tuple) and c[0] == "release"
               for c in FakeClient.last.calls)
