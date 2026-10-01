"""The generated script's own send loop, exercised without root or a NIC.

A fake ``scapy.all`` is installed in ``sys.modules`` and the script is exec'd,
so the pacing, the burst state machine, the counting and the honesty flags are
all tested for real. Without this the engine would only ever be checked by
running it as root against live hardware, which is exactly the code path that
should not be first tried on a live device.
"""

from __future__ import annotations

import json

import pytest

from traphy.codegen import generate
from traphy.models import (
    FieldTarget,
    Packet,
    Profile,
    RateType,
    Stream,
    TxMode,
    VMField,
    VMOp,
)


def run(source: str, argv: list[str]) -> tuple[int, list[dict]]:
    """Exec a generated script and collect the events it printed."""
    import io
    import contextlib

    namespace: dict = {"__name__": "generated"}
    exec(compile(source, "generated.py", "exec"), namespace)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = namespace["main"](argv)
    events = [json.loads(line[len("@traphy "):])
              for line in buffer.getvalue().splitlines()
              if line.startswith("@traphy ")]
    return rc, events


def load(source: str) -> dict:
    """Exec a generated script without running it, to poke at its helpers."""
    namespace: dict = {"__name__": "generated"}
    exec(compile(source, "generated.py", "exec"), namespace)
    return namespace


def final(events: list[dict]) -> dict:
    return next(e for e in events if e["ev"] == "done")


def test_a_short_continuous_run_sends_at_about_the_asked_rate(fake_scapy):
    profile = Profile(streams=[Stream(rate_type=RateType.PPS, rate_value=2000)])
    rc, events = run(generate(profile), ["--iface", "eth9", "--duration", "0.5"])

    assert rc == 0
    done = final(events)
    # Pacing is best-effort by design, so this checks the order of magnitude,
    # not a precise count: the point is that it neither stalls nor runs away.
    assert 500 <= done["tx"] <= 1600
    assert done["tx_bytes"] == done["tx"] * 64
    assert fake_scapy.sockets[0].iface == "eth9"
    assert fake_scapy.sockets[0].closed


def test_the_socket_is_opened_once_not_per_frame(fake_scapy):
    profile = Profile(streams=[Stream(rate_value=500)])
    run(generate(profile), ["--iface", "eth0", "--duration", "0.3"])
    assert len(fake_scapy.sockets) == 1


def test_a_count_run_sends_exactly_that_many(fake_scapy):
    profile = Profile(streams=[Stream(rate_value=5000)])
    _rc, events = run(generate(profile), ["--iface", "eth0", "--count", "300"])
    assert final(events)["tx"] == 300


def test_frames_cycle_through_an_expanded_range(fake_scapy):
    """Every address in the sweep goes out, in order, and then it wraps."""
    stream = Stream(rate_value=5000, packet=Packet(layer="l3"),
                    vm_fields=[VMField(target=FieldTarget.IP_DST, op=VMOp.INC,
                                       min_value="48.0.0.1", max_value="48.0.0.10")])
    run(generate(Profile(streams=[stream])), ["--iface", "eth0", "--count", "20"])
    sent = fake_scapy.sockets[0].sent
    assert len(sent) == 20
    assert sent[:10] == sent[10:]          # the set repeats, in the same order
    assert len({bytes(f) for f in sent}) == 10


def test_a_single_burst_stops_after_one_burst(fake_scapy):
    stream = Stream(rate_value=10_000, tx_mode=TxMode.SINGLE_BURST,
                    pkts_per_burst=120)
    _rc, events = run(generate(Profile(streams=[stream])),
                      ["--iface", "eth0", "--duration", "2"])
    assert final(events)["tx"] == 120


def test_multi_burst_sends_every_burst_and_no_more(fake_scapy):
    stream = Stream(rate_value=50_000, tx_mode=TxMode.MULTI_BURST,
                    pkts_per_burst=50, number_of_bursts=4, ibg_usec=1000)
    _rc, events = run(generate(Profile(streams=[stream])),
                      ["--iface", "eth0", "--duration", "3"])
    assert final(events)["tx"] == 200


def test_streams_are_mixed_in_proportion_to_their_rates(fake_scapy):
    """IMIX is only IMIX if the small frames really do outnumber the big ones."""
    profile = Profile(streams=[
        Stream(name="small", packet=Packet(frame_size=64), rate_value=4000),
        Stream(name="big", packet=Packet(frame_size=512), rate_value=1000),
    ])
    run(generate(profile), ["--iface", "eth0", "--count", "500"])
    sizes = [len(f) for f in fake_scapy.sockets[0].sent]
    small = sizes.count(64)
    assert small / len(sizes) == pytest.approx(0.8, abs=0.1)


def test_without_a_receive_interface_the_result_says_so(fake_scapy):
    _rc, events = run(generate(Profile(streams=[Stream(rate_value=200)])),
                      ["--iface", "eth0", "--duration", "0.2"])
    done = final(events)
    assert done["rx"] == 0
    assert done["rx_source"] == "none"
    assert done["reliable"] is False


def test_with_a_receive_interface_the_catch_is_counted(fake_scapy, sniffer_catches):
    """Counted, named - and never called reportable-as-is.

    A sniffer matching a marker sees only our frames, which is worth more than
    a port counter. It is still software: at rate it drops frames on its own,
    and the loss column then describes the sniffer. So the figure always
    carries its caveat.
    """
    sniffer_catches(42)
    _rc, events = run(generate(Profile(streams=[Stream(rate_value=200)])),
                      ["--iface", "eth0", "--rx-iface", "eth1", "--duration", "0.2"])
    done = final(events)
    assert done["rx"] == 42
    assert done["rx_source"] == "marker"
    assert done["reliable"] is False


# --------------------------------------------------------------------------- #
# MTU: the setting on this machine that looks exactly like a fault in the device
# --------------------------------------------------------------------------- #
def mtu_check(fake_scapy, frame_size, mtu, vlan=None):
    """Run the script's own MTU check against a made-up interface size."""
    stream = Stream(rate_value=10,
                    packet=Packet(layer="l3", frame_size=frame_size, vlan=vlan))
    ns = load(generate(Profile(streams=[stream])))
    ns["link_mtu"] = lambda _iface: mtu
    built = ns["build_all"](True)
    return ns["mtu_refusals"]("eth0", built)


def test_a_frame_that_will_not_fit_the_mtu_is_refused_before_it_is_sent(fake_scapy):
    """Otherwise it simply does not go out, and the run reports 100% loss -
    indistinguishable from a dead port or a wrong VLAN, except that the fault is
    on this machine and everybody goes looking in the device."""
    refusals = mtu_check(fake_scapy, frame_size=9000, mtu=1500)
    assert len(refusals) == 1
    assert "9000" in refusals[0] and "1500" in refusals[0]
    assert "1514" in refusals[0]          # what the MTU actually allows


def test_a_frame_that_exactly_fills_the_mtu_is_allowed(fake_scapy):
    assert mtu_check(fake_scapy, frame_size=1514, mtu=1500) == []


def test_a_tag_buys_four_more_bytes(fake_scapy):
    """MTU covers the payload above L2, so the header and each tag sit on top.
    A tagged 1518 fits a 1500 MTU; the same frame untagged at 1519 does not."""
    assert mtu_check(fake_scapy, frame_size=1518, mtu=1500, vlan=100) == []
    assert mtu_check(fake_scapy, frame_size=1519, mtu=1500) != []


def test_an_unreadable_mtu_lets_the_run_proceed(fake_scapy):
    """Zero means "не знаю", not "не влезет". Refusing over an unreadable file
    would be worse than trying to send."""
    assert mtu_check(fake_scapy, frame_size=9000, mtu=0) == []


def test_the_refusal_names_the_interface_and_both_ways_out(fake_scapy):
    line = mtu_check(fake_scapy, frame_size=9000, mtu=1500)[0]
    assert "eth0" in line
    assert "уменьши размер" in line and "подними" in line


def test_a_truncated_range_is_reported_not_swallowed(fake_scapy):
    stream = Stream(rate_value=100, packet=Packet(layer="l3"),
                    vm_fields=[VMField(target=FieldTarget.IP_DST, op=VMOp.INC,
                                       min_value="48.0.0.1",
                                       max_value="48.0.255.254")])
    _rc, events = run(generate(Profile(streams=[stream])),
                      ["--iface", "eth0", "--duration", "0.1"])
    ready = next(e for e in events if e["ev"] == "ready")
    assert ready["truncated"], "усечение диапазона должно быть названо"
    assert "1024" in ready["truncated"][0]


def test_dry_run_touches_no_socket(fake_scapy):
    _rc, events = run(generate(Profile(streams=[Stream()])),
                      ["--iface", "eth0", "--dry-run"])
    assert fake_scapy.sockets == []
    done = final(events)
    assert done["tx"] == 0 and done["reliable"] is False


def test_quiet_suppresses_the_machine_readable_lines(fake_scapy):
    _rc, events = run(generate(Profile(streams=[Stream(rate_value=100)])),
                      ["--iface", "eth0", "--duration", "0.1", "--quiet"])
    assert events == []


def test_frames_carry_the_marker_so_a_sniffer_can_match_them(fake_scapy):
    run(generate(Profile(streams=[Stream()]), tag="MARK42"),
        ["--iface", "eth0", "--count", "1"])
    assert b"MARK42" in fake_scapy.sockets[0].sent[0]


def test_frames_are_padded_to_the_requested_size(fake_scapy):
    profile = Profile(streams=[Stream(packet=Packet(frame_size=333))])
    run(generate(profile), ["--iface", "eth0", "--count", "1"])
    assert len(fake_scapy.sockets[0].sent[0]) == 333


def test_a_frame_too_small_for_its_headers_is_not_truncated(fake_scapy):
    """Cutting a header would emit something that still parses but is garbage."""
    profile = Profile(streams=[Stream(packet=Packet(layer="l4", frame_size=60))])
    run(generate(profile), ["--iface", "eth0", "--count", "1"])
    assert len(fake_scapy.sockets[0].sent[0]) >= 42
