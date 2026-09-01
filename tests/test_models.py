"""The traffic model: rates, validation and how ranges are sized."""

from __future__ import annotations

import pytest

from traphy.models import (
    FieldTarget,
    L4Proto,
    Packet,
    Profile,
    RateType,
    Stream,
    TxMode,
    VMField,
    VMOp,
    range_size,
)


def test_pps_from_each_rate_unit():
    """Every unit resolves to packets per second the same way the script does."""
    s = Stream(packet=Packet(frame_size=100), rate_type=RateType.PPS, rate_value=500)
    assert s.pps() == 500

    s.rate_type, s.rate_value = RateType.BPS_L2, 800_000
    assert s.pps() == 1000                       # 800 kbit / (100 B * 8)

    # A percentage prices the wire, so preamble, FCS and the gap count too.
    s.rate_type, s.rate_value = RateType.PERCENT, 100
    assert s.pps(link_mbit=1000) == pytest.approx(1e9 / ((100 + 24) * 8))


def test_frame_size_bounds_are_rejected():
    too_small = Profile(streams=[Stream(packet=Packet(frame_size=32))])
    assert any("меньше" in p for p in too_small.validate())

    too_big = Profile(streams=[Stream(packet=Packet(frame_size=9500))])
    assert any("jumbo" in p for p in too_big.validate())


def test_duplicate_stream_names_are_caught():
    profile = Profile(streams=[Stream(name="a"), Stream(name="a")])
    assert any("повторяется" in p for p in profile.validate())


def test_all_streams_disabled_is_a_problem():
    """A profile that would send nothing must say so, not run empty."""
    profile = Profile(streams=[Stream(enabled=False)])
    assert any("выключены" in p for p in profile.validate())


def test_range_on_a_layer_the_frame_lacks():
    """A port range on an L2 frame would silently do nothing at run time."""
    stream = Stream(
        packet=Packet(layer="l2"),
        vm_fields=[VMField(target=FieldTarget.DPORT, min_value="1", max_value="9")],
    )
    problems = Profile(streams=[stream]).validate()
    assert any("нет L4" in p for p in problems)

    stream.packet.layer = "l3"
    stream.vm_fields = [VMField(target=FieldTarget.IP_SRC)]
    assert Profile(streams=[stream]).validate() == []


def test_backwards_range_is_caught():
    stream = Stream(vm_fields=[VMField(target=FieldTarget.IP_SRC,
                                       min_value="16.0.0.9", max_value="16.0.0.1")])
    assert any("задом наперёд" in p for p in Profile(streams=[stream]).validate())


def test_unparseable_range_ends():
    stream = Stream(vm_fields=[VMField(target=FieldTarget.IP_SRC,
                                       min_value="не адрес", max_value="16.0.0.1")])
    assert any("не разобрать" in p for p in Profile(streams=[stream]).validate())


@pytest.mark.parametrize("lo,hi,step,expected", [
    ("16.0.0.1", "16.0.0.255", 1, 255),
    ("16.0.0.1", "16.0.0.255", 2, 128),   # 1, 3, … 255
    ("16.0.0.1", "16.0.0.1", 1, 1),
])
def test_range_size(lo, hi, step, expected):
    assert range_size(VMField(min_value=lo, max_value=hi, step=step)) == expected


def test_burst_settings_must_be_positive():
    stream = Stream(tx_mode=TxMode.MULTI_BURST, pkts_per_burst=0)
    assert any("один пакет" in p for p in Profile(streams=[stream]).validate())


def test_profile_round_trips_through_json(tmp_path):
    """Everything the builder can set survives a save and a load."""
    original = Profile(
        name="round", description="проверка",
        streams=[Stream(
            name="s", packet=Packet(layer="l4", vlan=100, l4_proto=L4Proto.TCP,
                                    frame_size=512),
            rate_type=RateType.BPS_L2, rate_value=1e6,
            tx_mode=TxMode.MULTI_BURST, pkts_per_burst=7, number_of_bursts=3,
            vm_fields=[VMField(target=FieldTarget.DPORT, op=VMOp.DEC,
                               min_value="1", max_value="99", step=3)])],
    )
    path = original.save(tmp_path / "p.json")
    loaded = Profile.load(path)
    assert loaded.to_dict() == original.to_dict()
    assert loaded.streams[0].packet.vlan == 100
    assert loaded.streams[0].vm_fields[0].op is VMOp.DEC


def test_packet_describe_mentions_every_layer():
    assert Packet(layer="l2").describe().startswith("Eth")
    assert "VLAN7" in Packet(layer="l2", vlan=7).describe()
    assert "TCP" in Packet(layer="l4", l4_proto=L4Proto.TCP).describe()
