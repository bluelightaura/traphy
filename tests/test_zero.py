"""A zero never goes out bare: what is established, and what is only suspected."""

from __future__ import annotations

from traphy.models import Packet, Profile, Stream
from traphy.runner import RunResult
from traphy.runner import zero
from traphy.target import Target


def profile_with(**packet_kw) -> Profile:
    return Profile(name="p", streams=[Stream(packet=Packet(**packet_kw))])


def result(**kw) -> RunResult:
    base = {"tx_pkts": 1000, "rx_pkts": 0, "rx_source": "flow_stats",
            "reliable": True, "engine": "trex", "tx_iface": "порт 0",
            "rx_iface": "порт 1"}
    return RunResult(**{**base, **kw})


def test_a_run_that_delivered_says_nothing():
    """Explaining a zero that did not happen would be noise on every screen."""
    assert zero.explain(result(rx_pkts=1000), profile_with(), Target()) == []


def test_nothing_sent_points_away_from_the_device():
    lines = zero.established(result(tx_pkts=0, rx_source="none"))
    assert "ни единого кадра" in lines[0]
    assert "устройство здесь ни при чём" in lines[0]


def test_hardware_count_makes_the_zero_mean_zero():
    lines = zero.established(result())
    assert any("ноль здесь означает именно ноль" in line for line in lines)


def test_nobody_counting_is_not_a_zero():
    lines = zero.established(result(rx_source="none", reliable=False))
    assert any("никто не считал" in line for line in lines)


def test_unmeasured_receive_is_the_only_thing_worth_saying():
    """With no receive port there is nothing to deduce about the device yet."""
    checks = zero.worth_checking(
        result(rx_source="none", reliable=False), profile_with(), Target())
    assert len(checks) == 1
    assert "порт приёма" in checks[0]


def test_tagged_frames_name_the_vlan_to_check():
    checks = zero.worth_checking(result(), profile_with(vlan=100), Target())
    assert any("[100]" in c and "VLAN" in c for c in checks)


def test_untagged_frames_warn_about_a_trunk():
    checks = zero.worth_checking(result(), profile_with(vlan=None), Target())
    assert any("без тега" in c and "trunk" in c for c in checks)


def test_unicast_destination_is_flagged_but_broadcast_is_not():
    unicast = zero.worth_checking(
        result(), profile_with(eth_dst="00:11:22:33:44:55"), Target())
    assert any("юникастовое" in c for c in unicast)
    broadcast = zero.worth_checking(
        result(), profile_with(eth_dst="ff:ff:ff:ff:ff:ff"), Target())
    assert not any("юникастовое" in c for c in broadcast)


def test_multicast_counts_as_a_group_address():
    checks = zero.worth_checking(
        result(), profile_with(eth_dst="01:00:5e:00:00:01"), Target())
    assert not any("юникастовое" in c for c in checks)


def test_classic_frame_size_gets_the_fcs_reminder():
    """The 64-vs-60 trap costs a morning when it is not said out loud."""
    checks = zero.worth_checking(result(), profile_with(frame_size=64), Target())
    assert any("без FCS" in c and "60" in c for c in checks)
    quiet = zero.worth_checking(result(), profile_with(frame_size=128), Target())
    assert not any("без FCS" in c for c in quiet)


def test_same_port_both_ways_is_named_first():
    checks = zero.worth_checking(
        result(tx_iface="порт 0", rx_iface="порт 0"), profile_with(), Target())
    assert "собственную отправку" in checks[0]


def test_trex_falling_back_to_the_port_counter_is_called_out():
    checks = zero.worth_checking(
        result(rx_source="port_counter", reliable=False), profile_with(), Target())
    assert any("flow stats" in c for c in checks)


def test_disabled_streams_are_not_inspected():
    profile = Profile(name="p", streams=[
        Stream(enabled=False, packet=Packet(vlan=7)),
        Stream(enabled=True, packet=Packet(vlan=None)),
    ])
    checks = zero.worth_checking(result(), profile, Target())
    assert not any("[7]" in c for c in checks)


def test_explain_puts_facts_before_suspicions():
    lines = zero.explain(result(), profile_with(vlan=100), Target())
    order = [i for i, line in enumerate(lines) if line.startswith("· ")]
    heading = next(i for i, line in enumerate(lines) if line.startswith("проверить"))
    assert max(order) < heading


def test_is_zero_needs_somebody_to_have_been_counting():
    assert zero.is_zero(result())
    assert not zero.is_zero(result(rx_source="none"))
    assert not zero.is_zero(result(tx_pkts=0))


def test_a_sniffer_count_is_not_called_hardware():
    """«marker» - это сниффер по метке в теле кадра. Назвать его аппаратным
    значит приписать счёту точность, которой у него нет."""
    from traphy.runner.result import RunResult

    said = " ".join(zero.established(
        RunResult(engine="scapy", tx_pkts=1000, rx_pkts=0,
                  rx_source="marker", reliable=True, tx_iface="vlan.12")))
    assert "аппаратно" not in said
    assert "сниффером" in said
    hw = " ".join(zero.established(
        RunResult(engine="trex", tx_pkts=1000, rx_pkts=0,
                  rx_source="flow_stats", reliable=True, tx_iface="0")))
    assert "аппаратными счётчиками" in hw


def test_a_vlan_subinterface_tags_frames_the_profile_never_tagged():
    """Профиль без тега + отправка с vlan.12 = кадры уходят тегированными.
    Совет искать нетегированный трафик уводит в сторону."""
    assert zero.iface_tag("vlan.12") == 12
    assert zero.iface_tag("ens19.220") == 220
    assert zero.iface_tag("vlan11") == 11
    assert zero.iface_tag("ens19") is None
    assert zero.iface_tag("eth0") is None
    assert zero.iface_tag("vlan.9999") is None


def test_the_dead_link_is_suggested_before_anything_subtle():
    """Найдено на стенде: ближний порт честно посчитал 1000 входящих, а
    дальний был down - выйти кадрам было некуда."""
    from traphy.presets import build
    from traphy.runner.result import RunResult
    from traphy.target import Target

    result = RunResult(engine="scapy", tx_pkts=1000, rx_pkts=0,
                       rx_source="marker", reliable=True,
                       tx_iface="vlan.12", rx_iface="vlan.11")
    checks = zero.worth_checking(result, build("l3_ip"),
                                 Target(name="t", engine="scapy",
                                        tx_iface="vlan.12",
                                        rx_iface="vlan.11"))
    assert "линк" in checks[0]
    said = " ".join(checks)
    assert "тег 12" in said
    assert "без тега" not in said


def test_a_dry_run_is_not_explained_as_a_failure():
    """Не отправить ни кадра - смысл холостого прогона, а не находка."""
    from traphy.presets import build
    from traphy.runner.result import RunResult
    from traphy.target import Target

    result = RunResult(engine="scapy", dry_run=True, tx_pkts=0, rx_pkts=0,
                       rx_source="none", tx_iface="vlan.12",
                       rx_iface="vlan.11")
    target = Target(name="t", engine="scapy", tx_iface="vlan.12",
                    rx_iface="vlan.11")
    assert zero.explain(result, build("l3_ip"), target) == []
