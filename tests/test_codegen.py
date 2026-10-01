"""The generated script: what it contains and what it refuses to hide."""

from __future__ import annotations

from traphy import presets
from traphy.codegen import EXPAND_CAP, RANDOM_POOL, frame_count, generate, script_name
from traphy.models import (
    FieldTarget,
    L4Proto,
    Packet,
    Profile,
    Stream,
    TxMode,
    VMField,
    VMOp,
)


def test_every_preset_generates_valid_python():
    for key in presets.PRESETS:
        profile = presets.build(key)
        assert profile.validate() == []
        compile(generate(profile), f"{key}.py", "exec")


def test_disabled_streams_are_named_but_not_emitted():
    profile = Profile(streams=[Stream(name="on"), Stream(name="off", enabled=False)])
    text = generate(profile)
    assert "Выключенные потоки не вошли: off" in text
    assert "'name': 'on'" in text
    assert "'name': 'off'" not in text


def test_l3_frames_carry_an_explicit_protocol():
    """Left alone Scapy stamps proto 0, which reads as malformed in a capture."""
    text = generate(Profile(streams=[Stream(packet=Packet(layer="l3"))]))
    assert "proto=61" in text
    l4 = generate(Profile(streams=[Stream(packet=Packet(layer="l4"))]))
    assert "proto=61" not in l4


def test_vlan_layer_is_inserted_between_ether_and_ip():
    text = generate(Profile(streams=[Stream(packet=Packet(layer="l4", vlan=100))]))
    ether = text.index("Ether(")
    dot1q = text.index("Dot1Q(vlan=100")
    ip = text.index("IP(src=")
    assert ether < dot1q < ip


def test_tcp_and_udp_pick_the_right_layer():
    tcp = generate(Profile(streams=[Stream(packet=Packet(l4_proto=L4Proto.TCP))]))
    assert "TCP(sport=" in tcp and "UDP(sport=" not in tcp


def test_increment_ranges_become_loops_and_random_ranges_become_pools():
    walk = Stream(vm_fields=[VMField(target=FieldTarget.IP_DST, op=VMOp.INC,
                                     min_value="48.0.0.1", max_value="48.0.0.9")])
    text = generate(Profile(streams=[walk]))
    assert "for v_ip_dst in ip_range(" in text

    roll = Stream(vm_fields=[VMField(target=FieldTarget.IP_SRC, op=VMOp.RANDOM,
                                     min_value="16.0.0.1", max_value="16.0.9.9")])
    text = generate(Profile(streams=[roll]))
    assert "pool_ip_src = rand_ips(" in text


def test_descending_port_range_walks_downwards():
    stream = Stream(vm_fields=[VMField(target=FieldTarget.DPORT, op=VMOp.DEC,
                                       min_value="10", max_value="20")])
    assert "down=True" in generate(Profile(streams=[stream]))


def test_frame_count_matches_what_the_ranges_produce():
    assert frame_count(presets.build("l3_ip")) == 1
    assert frame_count(presets.build("ip_sweep")) == 254
    assert frame_count(presets.build("imix")) == 3
    # Random draws a fixed pool rather than the whole span.
    assert frame_count(presets.build("table_stress")) == RANDOM_POOL


def test_frame_count_respects_the_expansion_cap():
    """A /16 sweep is capped, and the count says so rather than promising 65k."""
    stream = Stream(vm_fields=[VMField(target=FieldTarget.IP_DST, op=VMOp.INC,
                                       min_value="48.0.0.1", max_value="48.0.255.254")])
    assert frame_count(Profile(streams=[stream])) == EXPAND_CAP


def test_two_ranges_multiply():
    stream = Stream(vm_fields=[
        VMField(target=FieldTarget.IP_DST, min_value="48.0.0.1", max_value="48.0.0.10"),
        VMField(target=FieldTarget.DPORT, min_value="1", max_value="5"),
    ])
    assert frame_count(Profile(streams=[stream])) == 10 * 5


def test_burst_settings_reach_the_stream_table():
    stream = Stream(tx_mode=TxMode.MULTI_BURST, pkts_per_burst=250,
                    number_of_bursts=4, ibg_usec=1500)
    text = generate(Profile(streams=[stream]))
    assert "'mode': 'multi_burst'" in text
    assert "'burst': 250" in text and "'bursts': 4" in text and "'ibg': 1500" in text


def test_the_marker_is_per_run():
    """A fresh tag each run stops a sniffer counting the previous run's tail."""
    profile = presets.build("l3_ip")
    assert "TAG = 'ABC1234'" in generate(profile, tag="ABC1234")


def test_script_name_is_derived_safely():
    assert script_name(Profile(name="l3 ip/sweep")) == "l3_ip_sweep.py"


def _pacer_class(profile_name):
    """Класс Pacer из сгенерированного скрипта - он живёт только там."""
    from traphy import codegen, presets

    namespace: dict = {}
    exec(compile(codegen.generate(presets.build(profile_name)),  # nosec B102
                 "<сгенерировано>", "exec"), namespace)
    return namespace["Pacer"]


def test_a_burst_stream_finishes_when_its_share_of_count_runs_out():
    """Найдено на стенде: burst_probe не завершался никогда.

    Бёрст в 2000 кадров при доле 500 отдаёт всё за один вызов и назначает
    следующий бёрст на будущее. finished() смотрел только на бёрсты, а
    --count вдобавок снимает дедлайн - и цикл крутился вечно.
    """
    pacer = _pacer_class("burst_probe")({"name": "burst", "pps": 500.0,
                                         "mode": "multi_burst", "burst": 2000,
                                         "bursts": 10, "ibg": 50000.0}, 500)
    assert not pacer.finished()
    pacer.sent += pacer.due(0.0)
    assert pacer.sent == 500
    assert pacer.finished(), "бёрстовый поток не увидел свой --count"
    assert pacer.due(100.0) == 0


def test_a_burst_stream_without_a_count_still_finishes_on_its_bursts():
    """Вторая дорога к концу не должна была пострадать от починки первой."""
    pacer = _pacer_class("burst_probe")({"name": "burst", "pps": 1000.0,
                                         "mode": "single_burst", "burst": 10,
                                         "bursts": 1, "ibg": 0.0}, 0)
    pacer.sent += pacer.due(0.0)
    assert pacer.sent == 10
    assert pacer.finished()
