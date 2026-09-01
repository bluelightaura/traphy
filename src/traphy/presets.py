"""Ready-made profiles for the things people actually point a generator at.

Each entry is a function returning a fresh :class:`~traphy.models.Profile`, so
picking a preset in the menu never hands back a shared object the next edit
would mutate underneath. They are starting points: the builder screen edits
whatever a preset produced, and nothing here is more authoritative than what
the operator types afterwards.

The layer ladder (L2 -> L3 -> L4) and the sweeps map onto what a switch or
router is being asked to do: forward frames, route packets, track sessions, and
keep a table under pressure.
"""

from __future__ import annotations

from collections.abc import Callable

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
)


def l2_ethernet(rate_pps: float = 1000) -> Profile:
    """Bare Ethernet frames - the switching and MAC-learning path only."""
    s = Stream(
        name="l2_eth",
        packet=Packet(layer="l2", frame_size=64),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
    )
    return Profile(name="l2_ethernet",
                   description="Чистый L2 Ethernet — коммутация",
                   streams=[s])


def l2_vlan(vlan: int = 100, rate_pps: float = 1000) -> Profile:
    """Tagged frames on one VLAN - trunk handling and per-VLAN forwarding."""
    s = Stream(
        name="l2_vlan",
        packet=Packet(layer="l2", vlan=vlan, frame_size=68),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
    )
    return Profile(name="l2_vlan",
                   description=f"L2 с тегом VLAN {vlan} — транк",
                   streams=[s])


def l3_ip(rate_pps: float = 1000) -> Profile:
    """IPv4 over UDP - the plain routing and forwarding case."""
    s = Stream(
        name="l3_ip",
        packet=Packet(layer="l3", ip_src="16.0.0.1", ip_dst="48.0.0.1",
                      frame_size=128),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
    )
    return Profile(name="l3_ip", description="L3 IPv4 — маршрутизация",
                   streams=[s])


def l4_udp(rate_pps: float = 1000) -> Profile:
    """UDP with fixed ports - the baseline every ACL test starts from."""
    s = Stream(
        name="l4_udp",
        packet=Packet(l4_proto=L4Proto.UDP, sport=1025, dport=53, frame_size=128),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
    )
    return Profile(name="l4_udp", description="L4 UDP — фиксированные порты",
                   streams=[s])


def l4_tcp(rate_pps: float = 1000) -> Profile:
    """TCP frames - session tables, stateful firewalls, NAT."""
    s = Stream(
        name="l4_tcp",
        packet=Packet(l4_proto=L4Proto.TCP, sport=1025, dport=80, frame_size=64),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
    )
    return Profile(name="l4_tcp", description="L4 TCP — таблицы сессий",
                   streams=[s])


def imix() -> Profile:
    """The classic 64/590/1514 mix at 7:4:1, which is what real traffic looks
    like far more than any single frame size does."""
    weights = ((64, 7), (590, 4), (1514, 1))
    streams = [
        Stream(name=f"imix_{size}",
               packet=Packet(frame_size=size),
               rate_type=RateType.PPS,
               rate_value=share * 1000,
               tx_mode=TxMode.CONTINUOUS)
        for size, share in weights
    ]
    return Profile(name="imix", description="IMIX 64/590/1514 в 7:4:1",
                   streams=streams)


def ip_sweep(hosts: int = 254, rate_pps: float = 5000) -> Profile:
    """Walk the destination IP across a /24 - one route lookup per frame."""
    last = min(1 + max(1, hosts), 254)
    s = Stream(
        name="ip_sweep",
        packet=Packet(layer="l3", ip_src="16.0.0.1", ip_dst="48.0.0.1",
                      frame_size=128),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
        vm_fields=[VMField(target=FieldTarget.IP_DST, op=VMOp.INC,
                           min_value="48.0.0.1", max_value=f"48.0.0.{last}")],
    )
    return Profile(name="ip_sweep", description="Перебор IP назначения по /24",
                   streams=[s])


def port_sweep(rate_pps: float = 5000) -> Profile:
    """Walk the destination port - session tables, NAT pools, ACL breadth."""
    s = Stream(
        name="port_sweep",
        packet=Packet(l4_proto=L4Proto.UDP, sport=1025, dport=1, frame_size=64),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
        vm_fields=[VMField(target=FieldTarget.DPORT, op=VMOp.INC,
                           min_value="1", max_value="1024")],
    )
    return Profile(name="port_sweep", description="Перебор порта назначения",
                   streams=[s])


def table_stress(rate_pps: float = 10000) -> Profile:
    """A wide random source-IP spread at high rate - pressure on whatever
    table the device keeps per flow. Random rather than incrementing so the
    device cannot get help from locality."""
    s = Stream(
        name="table_stress",
        packet=Packet(frame_size=64),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
        vm_fields=[VMField(target=FieldTarget.IP_SRC, op=VMOp.RANDOM,
                           min_value="16.0.0.1", max_value="16.0.255.254")],
    )
    return Profile(name="table_stress",
                   description="Случайные источники на высоком pps — таблицы",
                   streams=[s])


def burst_probe(rate_pps: float = 20000) -> Profile:
    """Short bursts with gaps - buffer depth and microburst tolerance, which a
    steady stream never shows you."""
    s = Stream(
        name="burst",
        packet=Packet(frame_size=512),
        rate_type=RateType.PPS,
        rate_value=rate_pps,
        tx_mode=TxMode.MULTI_BURST,
        pkts_per_burst=2000,
        number_of_bursts=10,
        ibg_usec=50000.0,
    )
    return Profile(name="burst_probe",
                   description="Очереди с паузами — буферы и микробёрсты",
                   streams=[s])


# What the menu lists, in the order it lists them: the layer ladder first, then
# the mixes, then the two that deliberately hurt.
PRESETS: dict[str, tuple[str, str, Callable[[], Profile]]] = {
    "l2_ethernet": ("L2 Ethernet", "коммутация, чистые кадры", l2_ethernet),
    "l2_vlan": ("L2 + VLAN", "транк, тегированные кадры", l2_vlan),
    "l3_ip": ("L3 IPv4", "маршрутизация", l3_ip),
    "l4_udp": ("L4 UDP", "фиксированные порты", l4_udp),
    "l4_tcp": ("L4 TCP", "таблицы сессий", l4_tcp),
    "imix": ("IMIX", "64/590/1514 — как живой трафик", imix),
    "ip_sweep": ("Перебор IP", "/24 по назначению — FIB", ip_sweep),
    "port_sweep": ("Перебор портов", "сессии, NAT, ACL", port_sweep),
    "table_stress": ("Стресс таблиц", "случайные источники, высокий pps", table_stress),
    "burst_probe": ("Очередями", "буферы и микробёрсты", burst_probe),
}


def build(key: str) -> Profile:
    """A fresh profile for a preset key. Raises KeyError on an unknown key."""
    return PRESETS[key][2]()


def keys() -> list[str]:
    return list(PRESETS)
