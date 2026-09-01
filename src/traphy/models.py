"""The traffic model: what a frame looks like, how fast it goes, what walks.

Everything the tool does hangs off these dataclasses. The menu edits them, the
code generator turns them into a stand-alone Scapy script, and the runner ships
that script to a host and reads its counters back. The model itself is plain
stdlib on purpose: it imports without Scapy installed, so the generate-and-save
path works on a laptop that has no NIC to speak of.

A ``Profile`` is a named set of ``Stream``s. A stream is one ``Packet`` plus a
rate and a TX mode, optionally with ``VMField``s - the ranges that make a single
stream walk source IPs or destination ports instead of repeating one frame.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# Highest L2 frame we will build. Beyond this the NIC has to be in jumbo mode
# and most of them are not, so the model rejects it rather than letting the
# script fail on the wire where the failure is far less legible.
MAX_FRAME = 9000

# Smallest legal Ethernet frame excluding the FCS the NIC appends.
MIN_FRAME = 60


class L4Proto(StrEnum):
    UDP = "UDP"
    TCP = "TCP"


class RateType(StrEnum):
    """How ``Stream.rate_value`` is to be read."""

    PPS = "pps"              # packets per second
    BPS_L2 = "bps_L2"        # bits per second counted at L2
    PERCENT = "percentage"   # % of the target link's rate


class TxMode(StrEnum):
    CONTINUOUS = "continuous"
    SINGLE_BURST = "single_burst"
    MULTI_BURST = "multi_burst"


class VMOp(StrEnum):
    """How a range walks: step up, step down, or pick at random each send."""

    INC = "inc"
    DEC = "dec"
    RANDOM = "random"


class FieldTarget(StrEnum):
    """Which packet field a range drives."""

    IP_SRC = "ip_src"
    IP_DST = "ip_dst"
    SPORT = "sport"
    DPORT = "dport"

    @property
    def is_ip(self) -> bool:
        return self in (FieldTarget.IP_SRC, FieldTarget.IP_DST)

    @property
    def label(self) -> str:
        return {
            FieldTarget.IP_SRC: "IP источника",
            FieldTarget.IP_DST: "IP назначения",
            FieldTarget.SPORT: "порт источника",
            FieldTarget.DPORT: "порт назначения",
        }[self]


@dataclass
class VMField:
    """One field that walks a range instead of holding still.

    Named after TRex's "field engine" variables, which is where the idea comes
    from, but the semantics here are Scapy's: ``inc``/``dec`` are expanded into
    concrete packets at generation time (bounded - see ``codegen.EXPAND_CAP``),
    while ``random`` stays volatile and resolves per send.
    """

    target: FieldTarget = FieldTarget.IP_SRC
    op: VMOp = VMOp.INC
    min_value: str = "16.0.0.1"
    max_value: str = "16.0.0.255"
    step: int = 1

    def describe(self) -> str:
        arrow = {VMOp.INC: "→", VMOp.DEC: "←", VMOp.RANDOM: "?"}[self.op]
        span = f"{self.min_value}..{self.max_value}"
        tail = f" шаг {self.step}" if self.op is not VMOp.RANDOM and self.step != 1 else ""
        return f"{self.target.label} {arrow} {span}{tail}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.value,
            "op": self.op.value,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "step": self.step,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VMField:
        return cls(
            target=FieldTarget(d["target"]),
            op=VMOp(d["op"]),
            min_value=str(d["min_value"]),
            max_value=str(d["max_value"]),
            step=max(1, int(d.get("step", 1))),
        )


@dataclass
class Packet:
    """One frame. ``layer`` decides how far up the stack it is built.

    ``l2`` is Ether only, ``l3`` adds IPv4, ``l4`` adds UDP or TCP. A VLAN tag
    is inserted between Ether and whatever follows when ``vlan`` is set, which
    is the usual way to make a switch under test do trunk work.
    """

    layer: str = "l4"                     # l2 | l3 | l4
    eth_src: str = "00:00:00:00:00:01"
    eth_dst: str = "00:00:00:00:00:02"
    vlan: int | None = None               # None = untagged
    vlan_pcp: int = 0
    ip_src: str = "16.0.0.1"
    ip_dst: str = "48.0.0.1"
    ttl: int = 64
    l4_proto: L4Proto = L4Proto.UDP
    sport: int = 1025
    dport: int = 12
    frame_size: int = 64                  # total L2 bytes, FCS excluded

    @property
    def has_ip(self) -> bool:
        return self.layer in ("l3", "l4")

    @property
    def has_l4(self) -> bool:
        return self.layer == "l4"

    @property
    def has_vlan(self) -> bool:
        return self.vlan is not None

    def describe(self) -> str:
        """A one-line "what this frame is" for the menu's stream table."""
        parts = ["Eth"]
        if self.has_vlan:
            parts.append(f"VLAN{self.vlan}")
        if self.has_ip:
            parts.append("IP")
        if self.has_l4:
            parts.append(self.l4_proto.value)
        return f"{'/'.join(parts)} {self.frame_size}B"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["l4_proto"] = self.l4_proto.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Packet:
        vlan = d.get("vlan")
        return cls(
            layer=d.get("layer", "l4"),
            eth_src=d.get("eth_src", "00:00:00:00:00:01"),
            eth_dst=d.get("eth_dst", "00:00:00:00:00:02"),
            vlan=int(vlan) if vlan not in (None, "") else None,
            vlan_pcp=int(d.get("vlan_pcp", 0)),
            ip_src=d.get("ip_src", "16.0.0.1"),
            ip_dst=d.get("ip_dst", "48.0.0.1"),
            ttl=int(d.get("ttl", 64)),
            l4_proto=L4Proto(d.get("l4_proto", "UDP")),
            sport=int(d.get("sport", 1025)),
            dport=int(d.get("dport", 12)),
            frame_size=int(d.get("frame_size", 64)),
        )


@dataclass
class Stream:
    """A packet plus how it is sent: rate, TX mode, and any walking fields."""

    name: str = "s1"
    enabled: bool = True
    packet: Packet = field(default_factory=Packet)

    rate_type: RateType = RateType.PPS
    rate_value: float = 1000.0

    tx_mode: TxMode = TxMode.CONTINUOUS
    pkts_per_burst: int = 1000
    number_of_bursts: int = 5             # multi-burst only
    ibg_usec: float = 100.0               # inter-burst gap, multi-burst only

    vm_fields: list[VMField] = field(default_factory=list)

    def pps(self, link_mbit: int = 1000) -> float:
        """Best-effort packets/sec whatever unit the rate was entered in.

        ``link_mbit`` only matters for a percentage rate; everything else
        ignores it. The number is an intent, not a promise - see the note in
        :mod:`traphy.codegen` about what Scapy can actually hold.
        """
        size = max(self.packet.frame_size, 1)
        if self.rate_type is RateType.PPS:
            return self.rate_value
        if self.rate_type is RateType.BPS_L2:
            return self.rate_value / (size * 8)
        if self.rate_type is RateType.PERCENT:
            # L1 accounting: the wire also carries a 7B preamble, a 1B SFD, a
            # 4B FCS and a 12B inter-frame gap that the frame size leaves out.
            return (self.rate_value / 100.0) * (link_mbit * 1e6) / ((size + 24) * 8)
        return self.rate_value

    def rate_label(self) -> str:
        unit = {RateType.PPS: "pps", RateType.BPS_L2: "bps",
                RateType.PERCENT: "%"}[self.rate_type]
        value = f"{self.rate_value:g}"
        return f"{value} {unit}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "packet": self.packet.to_dict(),
            "rate_type": self.rate_type.value,
            "rate_value": self.rate_value,
            "tx_mode": self.tx_mode.value,
            "pkts_per_burst": self.pkts_per_burst,
            "number_of_bursts": self.number_of_bursts,
            "ibg_usec": self.ibg_usec,
            "vm_fields": [v.to_dict() for v in self.vm_fields],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Stream:
        return cls(
            name=d.get("name", "s1"),
            enabled=bool(d.get("enabled", True)),
            packet=Packet.from_dict(d.get("packet", {})),
            rate_type=RateType(d.get("rate_type", "pps")),
            rate_value=float(d.get("rate_value", 1000.0)),
            tx_mode=TxMode(d.get("tx_mode", "continuous")),
            pkts_per_burst=int(d.get("pkts_per_burst", 1000)),
            number_of_bursts=int(d.get("number_of_bursts", 5)),
            ibg_usec=float(d.get("ibg_usec", 100.0)),
            vm_fields=[VMField.from_dict(v) for v in d.get("vm_fields", [])],
        )


@dataclass
class Profile:
    """A named set of streams - the unit the tool generates and runs."""

    name: str = "profile1"
    description: str = ""
    streams: list[Stream] = field(default_factory=lambda: [Stream()])

    @property
    def enabled_streams(self) -> list[Stream]:
        return [s for s in self.streams if s.enabled]

    def total_pps(self, link_mbit: int = 1000) -> float:
        return sum(s.pps(link_mbit) for s in self.enabled_streams)

    # ---- serialization ---------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "streams": [s.to_dict() for s in self.streams],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Profile:
        return cls(
            name=d.get("name", "profile1"),
            description=d.get("description", ""),
            streams=[Stream.from_dict(s) for s in d.get("streams", [])] or [Stream()],
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> Profile:
        return cls.from_dict(json.loads(text))

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json() + "\n", encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> Profile:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    # ---- validation ------------------------------------------------------- #
    def validate(self) -> list[str]:
        """Every problem with this profile, worded for a person. Empty is OK.

        Called before generating and again before running, because a profile
        loaded from disk was not necessarily written by this version.
        """
        problems: list[str] = []
        if not self.name.strip():
            problems.append("у профиля пустое имя")
        if not self.streams:
            problems.append("в профиле нет потоков")
        elif not self.enabled_streams:
            problems.append("все потоки выключены — слать нечего")

        seen: set[str] = set()
        for i, s in enumerate(self.streams):
            tag = f"поток[{i}] «{s.name}»"
            if not s.name.strip():
                problems.append(f"{tag}: пустое имя")
            if s.name in seen:
                problems.append(f"{tag}: имя повторяется")
            seen.add(s.name)
            problems.extend(_stream_problems(s, tag))
        return problems


def _stream_problems(s: Stream, tag: str) -> list[str]:
    """The per-stream half of :meth:`Profile.validate`, kept separate so the
    rules stay readable and testable one at a time."""
    out: list[str] = []
    if s.rate_value <= 0:
        out.append(f"{tag}: скорость должна быть больше нуля")
    if s.rate_type is RateType.PERCENT and s.rate_value > 100:
        out.append(f"{tag}: процент линии больше 100")
    if s.packet.frame_size < MIN_FRAME:
        out.append(f"{tag}: кадр меньше {MIN_FRAME} B — короче минимального Ethernet")
    if s.packet.frame_size > MAX_FRAME:
        out.append(f"{tag}: кадр больше {MAX_FRAME} B — за пределом jumbo")
    if s.packet.vlan is not None and not 0 <= s.packet.vlan <= 4095:
        out.append(f"{tag}: VLAN вне диапазона 0..4095")
    if s.tx_mode is not TxMode.CONTINUOUS and s.pkts_per_burst <= 0:
        out.append(f"{tag}: в очереди должно быть хотя бы один пакет")
    if s.tx_mode is TxMode.MULTI_BURST and s.number_of_bursts <= 0:
        out.append(f"{tag}: очередей должно быть хотя бы одна")
    out.extend(_range_problems(s, tag))
    return out


def _range_problems(s: Stream, tag: str) -> list[str]:
    """Check the walking fields against the layers the packet actually has.

    A destination-port range on an L2 frame is not a small mistake to find at
    runtime: the script would send a fixed frame and the operator would read
    the result as "the switch did not care about ports".
    """
    out: list[str] = []
    for vf in s.vm_fields:
        if vf.target.is_ip and not s.packet.has_ip:
            out.append(f"{tag}: диапазон по {vf.target.label}, но в кадре нет IP")
            continue
        if not vf.target.is_ip and not s.packet.has_l4:
            out.append(f"{tag}: диапазон по {vf.target.label}, но в кадре нет L4")
            continue
        lo, hi, err = _range_bounds(vf)
        if err:
            out.append(f"{tag}: {err}")
        elif lo > hi:
            out.append(f"{tag}: диапазон {vf.target.label} задом наперёд "
                       f"({vf.min_value} > {vf.max_value})")
    return out


def _range_bounds(vf: VMField) -> tuple[int, int, str]:
    """Parse a range's ends into ints. Returns (lo, hi, error-or-empty)."""
    import ipaddress

    try:
        if vf.target.is_ip:
            lo = int(ipaddress.IPv4Address(vf.min_value))
            hi = int(ipaddress.IPv4Address(vf.max_value))
        else:
            lo, hi = int(vf.min_value), int(vf.max_value)
            if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
                return 0, 0, f"порт в диапазоне {vf.target.label} вне 0..65535"
    except (ValueError, ipaddress.AddressValueError):
        return 0, 0, f"диапазон {vf.target.label}: не разобрать концы"
    return lo, hi, ""


def range_size(vf: VMField) -> int:
    """How many distinct values a walking field covers (0 when unparseable).

    The menu shows this so an operator can see that a /16 sweep means 65k
    frames before the generator quietly caps it.
    """
    lo, hi, err = _range_bounds(vf)
    if err or lo > hi:
        return 0
    return (hi - lo) // max(1, vf.step) + 1
