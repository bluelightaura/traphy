"""Asking the generator about itself: its ports, who holds them, is it ready.

Distinct from :mod:`traphy.probe`, and the distinction is the whole reason this
exists. The probe asks a *host* what it has - a kernel, an interpreter, Scapy,
NICs. That question makes sense for Scapy and is nearly meaningless for the
other two: a TRex port is not in ``/sys/class/net`` because DPDK took it, and an
Ixia port is not on this machine at all. What an operator needs to know before
a run is about the *generator*: which ports exist, what they are plugged into,
whether one is already held by somebody else, and whether the thing is up.

Every engine answers, and an engine that cannot answer says so rather than
returning an empty list. That difference matters: "портов нет" and "я не умею
спрашивать" lead to opposite next moves, and a screen that shows an empty table
for both sends the operator to the rack for nothing.

A held port is the case this is really built around. Chassis ports and TRex
ports are shared, and taking one out from under a colleague mid-measurement is
a real thing this tool is able to do. It is never a thing it does by accident:
the holder comes back named, and taking the port is a separate, deliberate act.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from traphy.target import Target


@dataclass
class Port:
    """One port of the generator, in that generator's own vocabulary."""

    label: str = ""           # "0", "1/2", "eth1" - what the operator types
    description: str = ""     # card model, driver, whatever identifies it
    link: str = ""            # "up" / "down" / "" when not knowable
    speed_mbit: int = 0       # 0 = unknown rather than zero
    held_by: str = ""         # empty = free; otherwise who has it
    note: str = ""            # anything else worth one line

    @property
    def free(self) -> bool:
        return not self.held_by

    def describe(self) -> str:
        bits = [self.label]
        if self.description:
            bits.append(self.description)
        if self.speed_mbit:
            bits.append(_speed(self.speed_mbit))
        if self.link:
            bits.append(f"линк {self.link}")
        if self.held_by:
            bits.append(f"занят: {self.held_by}")
        return " · ".join(bits)


def _speed(mbit: int) -> str:
    """25000 as "25G", 1000 as "1G", anything odd as megabits."""
    if mbit >= 1000 and mbit % 1000 == 0:
        return f"{mbit // 1000}G"
    return f"{mbit}M"


@dataclass
class Readiness:
    """Whether the generator can be used right now, and what is in the way."""

    known: bool = False           # False = this engine cannot answer at all
    up: bool = False
    version: str = ""
    ports: list[Port] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def usable(self) -> bool:
        return self.known and self.up and not self.problems

    def summary(self) -> str:
        if not self.known:
            return self.note or "этот движок не умеет рассказывать о генераторе"
        if not self.up:
            if self.problems:
                return self.problems[0]
            # Not asked and not answering are different states, and only one of
            # them is a reason to walk to the rack.
            return self.note or "генератор не отвечает"
        free = sum(1 for p in self.ports if p.free)
        head = f"{self.version or 'генератор'} на связи"
        return f"{head} · портов {len(self.ports)}, свободно {free}"


def cannot_ask(why: str) -> Readiness:
    """The honest answer for an engine with nothing to query.

    Scapy is the case: there is no generator behind it, only a host, and the
    host is what :mod:`traphy.probe` is for. Saying that outright is better
    than an empty table that reads like a broken chassis.
    """
    return Readiness(known=False, note=why)


class Inventory(Protocol):
    """Optional half of the engine seam: what an engine knows about its ports.

    Optional on purpose. An engine that does not implement it is not broken -
    :func:`ask` answers for it - which is what keeps a new engine to one file
    instead of one file plus a forced implementation of something its
    generator has no concept of.
    """

    def readiness(self, target: Target) -> Readiness:
        """Ports, versions and whatever would stop a run, asked of the generator."""


def ask(engine: object, target: Target) -> Readiness:
    """Readiness from an engine that has it, a plain answer from one that has not."""
    method = getattr(engine, "readiness", None)
    if method is None:
        title = getattr(engine, "title", "движок")
        return cannot_ask(f"{title} не спрашивает генератор о портах - "
                          f"здесь смотри probe по хосту")
    return method(target)


def not_asked(ports: list[Port], why: str) -> Readiness:
    """What is known from the saved target, with the generator not yet queried.

    The honest middle state, and it needs its own shape because the two
    obvious ones are both lies: ``up=True`` would claim an answer nobody asked
    for, and :func:`cannot_ask` would claim the engine has no idea when it has
    the operator's own configuration in hand. So the ports come back labelled
    as configuration rather than as fact, and ``up`` stays False until
    something actually talks to the generator.
    """
    return Readiness(known=True, up=False, ports=ports, note=why)
