"""Engines: the different ways traffic can actually be produced.

TRaphy's model of traffic is one thing; what puts it on the wire is another.
The Scapy engine writes a Python script and runs it with root on a NIC. TRex
drives a DPDK generator that can hold line rate. JMeter does not send frames at
all - it opens connections and issues requests, which is a different shape of
load for a different question.

They share everything else: the target, the transport that ships a file and
runs it, the probe that says what the host has, the archive that records what
happened. So an engine is a small object - it declares what it needs from the
host, turns a profile into an artefact, and says how to invoke it - and the
rest of the tool does not branch on which one is selected.

Scapy, TRex and Ixia are implemented. JMeter is declared here rather than left
as an idea, so the seam it will fit into is a real one: selecting it tells the
operator exactly what is missing instead of failing somewhere deeper.
"""

from __future__ import annotations

from traphy.engines.base import Engine, EngineNotReady
from traphy.engines.ixia import IxiaEngine
from traphy.engines.jmeter import JMeterEngine
from traphy.engines.scapy_engine import ScapyEngine
from traphy.engines.trex import TrexEngine

# In the order the menu offers them: what works, then what is coming.
REGISTRY: dict[str, Engine] = {
    engine.key: engine
    for engine in (ScapyEngine(), TrexEngine(), IxiaEngine(), JMeterEngine())
}

DEFAULT = ScapyEngine.key


def get(key: str) -> Engine:
    """The engine for a key, falling back to Scapy for an unknown one.

    A target file written by a later version naming an engine this build does
    not have must not stop the menu from opening; it degrades to the engine
    that is always present and the target form shows what is selected.
    """
    return REGISTRY.get(key, REGISTRY[DEFAULT])


def options() -> list[tuple[str, str, str]]:
    """(key, title, hint) for the engine picker, ready-to-use engines first."""
    out = []
    for engine in REGISTRY.values():
        hint = engine.hint if engine.ready else f"{engine.hint} - {engine.status}"
        out.append((engine.key, engine.title, hint))
    return out


__all__ = ["DEFAULT", "REGISTRY", "Engine", "EngineNotReady", "get", "options"]
