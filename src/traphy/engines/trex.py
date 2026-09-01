"""The TRex engine — declared, not yet implemented.

Where it fits: Scapy paces through the kernel and gives out somewhere in the
tens of thousands of frames a second. Above that a run tells you about the
generator rather than about the device, which is exactly when a DPDK generator
earns its complexity. TRex also measures loss properly - per-stream flow stats
counted in hardware rather than a sniffer matching a marker - so a result from
it can carry a number the Scapy path has to caveat.

What it will need, and why it is not a small change:

* **A profile in TRex's own shape.** ``STLStream`` with a ``STLProfile``, rates
  as ``STLTXCont``/``STLTXSingleBurst``/``STLTXMultiBurst``, and ranges as
  field-engine variables (``STLVmFlowVar`` plus a write to a packet offset)
  rather than expanded frames. The model in :mod:`traphy.models` already lines
  up with this - the ranges are called VM fields for exactly that reason.
* **TRex's own Scapy.** Field offsets the engine writes into are resolved
  against the patched Scapy that ships inside a TRex release. Frames crafted
  with a stand-alone Scapy can land those writes at the wrong offset, so the
  artefact has to be built on the host, under TRex's interpreter.
* **A daemon, not a command.** TRex runs as a server and is driven over its
  sync port by ``STLClient``; a run means connect, acquire the ports, load the
  profile, start, poll stats, stop. That is a different lifecycle from "run a
  script and read its stdout", so the artefact is a control script that talks
  to a server that must already be up.
* **Ports, not interfaces.** TRex owns its NICs through DPDK and addresses them
  by index. The target's interface names stop being the right identifier, which
  is what :class:`~traphy.target.Nic` exists to bridge.

Selecting it is allowed; every path that would touch the wire refuses with the
reason rather than half-working.
"""

from __future__ import annotations

from traphy.engines.base import Declared
from traphy.probe import HostInfo


class TrexEngine(Declared):
    key = "trex"
    title = "TRex"
    hint = "DPDK, линейная скорость, честные потери"
    layers = "L2–L4"
    ready = False
    status = "ещё не реализован"
    file_suffix = ".py"

    def blockers(self, host: HostInfo) -> list[str]:
        """What a host would need before this engine could be wired in.

        Reported even while the engine is a plan, so setting a target up for it
        is useful work rather than guesswork.
        """
        out = [f"движок TRex {self.status}"]
        if not host.has_trex:
            out.append("на цели не видно каталога TRex (обычно /opt/trex)")
        if not (host.is_root or host.can_sudo):
            out.append("нет root и sudo без пароля — TRex без них не поднять")
        return out
