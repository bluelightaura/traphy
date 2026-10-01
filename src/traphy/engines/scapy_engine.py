"""The Scapy engine: a stand-alone Python script, run with root on a NIC.

This is the one that works. It wraps :mod:`traphy.codegen`, which is where the
script itself is built; everything here is the seam - what to run it with, what
to pass it, and what about a host would stop it.

Its honest limits: rate is paced rather than guaranteed, and loss is measured
only when the target has a receive interface. Both are surfaced by the runner
rather than hidden here, but they are the reason the TRex engine exists as a
plan at all.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from traphy import codegen
from traphy.models import Profile
from traphy.probe import HostInfo
from traphy.runspec import RunSpec
from traphy.target import Target


class ScapyEngine:
    key = "scapy"
    title = "Scapy"
    hint = "любой Linux с NIC и root"
    layers = "L2-L4"
    ready = True
    status = ""
    file_suffix = ".py"
    uses_ifaces = True

    def generate(self, profile: Profile, tag: str) -> str:
        return codegen.generate(profile, tag=tag)

    def interpreter(self, target: Target) -> str:
        return target.python

    def args(self, target: Target, spec: RunSpec, archive: Path | None) -> list[str]:
        args = ["--iface", target.tx_iface, "--duration", f"{spec.duration:g}"]
        if target.rx_iface:
            args += ["--rx-iface", target.rx_iface]
        if spec.count:
            args += ["--count", str(spec.count)]
        if spec.pps:
            args += ["--pps", f"{spec.pps:g}"]
        if spec.dry_run:
            args.append("--dry-run")
        elif spec.capture:
            # Deliberately not a path. The script runs on the sending machine,
            # and the archive is a directory on this one - handing it that path
            # wrote the dump into a directory the target does not have. The
            # frames come home inside the event stream instead, the same way
            # TRex returns them, and land in the archive here.
            args += ["--capture", "--capture-limit", str(spec.capture_limit)]
        return args

    def needs_root(self, spec: RunSpec) -> bool:
        """Only a real send needs the raw socket; building frames does not.

        Asking for sudo on a dry run would be asking for a privilege the work
        does not use, which is both rude and a habit worth not forming.
        """
        return not spec.dry_run

    def blockers(self, host: HostInfo) -> list[str]:
        out: list[str] = []
        if not host.has_scapy:
            out.append("на цели нет Scapy - поставь: pip install scapy")
        if not (host.is_root or host.can_sudo):
            out.append("нет root и sudo без пароля - сырой сокет не открыть")
        if not any(i.is_up for i in host.usable_ifaces()):
            out.append("ни один подходящий интерфейс не поднят")
        return out

    def port_labels(self, target: Target) -> tuple[str, str]:
        return target.tx_iface, target.rx_iface

    def target_problems(self, target: Target) -> list[str]:
        """An interface name is this engine's whole idea of a port.

        The receive check only fires on a remote target: sending and sniffing
        on one interface is how a local loopback test is legitimately done,
        whereas on a box across the room it means the sniffer is counting our
        own departures and calling them arrivals.
        """
        out: list[str] = []
        if not target.tx_iface.strip():
            out.append("не выбран интерфейс отправки")
        if target.rx_iface and target.rx_iface == target.tx_iface \
                and not target.is_local:
            out.append("приём и отправка на одном интерфейсе - "
                       "потери мерить нечем")
        return out

    def frame_count(self, profile: Profile) -> int:
        return codegen.frame_count(profile)

    def describe_result(self, event: dict[str, Any]) -> str:
        return ""
