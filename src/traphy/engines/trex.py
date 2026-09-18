"""The TRex engine: a DPDK generator driven over its own control port.

Two things make this worth the extra moving parts. Scapy paces through the
kernel and gives out somewhere in the tens of thousands of frames a second;
above that a run describes the generator rather than the device. And TRex
counts loss in hardware - one counter per stream group on the receiving port -
instead of matching a marker in a payload with a sniffer, so its number goes
into a report without a caveat attached.

What it costs, and none of it is hidden from the operator:

* **The release has to be on the target.** Frames are built by the Scapy that
  ships inside it, because the field engine writes at offsets computed against
  that Scapy. :mod:`traphy.codegen_stl` explains why that is not pedantry.
* **The daemon has to be up.** TRex owns the NICs through DPDK long before we
  connect; a run is a conversation with a server, not a program we start.
* **Ports, not interfaces.** The NICs are gone from ``/sys/class/net`` - they
  belong to DPDK now - and are addressed by index. That is why
  :attr:`uses_ifaces` is False and the target form asks for port numbers here.
* **No root.** The daemon was started with it; the client that drives it is an
  ordinary process, and asking for sudo would be asking for a privilege this
  work does not use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from traphy import codegen_stl
from traphy.models import Profile
from traphy.probe import HostInfo
from traphy.runspec import RunSpec
from traphy.target import Target

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from pathlib import Path

# What each way of counting the receive side is worth, in one line. Every
# result carries one of these; a loss figure whose provenance went unsaid is
# the thing this whole tool is arranged to avoid.
RX_SOURCES = {
    "flow_stats": "приём посчитан flow stats - счётчиками в железе по группе "
                  "потока; это число можно класть в отчёт как есть",
    "mixed": "часть потоков ушла без аппаратного счёта - потери посчитаны "
             "не по всему прогону",
    "port_counter": "приём посчитан счётчиком порта - там лежат не только "
                    "наши кадры",
    "none": "приём не измерялся - порт приёма не задан",
}


class TrexEngine:
    key = "trex"
    title = "TRex"
    hint = "DPDK, линейная скорость, потери по flow stats"
    layers = "L2-L4"
    ready = True
    status = ""
    file_suffix = ".py"
    uses_ifaces = False

    def generate(self, profile: Profile, tag: str) -> str:
        return codegen_stl.generate(profile, tag=tag)

    def interpreter(self, target: Target) -> str:
        """The target's own Python. The release's library is put on its path by
        the script rather than by the environment, so an operator can keep one
        interpreter and switch releases by changing a directory."""
        return target.python

    def args(self, target: Target, spec: RunSpec, archive: Path | None) -> list[str]:
        args = [
            "--trex-dir", target.trex_dir,
            "--server", target.trex_server,
            "--sync-port", str(target.trex_sync_port),
            "--tx-port", str(target.trex_port_tx),
            "--duration", f"{spec.duration:g}",
        ]
        if target.trex_port_rx >= 0:
            args += ["--rx-port", str(target.trex_port_rx)]
        if spec.pps:
            # TRex scales a whole profile with one multiplier, and it takes the
            # target rate directly - so an aggregate override stays aggregate
            # instead of being divided between streams here and rounded twice.
            args += ["--mult", f"{spec.pps:g}pps"]
        if spec.count:
            # Passed on rather than dropped: the script refuses it with the
            # reason and the way to get what was actually wanted.
            args += ["--count", str(spec.count)]
        if spec.dry_run:
            args.append("--dry-run")
        if spec.save_pcap and archive is not None:
            args += ["--pcap", str(archive / "streams.pcap")]
        return args

    def needs_root(self, spec: RunSpec) -> bool:
        return False

    def blockers(self, host: HostInfo) -> list[str]:
        out: list[str] = []
        if not host.has_trex:
            out.append("на цели не видно каталога TRex - обычно /opt/trex")
        elif not host.has_trex_stl:
            out.append(f"в {host.trex_dir} нет automation/trex_control_plane - "
                       f"это не распакованный релиз TRex")
        if not host.trex_daemon:
            out.append("демон TRex не отвечает - подними его на цели: "
                       "cd /opt/trex && ./t-rex-64 -i")
        return out

    def port_labels(self, target: Target) -> tuple[str, str]:
        return (f"порт {target.trex_port_tx}",
                f"порт {target.trex_port_rx}" if target.trex_port_rx >= 0
                else "")

    def target_problems(self, target: Target) -> list[str]:
        out: list[str] = []
        if not target.trex_dir.strip():
            out.append("не задан каталог TRex на цели")
        if not 1 <= target.trex_sync_port <= 65535:
            out.append("порт управления TRex вне 1..65535")
        if target.trex_port_tx < 0:
            out.append("не выбран порт отправки TRex")
        if target.trex_port_rx >= 0 and target.trex_port_rx == target.trex_port_tx:
            out.append("порт приёма совпадает с портом отправки - "
                       "счётчик поймает собственную отправку, а не то, "
                       "что вернулось через коробку")
        return out

    def frame_count(self, profile: Profile) -> int:
        return codegen_stl.frame_count(profile)

    def describe_result(self, event: dict[str, Any]) -> str:
        return RX_SOURCES.get(str(event.get("rx_source", "")), "")

    def warnings(self, profile: Profile) -> list[str]:
        """What this profile gives up on TRex, before it is sent rather than
        after. Not part of the engine protocol - the builder screen asks for it
        by name, because only this engine has anything to say here."""
        return codegen_stl.warnings(profile)
