"""Ask the target what it has: interfaces, root, Scapy, Python.

The setup screen would otherwise make a person type an interface name from
memory and find out it was wrong only when a run failed with "no such device".
Instead, once the connection is up, TRaphy ships a small stdlib-only script
that reads ``/sys/class/net`` and reports back - so ports are *picked from what
is actually there*, with their MAC, link state and negotiated speed alongside.

The probe deliberately imports nothing beyond the standard library and does not
need root. It has to succeed on a box where Scapy is missing, because reporting
that Scapy is missing is one of the things it is for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from traphy.transport import Transport, TransportError

# Interfaces that are never a sensible place to point a traffic generator, so
# the picker hides them unless there is nothing else to show.
BORING_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "cni", "flannel",
                   "tailscale", "wg", "tun", "tap")


@dataclass
class Iface:
    """One interface on the target, as the target itself describes it."""

    name: str
    mac: str = ""
    state: str = ""            # up | down | unknown
    speed_mbit: int = 0        # 0 when the driver will not say
    mtu: int = 0
    driver: str = ""

    @property
    def is_up(self) -> bool:
        return self.state == "up"

    @property
    def interesting(self) -> bool:
        """Whether this is a plausible place to send test traffic from."""
        return not self.name.startswith(BORING_PREFIXES)

    def describe(self) -> str:
        bits = [self.mac or "—"]
        bits.append("up" if self.is_up else self.state or "?")
        if self.speed_mbit:
            bits.append(f"{self.speed_mbit} Мбит/с")
        if self.mtu and self.mtu != 1500:
            bits.append(f"MTU {self.mtu}")
        return " · ".join(bits)


@dataclass
class HostInfo:
    """What we learned about the target in one round trip."""

    ok: bool = False
    error: str = ""
    hostname: str = ""
    kernel: str = ""
    python: str = ""
    has_scapy: bool = False
    scapy_version: str = ""
    is_root: bool = False
    can_sudo: bool = False
    ifaces: list[Iface] = field(default_factory=list)

    # What the other engines would need. Collected on the same round trip so
    # that setting a target up for TRex or JMeter is answerable now, even
    # though neither engine is wired in yet.
    has_java: bool = False
    has_jmeter: bool = False
    has_trex: bool = False

    def usable_ifaces(self) -> list[Iface]:
        """Real NICs first; falls back to everything when there are none.

        A container or a VM may genuinely have nothing but a veth, and refusing
        to list anything there would be worse than listing something odd.
        """
        real = [i for i in self.ifaces if i.interesting]
        return real or list(self.ifaces)

    def blockers(self, engine: str = "scapy") -> list[str]:
        """What would stop a run right now, worded as something to fix.

        Which answers apply depends on the engine - Scapy wants Scapy and a raw
        socket, JMeter wants a JVM - so the judgement lives with the engine and
        this only carries the facts.
        """
        from traphy import engines

        return engines.get(engine).blockers(self)


# The probe itself. Kept as a string because it runs *there*, under whatever
# Python the target has, and must not depend on anything TRaphy installed here.
PROBE_SCRIPT = '''\
import json, os, platform, socket, subprocess, sys

def read(path, default=""):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return default

def ifaces():
    out = []
    base = "/sys/class/net"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for name in names:
        d = base + "/" + name
        speed = read(d + "/speed", "0")
        try:
            speed = max(0, int(speed))
        except ValueError:
            speed = 0
        driver = ""
        try:
            driver = os.path.basename(os.readlink(d + "/device/driver"))
        except OSError:
            pass
        try:
            mtu = int(read(d + "/mtu", "0") or 0)
        except ValueError:
            mtu = 0
        out.append({
            "name": name,
            "mac": read(d + "/address"),
            "state": read(d + "/operstate", "unknown"),
            "speed_mbit": speed,
            "mtu": mtu,
            "driver": driver,
        })
    return out

def scapy():
    try:
        import scapy
        return True, getattr(scapy, "VERSION", "?")
    except Exception:
        return False, ""

def which(name):
    for base in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True
    return False

def trex_dir():
    for path in ("/opt/trex", "/usr/local/trex"):
        if os.path.isdir(path):
            return True
    return False

def can_sudo():
    if os.geteuid() == 0:
        return True
    try:
        return subprocess.call(["sudo", "-n", "true"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0
    except OSError:
        return False

has, version = scapy()
print("@traphy " + json.dumps({
    "ev": "host",
    "ok": True,
    "hostname": socket.gethostname(),
    "kernel": platform.release(),
    "python": platform.python_version(),
    "has_scapy": has,
    "scapy_version": version,
    "is_root": os.geteuid() == 0,
    "can_sudo": can_sudo(),
    "ifaces": ifaces(),
    "has_java": which("java"),
    "has_jmeter": which("jmeter"),
    "has_trex": trex_dir(),
}))
'''


def inspect(transport: Transport, timeout: int = 30) -> HostInfo:
    """Run the probe and turn its answer into a :class:`HostInfo`.

    Never raises for an unhelpful target: a probe that fails comes back as an
    info object with ``ok`` False and a reason, because the setup screen wants
    to show that, not handle an exception.
    """
    from traphy.runner import parse_event

    payload: dict[str, Any] | None = None

    def take(line: str) -> None:
        nonlocal payload
        event = parse_event(line)
        if event and event.get("ev") == "host":
            payload = event

    try:
        completed = transport.run_stream(PROBE_SCRIPT, [], take, timeout=timeout)
    except TransportError as exc:
        return HostInfo(ok=False, error=str(exc))

    if payload is None:
        reason = (completed.stderr or completed.stdout).strip().splitlines()
        tail = reason[-1] if reason else f"код {completed.rc}"
        return HostInfo(ok=False, error=f"цель не ответила на опрос: {tail}")

    return HostInfo(
        ok=True,
        hostname=str(payload.get("hostname", "")),
        kernel=str(payload.get("kernel", "")),
        python=str(payload.get("python", "")),
        has_scapy=bool(payload.get("has_scapy")),
        scapy_version=str(payload.get("scapy_version", "")),
        is_root=bool(payload.get("is_root")),
        can_sudo=bool(payload.get("can_sudo")),
        ifaces=[_iface(d) for d in payload.get("ifaces", []) if isinstance(d, dict)],
        has_java=bool(payload.get("has_java")),
        has_jmeter=bool(payload.get("has_jmeter")),
        has_trex=bool(payload.get("has_trex")),
    )


def _iface(d: dict[str, Any]) -> Iface:
    return Iface(
        name=str(d.get("name", "")),
        mac=str(d.get("mac", "")),
        state=str(d.get("state", "unknown")),
        speed_mbit=int(d.get("speed_mbit", 0) or 0),
        mtu=int(d.get("mtu", 0) or 0),
        driver=str(d.get("driver", "")),
    )
