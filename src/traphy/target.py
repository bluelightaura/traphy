"""Where the traffic actually leaves from: a host and the NICs on it.

TRaphy does not send packets itself. It generates a Scapy script and hands it
to a *target* - either this machine or a box reached over SSH - which is the
one that needs root, a real NIC and Scapy installed. Everything needed to get
there and to interpret the result lives in :class:`Target`.

Targets are JSON under a per-user state directory rather than in the working
tree, for the same reason CLIRadar keeps its device config out of git: a saved
target names a real machine on a real network, and that belongs to the person,
not to the repository.

No password is ever written here. SSH auth is by key or agent; if a target
genuinely needs a password, it is read into the process environment for the
life of the run and never persisted.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Reasonable link rates to price a percentage against. The value is only ever
# used to turn "50% of the line" into a pps number; it does not constrain what
# the NIC does.
LINK_RATES = (100, 1000, 10000, 25000, 40000, 100000)


@dataclass
class Nic:
    """One interface on the target, under the name the operator thinks in."""

    name: str = "tx"          # a label: "tx", "to-SW101", whatever reads well
    iface: str = "eth0"       # what the target's kernel calls it
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Nic:
        return cls(name=str(d.get("name", "")), iface=str(d.get("iface", "")),
                   note=str(d.get("note", "")))


@dataclass
class Target:
    """A host that can send traffic, and how to reach it.

    ``use_ssh`` False means "this machine": the script is run as a subprocess
    and no SSH is involved at all. Otherwise ``host``/``ssh_user`` are used, the
    host key is checked against ``~/.ssh/known_hosts``, and only key or agent
    auth is attempted unless a password is supplied out of band.
    """

    name: str = "local"
    description: str = ""

    # Which generator produces the traffic here. Stored per target because it
    # is a property of the machine - the box with DPDK bound NICs is a TRex
    # target, the one with a JVM is a JMeter target - not of the profile.
    engine: str = "scapy"

    use_ssh: bool = False
    host: str = "127.0.0.1"
    ssh_user: str = ""
    ssh_port: int = 22
    ssh_key: str = ""              # path to a private key; empty = agent/default
    strict_host_key: bool = True   # refuse a host not already in known_hosts

    python: str = "python3"        # interpreter on the target
    use_sudo: bool = True          # raw sockets need root on the sending side

    tx_iface: str = "eth0"         # where frames go out
    rx_iface: str = ""             # where they are expected back; empty = no rx
    link_mbit: int = 1000          # only used to price a "% of line" rate

    nics: list[Nic] = field(default_factory=list)

    # ---- helpers ---------------------------------------------------------- #
    @property
    def is_local(self) -> bool:
        """True when the script runs here, with no SSH hop in between."""
        return not self.use_ssh or self.host in ("", "127.0.0.1", "localhost", "::1")

    def endpoint(self) -> str:
        """A short "where am I sending from" for the menu's header line."""
        if self.is_local:
            return f"локально · {self.tx_iface or '-'}"
        user = f"{self.ssh_user}@" if self.ssh_user else ""
        port = f":{self.ssh_port}" if self.ssh_port != 22 else ""
        return f"{user}{self.host}{port} · {self.tx_iface or '-'}"

    def measures_rx(self) -> bool:
        """Whether a run can report loss at all, or only what it sent.

        Without a receive interface the script counts TX and nothing else, and
        every downstream number has to say so rather than implying zero loss.
        """
        return bool(self.rx_iface)

    # ---- serialization ---------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["nics"] = [n.to_dict() for n in self.nics]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Target:
        return cls(
            name=str(d.get("name", "local")),
            description=str(d.get("description", "")),
            engine=str(d.get("engine", "scapy")),
            use_ssh=bool(d.get("use_ssh", False)),
            host=str(d.get("host", "127.0.0.1")),
            ssh_user=str(d.get("ssh_user", "")),
            ssh_port=int(d.get("ssh_port", 22)),
            ssh_key=str(d.get("ssh_key", "")),
            strict_host_key=bool(d.get("strict_host_key", True)),
            python=str(d.get("python", "python3")),
            use_sudo=bool(d.get("use_sudo", True)),
            tx_iface=str(d.get("tx_iface", "eth0")),
            rx_iface=str(d.get("rx_iface", "")),
            link_mbit=int(d.get("link_mbit", 1000)),
            nics=[Nic.from_dict(n) for n in d.get("nics", [])],
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def validate(self) -> list[str]:
        problems: list[str] = []
        if not self.name.strip():
            problems.append("у цели пустое имя")
        if self.use_ssh and not self.host.strip():
            problems.append("SSH включён, но адрес не задан")
        if self.use_ssh and not self.ssh_user.strip():
            problems.append("SSH включён, но логин не задан")
        if not 1 <= self.ssh_port <= 65535:
            problems.append("порт SSH вне 1..65535")
        if not self.tx_iface.strip():
            problems.append("не выбран интерфейс отправки")
        if self.rx_iface and self.rx_iface == self.tx_iface and not self.is_local:
            problems.append("приём и отправка на одном интерфейсе - "
                            "потери мерить нечем")
        if self.link_mbit <= 0:
            problems.append("скорость линии должна быть больше нуля")
        problems.extend(self._engine_problems())
        if self.ssh_key and not Path(self.ssh_key).expanduser().exists():
            problems.append(f"ключ {self.ssh_key} не найден")
        return problems

    def _engine_problems(self) -> list[str]:
        """Refuse a target pointed at an engine this build cannot drive.

        Selecting one is fine while setting up; running is what needs it ready,
        and this is the check every run goes through.
        """
        from traphy import engines

        engine = engines.get(self.engine)
        if not engine.ready:
            return [f"движок «{engine.title}» {engine.status}"]
        return []


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def state_dir() -> Path:
    """Where targets live, honouring XDG_STATE_HOME when it is set."""
    base = os.environ.get("XDG_STATE_HOME") or ""
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "traphy"


class TargetStore:
    """Targets as one JSON file each, in a directory the operator owns."""

    def __init__(self, directory: str | Path | None = None):
        self.dir = Path(directory) if directory else state_dir() / "targets"

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, name: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name) or "target"
        return self.dir / f"{safe}.json"

    def save(self, target: Target) -> Path:
        """Write a target out atomically, so an interrupted save keeps the old
        one rather than leaving half a file the next start has to discard."""
        self._ensure()
        path = self.path_for(target.name)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(target.to_json() + "\n", encoding="utf-8")
        tmp.replace(path)
        return path

    def load(self, name: str) -> Target:
        raw = json.loads(self.path_for(name).read_text(encoding="utf-8"))
        return Target.from_dict(raw)

    def try_load(self, name: str) -> Target | None:
        """Load, or None if it is missing or unreadable. Used on start-up,
        where a corrupt file must not stop the menu from opening."""
        try:
            return self.load(name)
        except (OSError, ValueError, TypeError):
            return None

    def list(self) -> list[str]:
        if not self.dir.exists():
            return []
        return sorted(p.stem for p in self.dir.glob("*.json"))

    def delete(self, name: str) -> None:
        self.path_for(name).unlink(missing_ok=True)

    def ensure_seed(self) -> Target:
        """Guarantee at least one target exists, and return the first.

        The seed is this machine with a placeholder interface: it is offline,
        harmless, and it makes the first screen show a real form rather than an
        empty list. Deliberately not a remembered lab address - a repository
        that ships someone's bench IP is how that address ends up public.
        """
        existing = self.list()
        if existing:
            found = self.try_load(existing[0])
            if found:
                return found
        seed = Target(name="local", description="эта машина",
                      use_ssh=False, host="127.0.0.1", tx_iface="eth0")
        self.save(seed)
        return seed


# --------------------------------------------------------------------------- #
# Reachability
# --------------------------------------------------------------------------- #
ProgressCB = Callable[[float], None]


def probe_reachable(target: Target, timeout: float = 4.0,
                    on_progress: ProgressCB | None = None) -> tuple[bool, str]:
    """Can we get to the target at all? Returns (reachable, explanation).

    Deliberately shallow: this opens a TCP connection to the SSH port and
    nothing more. It answers "is the box there and listening", which is the
    question a person has when the next screen refuses to start a run; proving
    the credentials work is the run's own job.

    A local target is reachable by definition - there is nothing to cross.
    """
    if target.is_local:
        if on_progress:
            on_progress(1.0)
        return True, "локальный запуск - сеть не нужна"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # A progress tick before the blocking connect, so the bar moves even
        # when the connect itself is the thing taking the time.
        if on_progress:
            on_progress(0.15)
        sock.connect((target.host, target.ssh_port))
    except socket.gaierror:
        return False, f"имя {target.host} не разрешается"
    except TimeoutError:
        return False, f"{target.host}:{target.ssh_port} не отвечает за {timeout:g} c"
    except OSError as exc:
        return False, f"{target.host}:{target.ssh_port} - {exc.strerror or exc}"
    finally:
        sock.close()
        if on_progress:
            on_progress(1.0)
    return True, f"порт {target.ssh_port} открыт на {target.host}"


def host_key_known(host: str, port: int = 22) -> bool:
    """Whether this host already has a pinned key in ~/.ssh/known_hosts.

    The menu asks before a strict connection so the refusal comes with an
    explanation and a choice, instead of surfacing as a paramiko exception in
    the middle of a run.
    """
    path = Path.home() / ".ssh" / "known_hosts"
    entry = f"[{host}]:{port}" if port != 22 else host
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        names = line.split(None, 1)[0]
        if entry in names.split(","):
            return True
    return False
