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

import contextlib
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

# How long a target name may be. The limit is the filesystem's, not taste: a
# name becomes a file name (see :meth:`TargetStore.path_for`), and most of them
# stop at 255 bytes - where a Cyrillic character costs two. Sixty-four is well
# inside that on any encoding and still longer than anything a person types.
NAME_MAX = 64


def name_problem(name: str) -> str:
    """Why this target name cannot be stored, or empty when it can.

    One rule in one place because two callers need the same answer: the form
    refuses the value as it is typed, and :meth:`Target.validate` refuses a
    target that arrived from a file. Checking only at write time meant 300
    characters in the name field reached ``open()`` and came back as
    ``OSError: File name too long`` - a crash panel, with the whole form lost.
    """
    text = name.strip()
    if not text:
        return "у цели пустое имя"
    if len(text) > NAME_MAX:
        return f"имя цели длиннее {NAME_MAX} символов - файл с таким не создать"
    if any(ch in text for ch in "/\\") or any(ord(ch) < 32 for ch in text):
        # Эти символы не отвергаются, а молча заменяются на «_» при записи -
        # то есть «a/b» и «a_b» становятся одним файлом, и человек правит не ту
        # цель. Лучше отказ на вводе, чем совпадение задним числом.
        return "в имени цели нельзя / \\ и управляющие символы"
    if not any(ch.isalnum() or ch in "-_" for ch in text):
        return "в имени цели нет ни буквы, ни цифры - записывать его некуда"
    return ""


@dataclass
class Nic:
    """One interface on the target, under the name the operator thinks in."""

    name: str = "tx"          # a label: "tx", "to-the-switch", whatever reads
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
    # What to do about a host key we have not seen: "strict" refuses it,
    # "accept-new" takes it once and writes it to known_hosts. A key that has
    # CHANGED is refused either way - see traphy.transport.HOST_KEY_MODES.
    host_key: str = "strict"
    # Optional and stronger than known_hosts: the machine has to show exactly
    # this fingerprint. Worth setting on a shared bench, where a box being
    # reinstalled and a box being swapped look identical from here.
    host_key_fingerprint: str = ""

    python: str = "python3"        # interpreter on the target
    use_sudo: bool = True          # raw sockets need root on the sending side

    tx_iface: str = "eth0"         # where frames go out
    rx_iface: str = ""             # where they are expected back; empty = no rx
    link_mbit: int = 1000          # only used to price a "% of line" rate

    # TRex addresses its NICs by index, because DPDK has taken them out of
    # /sys/class/net entirely - an interface name is not a thing that exists
    # on that box any more. These are only read when the engine is TRex; a
    # Scapy target carries them unused and unharmed.
    trex_dir: str = "/opt/trex"    # the unpacked release on the target
    trex_server: str = "127.0.0.1"  # the daemon, as seen from the target
    trex_sync_port: int = 4501     # its control port
    trex_port_tx: int = 0
    trex_port_rx: int = -1         # -1 = not set, so loss is not measured
    # Take ports that somebody else holds. Off by default for the same
    # reason as on Ixia: the generator is shared, and a run that quietly
    # evicts a colleague breaks their measurement without telling either
    # of you.
    trex_force: bool = False

    # Ixia is not a machine at all: the traffic comes out of a chassis in a
    # rack, configured through an API server, and the client runs here. So a
    # port is an address plus a card and a socket on it, written "карта/порт".
    # No password lives here - see traphy.engines.ixia.PASSWORD_ENV.
    ixia_api_host: str = ""        # IxNetwork API server
    ixia_api_port: int = 11009     # 11009 on Windows, 443 on the Linux server
    ixia_api_user: str = ""        # empty = a server that wants no login
    ixia_chassis: str = ""
    ixia_port_tx: str = "1/1"
    ixia_port_rx: str = "1/2"
    # Taking a port off whoever is holding it. Off by default and deliberately
    # so: a chassis is shared, and the person mid-measurement on that port has
    # no way of knowing it was us.
    ixia_force: bool = False

    nics: list[Nic] = field(default_factory=list)

    # ---- helpers ---------------------------------------------------------- #
    @property
    def is_local(self) -> bool:
        """True when the script runs here, with no SSH hop in between."""
        return not self.use_ssh or self.host in ("", "127.0.0.1", "localhost", "::1")

    def adopt(self, info: Any) -> list[str]:
        """Взять с цели то, что она рассказала о себе. Что изменилось - вернуть.

        Берётся только то, что машина знает лучше человека и может назвать
        сама: где лежит релиз, сколько у демона портов, какую линию он
        объявляет. Всё остальное - адрес, логин, пароль, режим ключа хоста -
        не трогается: этого цель про себя не знает, и подставить туда догадку
        значит сломать вход ради удобства.

        Список изменений возвращается, а не пишется в лог, потому что молчаливо
        переписанное поле - это поле, в котором потом ищут свою же опечатку.
        """
        changed: list[str] = []

        def put(field: str, value: Any, said: str) -> None:
            if getattr(self, field) != value:
                changed.append(said)
                setattr(self, field, value)

        if getattr(info, "has_trex_stl", False) and info.trex_dir:
            put("trex_dir", info.trex_dir, f"каталог релиза: {info.trex_dir}")
        # Демон живёт на самой цели, а скрипт уже выполняется там же. Внешний
        # адрес в этом поле не даёт ничего: наличие демона и проверяется на
        # 127.0.0.1.
        if getattr(info, "trex_daemon", False):
            put("trex_server", "127.0.0.1", "демон: 127.0.0.1 (он на самой цели)")

        ports = int(getattr(info, "trex_ports", 0) or 0)
        if ports:
            put("trex_port_tx", 0, "порт отправки: 0")
            if ports >= 2:
                put("trex_port_rx", 1, "порт приёма: 1")
            else:
                put("trex_port_rx", -1,
                    "порт приёма снят: у демона всего один порт, ловить нечем")

        mbit = int(getattr(info, "trex_link_mbit", 0) or 0)
        if mbit:
            put("link_mbit", mbit, f"скорость линии: {mbit} Мбит/с")
        return changed

    def disagrees_with(self, info: Any) -> list[str]:
        """Чем цель расходится с тем, что машина рассказала о себе.

        Тот же расчёт, что и :meth:`adopt`, но на копии: узнать о расхождении
        человек должен раньше, чем прогон не пойдёт, и без того чтобы у него
        под руками что-то молча поменялось.
        """
        import copy

        return copy.deepcopy(self).adopt(info)

    def endpoint(self) -> str:
        """A short "where am I sending from" for the menu's header line."""
        where = self.tx_label() or "-"
        if self.is_local:
            return f"локально · {where}"
        user = f"{self.ssh_user}@" if self.ssh_user else ""
        port = f":{self.ssh_port}" if self.ssh_port != 22 else ""
        return f"{user}{self.host}{port} · {where}"

    def link_subject(self) -> str:
        """Which address the live check is about, as a label for its reading.

        Exactly what :func:`probe_reachable` touches and nothing else: the
        reading is stamped with this and dropped when it no longer matches, so
        an answer from the previous address cannot be shown as an answer from
        the one now in the field. The engine and the port names are left out on
        purpose - changing those says nothing about whether the box replies.
        """
        return f"{self.host}:{self.ssh_port}"

    def _uses_ifaces(self) -> bool:
        from traphy import engines

        return engines.get(self.engine).uses_ifaces

    def _labels(self) -> tuple[str, str]:
        from traphy import engines

        return engines.get(self.engine).port_labels(self)

    def tx_label(self) -> str:
        """Where frames leave from, named the way this engine names ports."""
        return self._labels()[0]

    def rx_label(self) -> str:
        """Where they are expected back, or empty when nobody is counting."""
        return self._labels()[1]

    def measures_rx(self) -> bool:
        """Whether a run can report loss at all, or only what it sent.

        Without a receive port the run counts TX and nothing else, and every
        downstream number has to say so rather than implying zero loss.
        """
        return bool(self.rx_label())

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
            # Targets written by an earlier build carry a boolean. False used
            # to mean "accept anything, remember nothing", which is the one
            # behaviour no mode offers any more; it maps to accept-new, which
            # is what that setting was always reaching for.
            host_key=str(d.get("host_key")
                         or ("strict" if d.get("strict_host_key", True)
                             else "accept-new")),
            host_key_fingerprint=str(d.get("host_key_fingerprint", "")),
            python=str(d.get("python", "python3")),
            use_sudo=bool(d.get("use_sudo", True)),
            tx_iface=str(d.get("tx_iface", "eth0")),
            rx_iface=str(d.get("rx_iface", "")),
            link_mbit=int(d.get("link_mbit", 1000)),
            trex_dir=str(d.get("trex_dir", "/opt/trex")),
            trex_server=str(d.get("trex_server", "127.0.0.1")),
            trex_sync_port=int(d.get("trex_sync_port", 4501)),
            trex_port_tx=int(d.get("trex_port_tx", 0)),
            trex_port_rx=int(d.get("trex_port_rx", -1)),
            trex_force=bool(d.get("trex_force", False)),
            ixia_api_host=str(d.get("ixia_api_host", "")),
            ixia_api_port=int(d.get("ixia_api_port", 11009)),
            ixia_api_user=str(d.get("ixia_api_user", "")),
            ixia_chassis=str(d.get("ixia_chassis", "")),
            ixia_port_tx=str(d.get("ixia_port_tx", "1/1")),
            ixia_port_rx=str(d.get("ixia_port_rx", "1/2")),
            ixia_force=bool(d.get("ixia_force", False)),
            nics=[Nic.from_dict(n) for n in d.get("nics", [])],
        )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def validate(self) -> list[str]:
        problems: list[str] = []
        problem = name_problem(self.name)
        if problem:
            problems.append(problem)
        if self.use_ssh and not self.host.strip():
            problems.append("SSH включён, но адрес не задан")
        if self.use_ssh and not self.ssh_user.strip():
            problems.append("SSH включён, но логин не задан")
        if not 1 <= self.ssh_port <= 65535:
            problems.append("порт SSH вне 1..65535")
        if self.link_mbit <= 0:
            problems.append("скорость линии должна быть больше нуля")
        problems.extend(self._engine_problems())
        if self.ssh_key and not Path(self.ssh_key).expanduser().exists():
            problems.append(f"ключ {self.ssh_key} не найден")
        return problems

    def _engine_problems(self) -> list[str]:
        """Refuse a target pointed at an engine this build cannot drive, and
        otherwise ask that engine what it is missing.

        Selecting an unfinished engine is fine while setting up; running is
        what needs it ready, and this is the check every run goes through.
        What a ready engine needs from the target is its own business - an
        interface name for Scapy, a port index for TRex - so it answers for
        itself rather than being enumerated here.
        """
        from traphy import engines

        engine = engines.get(self.engine)
        if not engine.ready:
            return [f"движок «{engine.title}» {engine.status}"]
        return engine.target_problems(self)


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
        one rather than leaving half a file the next start has to discard.

        An OSError still comes out of here - a name the filesystem refuses is a
        thing a person typed, and whoever asked for the write decides how to
        say so - but the temporary file goes first, so a refused save does not
        leave a half-written sibling for the next start to trip over.
        """
        self._ensure()
        path = self.path_for(target.name)
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(target.to_json() + "\n", encoding="utf-8")
            tmp.replace(path)
        except OSError:
            # Уборка не имеет права заслонить первую ошибку: интересна она, а
            # не то, что имя оказалось слишком длинным и для unlink тоже.
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise
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
