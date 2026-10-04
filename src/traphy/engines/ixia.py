"""The Ixia engine: an IxNetwork chassis driven over REST from this machine.

The third shape of run, and the one that bends the "target" idea furthest.
Scapy runs a script on a host. TRex talks to a daemon on a host. Ixia is neither
- the traffic comes out of a chassis somewhere on the network, configured
through an API server, and the client that does the configuring runs right
here. So an Ixia target is not a machine that executes anything; it is an
address, a card and a port.

Three things about it are worth stating out loud, because each one is a way to
be wrong quietly:

* **A port belongs to someone.** Chassis ports are shared, and one can be held
  by a colleague halfway through their own measurement. Taking it is a real
  thing this tool can do and never a thing it does by accident:
  :attr:`Target.ixia_force` is off by default, and a busy port comes back named
  together with whoever is on it.
* **A receive port is not optional.** A raw traffic item needs both endpoints,
  so unlike the other two engines there is no "send and do not count" mode
  here. That makes every Ixia run measure loss properly, which is a good
  property to have by construction rather than by discipline.
* **Passwords are never stored.** A Linux API server wants a login; the
  password is read from ``TRAPHY_IXIA_PASSWORD`` in the environment, not from
  the target file and not from the command line where every process on the
  machine can read it.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from traphy import codegen_ixnet
from traphy.engines import inventory
from traphy.engines.base import line_rate_note
from traphy.models import Profile, Stream
from traphy.probe import HostInfo
from traphy.runspec import RunSpec
from traphy.target import Target

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from pathlib import Path

    from traphy.models import VMField

# The environment variable the generated script reads its password from. Named
# here so the target form, the validation and the script all agree on it.
# This is the variable's name, not anybody's password - which is the whole
# point of it: the secret lives in the environment and never in this repository
# or in a saved target.
PASSWORD_ENV = "TRAPHY_IXIA_PASSWORD"  # nosec B105

RX_SOURCES = {
    "traffic_item": "приём посчитан самим шасси по traffic item - это счётчик "
                    "карты; число можно класть в отчёт как есть",
    "partial": "счётчики пришли не по всем потокам - потери посчитаны "
               "не по всему прогону",
}


def parse_port(text: str) -> tuple[int, int] | None:
    """``"1/2"`` into ``(card, port)``, or None when it is not that.

    Accepts a colon as well as a slash, because that is how half the chassis
    documentation writes it and retyping a port number from a label is exactly
    where a slip goes unnoticed.
    """
    parts = str(text).replace(":", "/").split("/")
    if len(parts) != 2:
        return None
    try:
        card, port = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    return (card, port) if card > 0 and port > 0 else None


class IxiaEngine:
    key = "ixia"
    title = "Ixia"
    hint = "IxNetwork: шасси по REST, счёт по traffic item"
    layers = "L2-L4"
    ready = True
    status = ""
    file_suffix = ".py"
    uses_ifaces = False
    # Шасси порты отдаёт, но следа аренды на нём traphy не ведёт - пока уборка
    # за убитым прогоном тут не реализована, а врать про умение нельзя.
    can_recover = False
    opens_raw_socket = False
    rate_hint = "скорость держит шасси - до линейной скорости порта"
    tagline = "собрать кадр руками - погнать его шасси IxNetwork"
    setup_hint = "шасси, карты, порты, связь"
    prepared_first = False
    counts_per_group = False

    def generate(self, profile: Profile, tag: str) -> str:
        return codegen_ixnet.generate(profile, tag=tag)

    def script_name(self, profile: Profile) -> str:
        return codegen_ixnet.script_name(profile)

    def interpreter(self, target: Target) -> str:
        """Whatever Python has ``ixnetwork-restpy`` - normally this machine's.

        The target is the chassis, not a host to log into, so an Ixia target is
        usually a local one and this is the local interpreter.
        """
        return target.python

    def args(self, target: Target, spec: RunSpec, archive: Path | None) -> list[str]:
        args = [
            "--api-host", target.ixia_api_host,
            "--api-port", str(target.ixia_api_port),
            "--chassis", target.ixia_chassis,
            "--tx-port", target.ixia_port_tx,
            "--rx-port", target.ixia_port_rx,
            "--duration", f"{spec.duration:g}",
        ]
        if target.ixia_api_user:
            args += ["--api-user", target.ixia_api_user]
        if spec.pps:
            args += ["--pps", f"{spec.pps:g}"]
        if spec.count:
            # Passed on rather than dropped: the script refuses it with the
            # reason and the way to get what was actually wanted.
            args += ["--count", str(spec.count)]
        if target.ixia_force or spec.force:
            # Липкий тумблер цели или решение на один прогон - см. тот же
            # разбор в движке TRex.
            args.append("--force")
        if spec.dry_run:
            args.append("--dry-run")
        return args

    def needs_root(self, spec: RunSpec) -> bool:
        """Nothing here opens a socket the kernel guards - the chassis does
        the sending and it was never ours to elevate."""
        return False

    def port_labels(self, target: Target) -> tuple[str, str]:
        chassis = target.ixia_chassis or "шасси"
        return (f"{chassis} {target.ixia_port_tx}",
                f"{chassis} {target.ixia_port_rx}")

    def blockers(self, host: HostInfo) -> list[str]:
        out: list[str] = []
        if not host.has_ixnetwork:
            out.append("нет ixnetwork-restpy - поставь там, откуда "
                       "запускается TRaphy: pip install ixnetwork-restpy")
        return out

    def target_problems(self, target: Target) -> list[str]:
        out: list[str] = []
        if not target.ixia_api_host.strip():
            out.append("не задан API-сервер IxNetwork")
        if not 1 <= target.ixia_api_port <= 65535:
            out.append("порт API вне 1..65535")
        if not target.ixia_chassis.strip():
            out.append("не задан адрес шасси")
        for label, value in (("отправки", target.ixia_port_tx),
                             ("приёма", target.ixia_port_rx)):
            if parse_port(value) is None:
                out.append(f"порт {label} задаётся как карта/порт, например 1/2")
        if (parse_port(target.ixia_port_tx)
                and parse_port(target.ixia_port_tx)
                == parse_port(target.ixia_port_rx)):
            out.append("порт приёма совпадает с портом отправки - "
                       "трафик некуда принимать")
        if target.ixia_api_user and not os.environ.get(PASSWORD_ENV):
            # Caught here rather than three minutes into a run: the fix is one
            # export away and the run has not touched the chassis yet.
            out.append(f"логин задан, а пароля нет - положи его в "
                       f"{PASSWORD_ENV}")
        return out

    def frame_count(self, profile: Profile) -> int:
        return codegen_ixnet.frame_count(profile)

    def rate_note(self, stream: Stream, link_mbit: int) -> str:
        return line_rate_note(stream, link_mbit, "шасси")

    def range_note(self, vf: VMField) -> str:
        """The chassis counts through a range itself - nothing is expanded
        here, so nothing is cut short."""
        return ""

    def describe_host(self, host: HostInfo) -> str:
        """Only one thing has to be here; the chassis is checked by the run."""
        if not host.has_ixnetwork:
            return "нет ixnetwork-restpy"
        version = f" {host.ixnetwork_version}" if host.ixnetwork_version else ""
        return f"ixnetwork-restpy{version}"

    def describe_result(self, event: dict[str, Any]) -> str:
        return RX_SOURCES.get(str(event.get("rx_source", "")), "")

    def warnings(self, profile: Profile) -> list[str]:
        return codegen_ixnet.warnings(profile)

    def readiness(self, target: Target) -> inventory.Readiness:
        """The chassis ports this target points at, before the session exists.

        Two things will fill in here once a session is opened and neither can
        be guessed from a file: whether the port has a link, and who is holding
        it. The second is the one that matters - a chassis port is shared, and
        a run that quietly takes one out from under a colleague mid-measurement
        is worse than a run that refuses. Until the session lands, the holder
        is reported as unknown rather than as free.
        """
        ports = [
            inventory.Port(label=target.ixia_port_tx,
                           description=target.ixia_chassis,
                           note="отправка · карта/порт шасси"),
            inventory.Port(label=target.ixia_port_rx,
                           description=target.ixia_chassis,
                           note="приём · карта/порт шасси"),
        ]
        where = target.ixia_api_host or "API-сервер не задан"
        return inventory.not_asked(
            ports, f"сессия к {where} не открывалась - занятость портов "
                   f"и линк неизвестны, показана настройка цели")
