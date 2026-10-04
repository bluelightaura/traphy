"""What every engine has to provide, and what it may assume.

An engine turns a :class:`~traphy.models.Profile` into something a host can
execute, says how to invoke it, and reports what would stop it from running
there. It does not open connections, write archives or draw anything - those
belong to the transport, the runner and the screens, and keeping them out is
what makes adding a second engine a matter of one file.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from pathlib import Path

    from traphy.models import Profile, Stream, VMField
    from traphy.probe import HostInfo
    from traphy.runner import RunSpec
    from traphy.target import Target


class EngineNotReady(RuntimeError):
    """This engine cannot do the job here, with a reason a person can act on."""


class Engine(Protocol):
    """The seam. Everything outside :mod:`traphy.engines` talks to this."""

    key: str            # what a target stores
    title: str          # what the picker shows
    hint: str           # one line under the title
    layers: str         # which layers of the stack this engine works at
    ready: bool         # False while an engine is declared but not implemented
    status: str         # why it is not ready, when it is not
    file_suffix: str    # what the generated artefact is called
    uses_ifaces: bool   # whether a NIC name is how this engine names a port
    can_recover: bool   # whether it can clean up after a run that was killed
    opens_raw_socket: bool  # whether the run itself needs a socket the kernel guards
    rate_hint: str      # the standing note under the rate field
    # Как этот движок называет происходящее. Шапка и подсказки меню были
    # написаны под Scapy и оставались такими при выбранном TRex: обещали
    # «погнать скриптом» там, где скрипт никуда не уезжает, и звали настраивать
    # «интерфейсы» там, где их нет, а есть индексы портов из trex_cfg.yaml.
    tagline: str        # подзаголовок главного экрана
    setup_hint: str     # что на самом деле настраивают в цели
    prepared_first: bool  # подготовку генератора делают до настройки цели
    counts_per_group: bool  # считает приём ещё и по группам flow_stats

    def generate(self, profile: Profile, tag: str) -> str:
        """The artefact to ship: a script, a plan, a config."""

    def script_name(self, profile: Profile) -> str:
        """What the artefact is called when it is saved or shown.

        The script screen and the save key ask for it here rather than from one
        generator, so "what you look at is what runs" holds for every engine
        and not only for the one that happens to be the default.
        """

    def interpreter(self, target: Target) -> str:
        """What runs the artefact on the host."""

    def args(self, target: Target, spec: RunSpec, archive: Path | None) -> list[str]:
        """The command-line arguments for one run."""

    def needs_root(self, spec: RunSpec) -> bool:
        """Whether this run has to be elevated on the host."""

    def blockers(self, host: HostInfo) -> list[str]:
        """What about this host would stop the run, worded as something to fix."""

    def port_labels(self, target: Target) -> tuple[str, str]:
        """(where frames leave, where they are expected back) in this engine's
        own vocabulary: an interface name, a port index, a chassis and slot.

        The run result and every screen show these, and none of them should
        have to know which engine is selected to print a sensible line.
        """

    def target_problems(self, target: Target) -> list[str]:
        """What this engine needs from the target that it has not been given.

        A Scapy target is wrong without an interface name; a TRex target is
        wrong without a port index, and an interface name means nothing to it
        at all. Rather than :meth:`Target.validate` growing a branch per
        engine, each engine says what it needs and the target asks whichever
        one it is pointed at.
        """

    def frame_count(self, profile: Profile) -> int:
        """How many distinct units of work the artefact will build."""

    def rate_note(self, stream: Stream, link_mbit: int) -> str:
        """What this engine has to say about a rate just accepted.

        ``link_mbit`` is not optional, because the only interesting thing to
        say about a rate is how it compares to something - the line, or what
        the sending path can pace - and a default would price "50% of the line"
        against a gigabit on a target that has twenty-five of them.
        """

    def range_note(self, vf: VMField) -> str:
        """What this engine will do to a range it cannot walk in full.

        Policy, not validation: whether a sweep is truncated depends on who
        builds the frames. Whether its ends parse at all does not, and stays
        with the model.
        """

    def describe_host(self, host: HostInfo) -> str:
        """What this engine wants to see on the host, in one line, or nothing.

        The "what answered" line is the same line for every engine, and what
        belongs in it is not: a TRex client has no use for Scapy and an Ixia
        one has no use for either.
        """

    def warnings(self, profile: Profile) -> list[str]:
        """What this profile gives up on this engine, before it is sent.

        Not the same as :meth:`target_problems`: nothing here stops a run. It
        is what the run will quietly fail to measure, which is worth reading
        while the traffic is still being composed.
        """

    def describe_result(self, event: dict[str, Any]) -> str:
        """A short line for a finished run, when the engine has one to add."""


class Declared:
    """Shared behaviour for an engine that is named but not yet implemented.

    Selecting one is allowed - a person may well be setting a target up for a
    generator that is not wired in yet - but every path that would touch the
    wire refuses with the same explanation rather than half-working.
    """

    key = ""
    title = ""
    hint = ""
    layers = ""
    ready = False
    status = "ещё не реализован"
    file_suffix = ".txt"
    uses_ifaces = True
    # Убирать за убитым прогоном умеет не всякий генератор: нужен и след на той
    # машине, и способ отобрать ресурсы у мёртвого владельца. У Scapy, который
    # шлёт сам и ничем не владеет, такой операции нет вовсе - и заставлять её
    # реализовать нельзя, поэтому умолчание отрицательное.
    can_recover = False
    opens_raw_socket = False
    rate_hint = ""
    tagline = "собрать кадр руками - погнать его генератором"
    setup_hint = "хост, порты, связь"
    prepared_first = False
    counts_per_group = False

    def _refuse(self) -> EngineNotReady:
        return EngineNotReady(
            f"движок «{self.title}» {self.status} - возьми Scapy "
            f"или дождись реализации")

    def generate(self, profile, tag):
        raise self._refuse()

    def script_name(self, profile):
        """A name even for an artefact nobody can build yet: the save screen
        offers a filename before it ever calls the generator."""
        return f"{profile.name}{self.file_suffix}"

    def interpreter(self, target):
        raise self._refuse()

    def args(self, target, spec, archive):
        raise self._refuse()

    def needs_root(self, spec):
        return False

    def port_labels(self, target):
        """Interface names, until an engine says otherwise.

        Saying otherwise is :attr:`uses_ifaces`: an engine that does not name
        ports by NIC has no interface to report either, and reporting one the
        target form never asked for is how a launcher line ends up describing
        the engine that was selected before this one.
        """
        if not self.uses_ifaces:
            return "", ""
        return target.tx_iface, target.rx_iface

    def target_problems(self, target):
        """Nothing to ask for yet - what it will need is not decided."""
        return []

    def frame_count(self, profile):
        return 0

    def rate_note(self, stream, link_mbit):
        """Nothing to compare against: what this engine can pace is not known
        until it exists."""
        return ""

    def range_note(self, vf):
        return ""

    def describe_host(self, host):
        """Silence rather than somebody else's requirement - the line this fills
        in used to say "без scapy" about engines that never wanted it."""
        return ""

    def warnings(self, profile):
        return []

    def describe_result(self, event):
        return ""


def line_rate_note(stream: Stream, link_mbit: int, who: str) -> str:
    """"More than the port can carry", for an engine that does hold line rate.

    Shared by TRex and Ixia because the arithmetic is the cable's, not the
    generator's. Only the ceiling is worth saying: below it these engines
    deliver what was asked, so a note on every value would train the eye to
    skip the one that matters.
    """
    size = max(stream.packet.frame_size, 1)
    # L1: кадр на проводе несёт ещё преамбулу, FCS и межкадровый интервал -
    # те же 24 байта, которыми Stream.pps считает «% от линии».
    ceiling = link_mbit * 1e6 / ((size + 24) * 8)
    pps = stream.pps(link_mbit)
    if pps > ceiling:
        return (f"! ~{pps:,.0f} pps - больше линии {link_mbit} Мбит/с, "
                f"при {size} B это {ceiling:,.0f} pps; {who} отдаст линию "
                f"и прогон выйдет короче запрошенного")
    return ""
