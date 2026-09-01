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

    from traphy.models import Profile
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

    def generate(self, profile: Profile, tag: str) -> str:
        """The artefact to ship: a script, a plan, a config."""

    def interpreter(self, target: Target) -> str:
        """What runs the artefact on the host."""

    def args(self, target: Target, spec: RunSpec, archive: Path | None) -> list[str]:
        """The command-line arguments for one run."""

    def needs_root(self, spec: RunSpec) -> bool:
        """Whether this run has to be elevated on the host."""

    def blockers(self, host: HostInfo) -> list[str]:
        """What about this host would stop the run, worded as something to fix."""

    def frame_count(self, profile: Profile) -> int:
        """How many distinct units of work the artefact will build."""

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

    def _refuse(self) -> EngineNotReady:
        return EngineNotReady(
            f"движок «{self.title}» {self.status} — возьми Scapy "
            f"или дождись реализации")

    def generate(self, profile, tag):
        raise self._refuse()

    def interpreter(self, target):
        raise self._refuse()

    def args(self, target, spec, archive):
        raise self._refuse()

    def needs_root(self, spec):
        return False

    def frame_count(self, profile):
        return 0

    def describe_result(self, event):
        return ""
