"""Executing a run, and everything that reads one afterwards.

Split into modules by what each part is for rather than kept as one file, and
the split is not cosmetic - it is what the rest of the tool leans on:

* :mod:`~traphy.runner.result` - the result object. Read by the screen, the
  history, the JSON output and by any comparison between two runs; none of
  those should have to import a transport to do it.
* :mod:`~traphy.runner.events` - the ``@traphy`` line protocol. The single
  place that knows what a ``tick`` or a ``done`` means, so an engine only has
  to emit them.
* :mod:`~traphy.runner.archive` - the directory a run leaves behind, and the
  way back to it a week later.
* :mod:`~traphy.runner.base` - the run itself.
* :mod:`~traphy.runner.zero` - why nothing came back, when nothing did.

The names below are the public surface; importing from the submodules directly
is fine inside the package and discouraged outside it.
"""

from __future__ import annotations

from traphy.runner.archive import Archive, open_archive, recent_runs, run_dir_root
from traphy.runner.base import TIMEOUT_MARGIN, EventCB, execute
from traphy.runner.events import EVENT_PREFIX, apply_events, parse_event
from traphy.runner.result import RunResult
from traphy.runner.zero import explain as explain_zero
from traphy.runspec import RunSpec

__all__ = [
    "EVENT_PREFIX",
    "TIMEOUT_MARGIN",
    "Archive",
    "EventCB",
    "RunResult",
    "RunSpec",
    "apply_events",
    "execute",
    "explain_zero",
    "open_archive",
    "parse_event",
    "recent_runs",
    "run_dir_root",
]
