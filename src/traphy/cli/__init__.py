"""The command line: the menu by default, and the same work without it.

Running ``traphy`` with no arguments opens the launcher, which is how the tool
is meant to be used - compose by hand, connect, send. The subcommands exist so
the same profiles are usable from a script or a CI job: generate a file, run a
saved profile against a named target, ask a target what it has.

Split three ways, and the split is the point:

* :mod:`~traphy.cli.parser` builds the parser and touches nothing else, so
  reading a command line never starts work;
* :mod:`~traphy.cli.resolve` turns a name into a profile or a target, failing
  with a line and a list rather than a traceback;
* :mod:`~traphy.cli.commands` holds one handler per command, each a thin call
  into the same functions the menu uses.

Everything a subcommand does is something the menu does too, through those same
functions. There is no second implementation to drift.
"""

from __future__ import annotations

from pathlib import Path

from traphy import __version__, menu
from traphy.cli.commands import (
    cmd_gen,
    cmd_history,
    cmd_presets,
    cmd_probe,
    cmd_recover,
    cmd_run,
    cmd_targets,
)
from traphy.cli.parser import build_parser
from traphy.cli.resolve import load_profile, load_target


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = {
        None: lambda a: menu.run(__version__, Path(a.profiles)),
        "gen": cmd_gen,
        "run": cmd_run,
        "probe": cmd_probe,
        "recover": cmd_recover,
        "presets": cmd_presets,
        "targets": cmd_targets,
        "history": cmd_history,
    }[args.command]
    return handler(args)


__all__ = ["build_parser", "load_profile", "load_target", "main"]
