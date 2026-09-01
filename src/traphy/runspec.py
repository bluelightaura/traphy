"""What one run asks for, kept apart from the code that carries it out.

An engine needs to read a run's parameters to build its arguments, and the
runner needs an engine to do the run - so the parameters live in their own
module and neither has to import the other. Small file, but it is what keeps
adding an engine from being a circular-import puzzle.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RunSpec:
    """Everything one run needs beyond the profile and the target."""

    duration: float = 10.0
    count: int = 0               # total packets; overrides duration when > 0
    pps: float = 0.0             # aggregate override; 0 = whatever the profile says
    dry_run: bool = False        # build and report, send nothing
    save_pcap: bool = False
    archive: bool = True
