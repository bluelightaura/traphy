"""The ``@traphy`` event stream: one line of JSON at a time, folded into a result.

Every engine's generated script speaks the same six events - ``stream``,
``ready``, ``tick``, ``done``, ``error``, ``note`` - and this module is the only
place that knows what they mean. That is what keeps an engine from having to
also be a result parser: adding a generator means emitting these lines, not
teaching the runner a new dialect.

The parsing is deliberately forgiving. A script's own stdout arrives mixed in
with whatever sudo, the shell, Scapy or a DPDK driver decided to print, so
anything that is not one of our lines is skipped rather than treated as a
failure.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from traphy.runner.result import RunResult

# The prefix the generated script puts in front of its JSON events.
EVENT_PREFIX = "@traphy "

# How much of stderr becomes the note. Long enough for a traceback's last
# frame and its message, short enough to stay one readable line on a panel.
NOTE_LIMIT = 200


def parse_event(line: str) -> dict[str, Any] | None:
    """One ``@traphy {...}`` line as a dict, or None for anything else."""
    if not line.startswith(EVENT_PREFIX):
        return None
    try:
        event = json.loads(line[len(EVENT_PREFIX):])
    except ValueError:
        return None
    return event if isinstance(event, dict) else None


def apply_events(result: RunResult, events: list[dict[str, Any]]) -> None:
    """Fold the event stream into the result, last word wins."""
    for event in events:
        kind = event.get("ev")
        if kind == "ready":
            result.truncated = list(event.get("truncated") or [])
        elif kind == "tick":
            result.tx_pkts = int(event.get("tx", result.tx_pkts))
            result.rx_pkts = int(event.get("rx", result.rx_pkts))
        elif kind == "done":
            result.tx_pkts = int(event.get("tx", 0))
            result.rx_pkts = int(event.get("rx", 0))
            result.tx_bytes = int(event.get("tx_bytes", 0))
            result.seconds = float(event.get("seconds", 0.0))
            result.achieved_pps = float(event.get("achieved_pps", 0.0))
            result.rx_source = str(event.get("rx_source", "none"))
            result.reliable = bool(event.get("reliable", False))
            if event.get("truncated"):
                result.truncated = list(event["truncated"])
            if event.get("note"):
                result.note = str(event["note"])
        elif kind in ("error", "note"):
            result.note = str(event.get("msg", "")) or result.note


def first_error(events: list[dict[str, Any]]) -> str:
    """The first thing the script called an error, for the result's note."""
    for event in events:
        if event.get("ev") == "error":
            return str(event.get("msg", ""))
    return ""


def tail(text: str, lines: int = 2) -> str:
    """The last couple of lines of stderr - where the reason usually is."""
    kept = [line.strip() for line in (text or "").splitlines() if line.strip()]
    note = " · ".join(kept[-lines:])
    return note if len(note) <= NOTE_LIMIT else note[-NOTE_LIMIT:].lstrip()
