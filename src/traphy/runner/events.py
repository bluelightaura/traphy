"""The ``@traphy`` event stream: one line of JSON at a time, folded into a result.

Every engine's generated script speaks the same events - ``stream``,
``ready``, ``tick``, ``capture``, ``done``, ``error``, ``note`` - and this
module is the only
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
    """Fold the event stream into the result.

    Counters are last-word-wins: a later tick supersedes an earlier one. What
    the script *said* is not - see :func:`_remember`.
    """
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
            result.service_mode = bool(event.get("service_mode", False))
            result.idle_rx = int(event.get("idle_rx", 0) or 0)
            result.idle_rx_groups = int(event.get("idle_rx_groups", 0) or 0)
            result.rx_foreign = int(event.get("rx_foreign", 0) or 0)
            result.rx_per_group = {str(pg): dict(row) for pg, row
                                   in (event.get("groups") or {}).items()}
            result.flow_err_rx = int(event.get("flow_err_rx", 0) or 0)
            result.flow_err_tx = int(event.get("flow_err_tx", 0) or 0)
            result.ordered_pkts = int(event.get("ordered", 0) or 0)
            result.link_down = bool(event.get("link_down", False))
            result.port_errors = dict(event.get("port_errors") or {})
            result.generator_errors = list(event.get("generator_errors") or [])
            if event.get("truncated"):
                result.truncated = list(event["truncated"])
            _remember(result, str(event.get("note", "")))
        elif kind == "capture":
            # Записанная сторона запоминается даже когда файл пуст: цену за
            # запись прогон уже заплатил - у TRex это сервисный режим и
            # пониженный потолок, - и оговорка про неё обязана прозвучать,
            # иначе прогон выглядит медленным без объяснения.
            name = str(event.get("name", ""))
            if name and name not in result.recorded:
                result.recorded.append(name)
        elif kind in ("error", "note"):
            _remember(result, str(event.get("msg", "")))


def _remember(result: RunResult, text: str) -> None:
    """Keep every note the script said, not only the last one.

    ``note`` is a single slot and the last writer wins, which is right for the
    headline and wrong for everything else. A mid-run sentence - an empty
    recording, a port taken by force - is overwritten by whatever ``done`` has
    to say about the counters, and the one line that would have stopped someone
    reading a blank capture as loss never reaches them.
    """
    said = text.strip()
    if not said:
        return
    if said not in result.notes:
        result.notes.append(said)
    result.note = said


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
