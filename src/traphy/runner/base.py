"""Performing one run: generate, ship, execute, read the counters back.

This is the seam between the model and the wire, and it is deliberately the
only place that touches all of them at once. It takes a profile and a target,
asks the selected engine for an artefact, hands it to a transport, feeds the
``@traphy`` lines to the event folder and returns a result.

What it is careful *not* to do is decide anything an engine should decide.
Which interpreter, which arguments, what counts as a port, whether root is
needed - all of that is asked of the engine rather than branched on here. That
is what lets a new generator be a file plus its code generator instead of a
patch spread across the runner, the target form and the result.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from traphy import codegen, engines
from traphy.runner.archive import open_archive
from traphy.runner.events import apply_events, first_error, parse_event, tail
from traphy.runner.result import RunResult
from traphy.runspec import RunSpec
from traphy.transport import Transport, open_transport

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from traphy.models import Profile
    from traphy.target import Target

# Called with each parsed event as the run proceeds, so a UI can draw progress.
EventCB = Callable[[dict[str, Any]], None]

# Grace on top of the requested duration before the transport gives up: script
# start-up, packet building for a large sweep, and the sniffer drain all happen
# outside the send loop.
TIMEOUT_MARGIN = 90


def execute(profile: Profile, target: Target, spec: RunSpec | None = None,
            on_event: EventCB | None = None, password: str = "",  # nosec B107
            transport: Transport | None = None,
            sudo_password: str = "") -> RunResult:  # nosec B107
    """Do the run. Raises :class:`TransportError` when the target is unreachable.

    Validation failures come back as a result with ``rc`` set and a note, not as
    an exception: a bad profile is an ordinary thing to hit in a builder, and
    the caller wants to show it, not handle it.

    ``transport`` is accepted so a caller that already opened one (the menu
    keeps it open across runs) does not reconnect per run; when it is None a
    transport is opened and closed here.

    ``sudo_password`` is for the ordinary bench machine, where the account that
    SSH accepts is not one sudo waves through. It travels down the script's
    stdin - never a file, never an argument, never the process table - and is
    not stored anywhere by this call.
    """
    spec = spec or RunSpec()
    started = time.time()
    result = RunResult(
        profile=profile.name, target=target.name,
        engine=target.engine,
        # Named the way the selected engine names a port: an interface for
        # Scapy, a TRex port index for TRex. The field keeps its name because
        # the history and the run screen read it, but its contents follow the
        # engine rather than assuming everything has a NIC name.
        tx_iface=target.tx_label(), rx_iface=target.rx_label(),
        requested_pps=spec.pps or profile.total_pps(target.link_mbit),
        dry_run=spec.dry_run,
        started_at=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
    )

    problems = profile.validate() + target.validate()
    if problems:
        result.rc = 2
        result.note = "; ".join(problems)
        return result

    # A fresh marker per run, so a sniffer never counts frames left over from
    # the previous one still draining through a slow path.
    engine = engines.get(target.engine)
    result.engine = engine.key
    tag = codegen.DEFAULT_TAG[:6] + secrets.token_hex(1)
    try:
        script = engine.generate(profile, tag=tag)
    except engines.EngineNotReady as exc:
        result.rc = 2
        result.note = str(exc)
        return result

    archive = open_archive(profile, script, result, engine.file_suffix) \
        if spec.archive else None
    args = engine.args(target, spec, archive.path if archive else None)

    own_transport = transport is None
    if own_transport:
        transport = open_transport(target, password=password)
    result.transport = transport.describe()

    events: list[dict[str, Any]] = []
    captures: dict[str, list[str]] = {}

    def handle(line: str) -> None:
        event = parse_event(line)
        if event is None:
            return
        if event.get("ev") == "capture_data":
            # Frames coming home. Kept out of the event log and out of the
            # UI callback: a capture is tens of thousands of base64 characters,
            # and a log nobody can scroll is a log nobody reads.
            captures.setdefault(str(event.get("name", "")), []).append(
                str(event.get("data", "")))
            return
        events.append(event)
        if archive:
            archive.log(line)
        if on_event:
            on_event(event)

    timeout = int(spec.duration + TIMEOUT_MARGIN)
    try:
        completed = transport.run_stream(
            script, args, handle, timeout=timeout,
            sudo=target.use_sudo and engine.needs_root(spec),
            secret=sudo_password)
    finally:
        if own_transport:
            transport.close()

    apply_events(result, events)
    if archive and captures:
        result.captures = archive.write_captures(captures)
    result.rc = completed.rc
    if completed.rc != 0 and not result.note:
        result.note = first_error(events) or tail(completed.stderr)
    if archive:
        archive.finish(result, completed.stderr)
        result.run_dir = str(archive.path)
    return result
