"""One run, start to finish: generate, ship, execute, read the counters back.

This is the seam between the model and the wire. :func:`execute` takes a
profile and a target, generates the script, hands it to a transport, parses the
``@traphy`` event lines the script prints, and returns a :class:`RunResult`.

The result is deliberately honest about where its numbers came from. There are
four ways the receive side can be counted and they are not worth the same:
``flow_stats`` is a hardware counter per stream group and needs no caveat,
``port_counter`` also sees traffic that is not ours, ``mixed`` covers only part
of the run, and ``none`` means nobody was counting at all. The result carries
which one it was, and every place that displays it has to say so: a zero in the
loss column that actually means "nobody was counting" is the single most
misleading thing a traffic tool can print.

Runs are also archived. Each one writes its profile, the exact script, the
event log and the result into a timestamped directory, so a number quoted in a
report a week later can be traced back to the frames that produced it.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from traphy import codegen, engines
from traphy.models import Profile
from traphy.runspec import RunSpec
from traphy.target import Target, state_dir
from traphy.transport import Transport, open_transport

# Called with each parsed event as the run proceeds, so a UI can draw progress.
EventCB = Callable[[dict[str, Any]], None]

# The prefix the generated script puts in front of its JSON events.
EVENT_PREFIX = "@traphy "

# Grace on top of the requested duration before the transport gives up: script
# start-up, packet building for a large sweep, and the sniffer drain all happen
# outside the send loop.
TIMEOUT_MARGIN = 90


@dataclass
class RunResult:
    """What one run produced, and how much of it to believe."""

    profile: str = ""
    target: str = ""
    engine: str = "scapy"
    transport: str = ""
    tx_iface: str = ""
    rx_iface: str = ""

    tx_pkts: int = 0
    rx_pkts: int = 0
    tx_bytes: int = 0
    seconds: float = 0.0
    requested_pps: float = 0.0
    achieved_pps: float = 0.0

    # marker | flow_stats | traffic_item | port_counter | mixed | partial |
    # none - see the module note
    rx_source: str = "none"
    reliable: bool = False       # False => the loss column needs its caveat
    rc: int = 0
    note: str = ""
    truncated: list[str] = field(default_factory=list)
    started_at: str = ""
    run_dir: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def loss_pkts(self) -> int:
        """Frames sent but not seen coming back. Meaningless when unreliable."""
        return max(0, self.tx_pkts - self.rx_pkts)

    @property
    def loss_pct(self) -> float:
        return (self.loss_pkts / self.tx_pkts * 100.0) if self.tx_pkts else 0.0

    @property
    def rate_shortfall(self) -> float:
        """How far under the asked-for rate the run actually landed, in percent.

        Scapy pacing gives out well before a NIC does. A run that asked for
        100k pps and delivered 30k has not tested the device at 100k, and the
        number that matters for that judgement is this one.
        """
        if self.requested_pps <= 0 or self.achieved_pps <= 0:
            return 0.0
        return max(0.0, (1 - self.achieved_pps / self.requested_pps) * 100.0)

    def summary(self) -> str:
        """One line for the menu's history and for the run screen's footer."""
        head = f"tx={self.tx_pkts} за {self.seconds:.1f} c ({self.achieved_pps:.0f} pps)"
        if self.reliable:
            return f"{head} · rx={self.rx_pkts} · потери {self.loss_pct:.2f}%"
        return f"{head} · приём не измерялся"

    def warnings(self) -> list[str]:
        """Everything about this result a reader should not have to infer."""
        out: list[str] = []
        if not self.reliable:
            out.append(self._rx_caveat())
        if self.rate_shortfall > 10:
            out.append(self._rate_caveat())
        out.extend(f"диапазон урезан - {t}" for t in self.truncated)
        if self.rc != 0:
            why = f": {self.note}" if self.note else ""
            out.append(f"скрипт завершился с кодом {self.rc}{why}")
        return out

    def _rx_caveat(self) -> str:
        """Why this run's loss figure cannot be read at face value.

        Four different situations, and they call for four different next
        moves - which is the whole reason the source is carried rather than
        just a boolean.
        """
        if self.rx_source == "port_counter":
            return ("приём считан счётчиком порта - туда легло всё, что в "
                    "него прилетело, так что потери по нему приблизительны")
        if self.rx_source == "mixed":
            return ("часть потоков ушла без аппаратного счёта - потери "
                    "посчитаны не по всему прогону")
        if self.rx_source == "partial":
            return ("счётчики пришли не по всем потокам - потери посчитаны "
                    "не по всему прогону")
        where = ("порт приёма" if self.engine in ("trex", "ixia")
                 else "интерфейс приёма")
        return (f"приём не измерялся - колонка потерь ничего не значит; "
                f"задай {where} в настройке цели")

    def _rate_caveat(self) -> str:
        """The rate the run actually held, and what falling short of it means.

        On Scapy it usually means the kernel path ran out of road; on TRex the
        generator is not the suspect, so the sentence points elsewhere. Either
        way the conclusion is the same and it is the one that matters: the
        device was not tested at the rate that was asked for.
        """
        head = (f"выдано {self.achieved_pps:.0f} pps из "
                f"{self.requested_pps:.0f} запрошенных "
                f"(-{self.rate_shortfall:.0f}%)")
        if self.engine == "trex":
            why = ("TRex не вышел на заданную скорость - обычно это потолок "
                   "порта или профиль, который его не набирает")
        elif self.engine == "ixia":
            why = ("шасси не вышло на заданную скорость - обычно это потолок "
                   "порта или профиль, который его не набирает")
        else:
            why = "Scapy упёрся"
        return f"{head} - {why}, устройство на этой скорости не проверено"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["loss_pkts"] = self.loss_pkts
        d["loss_pct"] = round(self.loss_pct, 3)
        d["rate_shortfall_pct"] = round(self.rate_shortfall, 1)
        return d


def run_dir_root() -> Path:
    """Where run archives accumulate."""
    return state_dir() / "runs"


def execute(profile: Profile, target: Target, spec: RunSpec | None = None,
            on_event: EventCB | None = None, password: str = "",  # nosec B107
            transport: Transport | None = None) -> RunResult:
    """Do the run. Raises :class:`TransportError` when the target is unreachable.

    Validation failures come back as a result with ``rc`` set and a note, not as
    an exception: a bad profile is an ordinary thing to hit in a builder, and
    the caller wants to show it, not handle it.

    ``transport`` is accepted so a caller that already opened one (the menu
    keeps it open across runs) does not reconnect per run; when it is None a
    transport is opened and closed here.
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

    archive = _open_archive(profile, script, result, engine.file_suffix) \
        if spec.archive else None
    args = engine.args(target, spec, archive.path if archive else None)

    own_transport = transport is None
    if own_transport:
        transport = open_transport(target, password=password)
    result.transport = transport.describe()

    events: list[dict[str, Any]] = []

    def handle(line: str) -> None:
        event = parse_event(line)
        if event is None:
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
            sudo=target.use_sudo and engine.needs_root(spec))
    finally:
        if own_transport:
            transport.close()

    _apply_events(result, events)
    result.rc = completed.rc
    if completed.rc != 0 and not result.note:
        result.note = _first_error(events) or _tail(completed.stderr)
    if archive:
        archive.finish(result, completed.stderr)
        result.run_dir = str(archive.path)
    return result


def parse_event(line: str) -> dict[str, Any] | None:
    """One ``@traphy {...}`` line as a dict, or None for anything else.

    The script's own stdout is mixed in with whatever sudo, the shell or Scapy
    decide to print, so this has to ignore noise rather than choke on it.
    """
    if not line.startswith(EVENT_PREFIX):
        return None
    try:
        event = json.loads(line[len(EVENT_PREFIX):])
    except ValueError:
        return None
    return event if isinstance(event, dict) else None


def _apply_events(result: RunResult, events: list[dict[str, Any]]) -> None:
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


def _first_error(events: list[dict[str, Any]]) -> str:
    for event in events:
        if event.get("ev") == "error":
            return str(event.get("msg", ""))
    return ""


# How much of stderr becomes the note. Long enough for a traceback's last
# frame and its message, short enough to stay one readable line on a panel.
NOTE_LIMIT = 200


def _tail(text: str, lines: int = 2) -> str:
    """The last couple of lines of stderr - where the reason usually is."""
    kept = [line.strip() for line in (text or "").splitlines() if line.strip()]
    note = " · ".join(kept[-lines:])
    return note if len(note) <= NOTE_LIMIT else note[-NOTE_LIMIT:].lstrip()


# --------------------------------------------------------------------------- #
# Archive
# --------------------------------------------------------------------------- #
class Archive:
    """A directory holding everything one run consisted of."""

    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self._log = (self.path / "events.jsonl").open("a", encoding="utf-8")

    def log(self, line: str) -> None:
        self._log.write(line[len(EVENT_PREFIX):] + "\n")
        self._log.flush()

    def finish(self, result: RunResult, stderr: str) -> None:
        (self.path / "result.json").write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        if stderr.strip():
            (self.path / "stderr.txt").write_text(stderr, encoding="utf-8")
        self._log.close()


def _open_archive(profile: Profile, script: str, result: RunResult,
                  suffix: str = ".py") -> Archive | None:
    """Start an archive for this run, or None if the disk will not have it.

    A run that cannot be archived still runs: losing the record is worse than
    nothing, but not as bad as refusing to send traffic over it.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    name = "".join(c if c.isalnum() or c in "-_" else "_" for c in profile.name)
    try:
        archive = Archive(run_dir_root() / f"{stamp}_{name}")
        (archive.path / "profile.json").write_text(profile.to_json() + "\n",
                                                   encoding="utf-8")
        (archive.path / f"script{suffix}").write_text(script, encoding="utf-8")
    except OSError:
        return None
    result.run_dir = str(archive.path)
    return archive


def recent_runs(limit: int = 10) -> list[dict[str, Any]]:
    """The last few archived results, newest first, for the history screen."""
    root = run_dir_root()
    if not root.exists():
        return []
    out: list[dict[str, Any]] = []
    for d in sorted(root.iterdir(), reverse=True):
        if len(out) >= limit:
            break
        try:
            data = json.loads((d / "result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data["dir"] = str(d)
            out.append(data)
    return out
