"""The directory one run leaves behind, and the way back to it.

A number quoted in a report a week later is worth what can be traced behind it.
So every run writes the profile it came from, the exact script that was
executed, the raw event log and the parsed result into one timestamped
directory - and the result carries the path.

A run that cannot be archived still runs. Losing the record is bad; refusing to
send traffic because a disk is full is worse, and the operator standing at the
stand can see the numbers on the screen either way.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from traphy.runner.events import EVENT_PREFIX
from traphy.target import state_dir

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from traphy.models import Profile
    from traphy.runner.result import RunResult


def run_dir_root() -> Path:
    """Where run archives accumulate."""
    return state_dir() / "runs"


class Archive:
    """A directory holding everything one run consisted of."""

    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self._log = (self.path / "events.jsonl").open("a", encoding="utf-8")

    def log(self, line: str) -> None:
        self._log.write(line[len(EVENT_PREFIX):] + "\n")
        self._log.flush()

    def write_captures(self, chunks: dict[str, list[str]]) -> dict[str, str]:
        """Assemble the base64 that came back and drop real pcaps in the run.

        Named ``tx.pcap`` and ``rx.pcap`` because that is what they are, and
        because a person opening the directory in a month should not need this
        code to work out which is which.
        """
        import base64

        written: dict[str, str] = {}
        for name, parts in sorted(chunks.items()):
            if not parts:
                continue
            path = self.path / f"{name}.pcap"
            try:
                path.write_bytes(base64.b64decode("".join(parts)))
            except (OSError, ValueError):
                continue
            written[name] = str(path)
        return written

    def finish(self, result: RunResult, stderr: str) -> None:
        (self.path / "result.json").write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        if stderr.strip():
            (self.path / "stderr.txt").write_text(stderr, encoding="utf-8")
        self._log.close()


def open_archive(profile: Profile, script: str, result: RunResult,
                 suffix: str = ".py") -> Archive | None:
    """Start an archive for this run, or None if the disk will not have it."""
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
