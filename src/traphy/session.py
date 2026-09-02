"""The state one sitting with the tool accumulates.

A single object the screens pass around: which target is selected, what has
been composed, whether the connection is up and what the target told us about
itself. Keeping it here rather than in module globals means a screen can be
called in a test with a made-up session and no terminal in sight.

The open transport lives here too. Reconnecting per run would be wasteful, and
worse, it would make "connected" a claim rather than a fact - here the claim is
backed by a socket that is still open.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from traphy import prefs as prefs_mod
from traphy import strings, ui
from traphy.models import Profile
from traphy.probe import HostInfo
from traphy.target import Target, TargetStore
from traphy.transport import Transport, TransportError, open_transport


@dataclass
class Session:
    """Everything the screens read and write while the menu is open."""

    target: Target = field(default_factory=Target)
    profile: Profile | None = None
    store: TargetStore = field(default_factory=TargetStore)
    prefs: dict[str, Any] = field(default_factory=dict)

    host: HostInfo | None = None          # what the last probe found
    transport: Transport | None = None    # kept open between runs
    password: str = ""                    # SSH password, this process only
    version: str = "0.0.0"

    profile_dir: Path = field(default_factory=lambda: Path("profiles"))
    script_dir: Path = field(default_factory=lambda: Path("scripts"))

    @property
    def connected(self) -> bool:
        """Whether we have a live transport and a target that answered it."""
        return self.transport is not None and bool(self.host and self.host.ok)

    def status_line(self) -> tuple[str, str]:
        """(text, colour role) for the launcher's connection line."""
        if self.connected:
            host = self.host.hostname if self.host else ""
            where = f"{host} · {self.target.tx_iface}" if host else self.target.tx_iface
            return f"✓ {strings.t('reachable')}: {where}", "ok"
        if self.host and not self.host.ok:
            return f"✗ {strings.t('unreachable')}: {ui.trim(self.host.error, 44)}", "bad"
        return f"○ {strings.t('unchecked')}", "dim"

    # ---- lifecycle -------------------------------------------------------- #
    def load(self) -> None:
        """Restore what the last sitting left behind, filling in defaults."""
        self.prefs = prefs_mod.load_prefs()
        strings.set_lang(str(self.prefs.get("lang", "ru")))
        ui.set_theme(str(self.prefs.get("theme", "dark")))

        name = str(self.prefs.get("target") or "")
        found = self.store.try_load(name) if name else None
        self.target = found or self.store.ensure_seed()

        profile_path = str(self.prefs.get("profile") or "")
        if profile_path and Path(profile_path).exists():
            try:
                self.profile = Profile.load(profile_path)
            except (OSError, ValueError):
                self.profile = None

    def save_prefs(self) -> None:
        self.prefs["lang"] = strings.lang()
        self.prefs["target"] = self.target.name
        prefs_mod.save_prefs(self.prefs)

    def remember_target(self, target: Target) -> None:
        """Adopt a target, persist it, and drop any connection to the old one."""
        if target.name != self.target.name or target.endpoint() != self.target.endpoint():
            self.disconnect()
        self.target = target
        self.store.save(target)
        self.save_prefs()

    def remember_profile(self, profile: Profile) -> None:
        self.profile = profile
        path = self.profile_dir / f"{_safe(profile.name)}.json"
        try:
            profile.save(path)
            self.prefs["profile"] = str(path.resolve())
        except OSError:
            self.prefs["profile"] = ""
        prefs_mod.save_prefs(self.prefs)

    def remember_run(self, profile_name: str, summary: str) -> None:
        prefs_mod.remember_run(self.prefs, profile_name,
                               time.strftime("%Y-%m-%d %H:%M", time.localtime()),
                               summary)
        prefs_mod.save_prefs(self.prefs)

    def last_run_line(self) -> str:
        runs = self.prefs.get("runs") or []
        if not isinstance(runs, list) or not runs:
            return ""
        last = runs[0]
        if not isinstance(last, dict):
            return ""
        parts = [str(last.get("profile", "")), str(last.get("at", ""))]
        return " · ".join(p for p in parts if p)

    # ---- connection ------------------------------------------------------- #
    def connect(self) -> tuple[bool, str]:
        """Open the transport and probe the target. Returns (ok, message).

        Any previous connection is closed first: a target whose address just
        changed must not keep answering through the old socket.
        """
        from traphy.probe import inspect

        self.disconnect()
        try:
            self.transport = open_transport(self.target, password=self.password)
        except TransportError as exc:
            self.host = HostInfo(ok=False, error=str(exc))
            return False, str(exc)

        self.host = inspect(self.transport)
        if not self.host.ok:
            self.disconnect()
            return False, self.host.error
        return True, self._reached(self.host)

    def _reached(self, info: HostInfo) -> str:
        """The "what answered" line, from a probe the caller already checked.

        Takes the info rather than reading ``self.host`` so it cannot be called
        with nothing to describe - an assertion here would vanish under `-O`
        and leave an AttributeError in its place.
        """
        bits = [info.hostname or self.target.host, f"python {info.python}"]
        bits.append(f"scapy {info.scapy_version}" if info.has_scapy else "без scapy")
        return " · ".join(bits)

    def disconnect(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        self.host = None


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name) or "profile"
