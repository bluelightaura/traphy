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

from traphy import forms, link
from traphy import prefs as prefs_mod
from traphy import strings, ui
from traphy.models import Profile
from traphy.probe import HostInfo
from traphy.target import Target, TargetStore, probe_reachable
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
    # Откуда он взялся, только чтобы экран не врал: «задан» без объяснения
    # заставляет искать, кто его задал. Сам пароль никуда не пишется.
    password_from: str = ""               # "" | "env" | "typed"

    # Один наблюдатель связи на всю программу. Держать его по экрану значило бы
    # стучать в общий стенд из двух мест сразу, а он общий.
    watch: link.Watch | None = None
    # Чью связь проверяем. Обычно цель; пока открыта форма - её черновик, иначе
    # индикатор описывал бы сохранённый адрес, а правят другой.
    watching: Target | None = None
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
            port = self.target.tx_label()
            where = f"{host} · {port}" if host else port
            return f"✓ {strings.t('reachable')}: {where}", "ok"
        if self.host and not self.host.ok:
            return f"✗ {strings.t('unreachable')}: {ui.trim(self.host.error, 44)}", "bad"
        return f"○ {strings.t('unchecked')}", "dim"

    # ---- lifecycle -------------------------------------------------------- #
    def load(self) -> None:
        """Restore what the last sitting left behind, filling in defaults."""
        # Пароль из окружения (его кладёт start из ~/.config/traphy/secrets.env).
        # До этого его читал только CLI, а меню передавало в paramiko пустую
        # строку - то есть цель с парольным входом из меню не открывалась вовсе.
        if not self.password:
            from traphy.transport import ssh_password

            found = ssh_password()
            if found:
                self.password, self.password_from = found, "env"

        self.prefs = prefs_mod.load_prefs()
        # Формы берут отсюда прошлые значения полей и сюда же их складывают.
        # Ставится один раз: без этого формы работают как раньше, только без
        # списка вводившегося ранее - что и нужно в тестах.
        forms.set_recall(forms.Recall(self.prefs, self.save_prefs))
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

    # ---- live link -------------------------------------------------------- #
    def watched(self) -> Target:
        return self.watching or self.target

    def start_watch(self) -> None:
        """Начать постоянную проверку связи. Идемпотентно."""
        if self.watch is None:
            self.watch = link.Watch(
                lambda: probe_reachable(self.watched(), timeout=2.0))
        self.watch.start()

    def stop_watch(self) -> None:
        if self.watch is not None:
            self.watch.stop()

    def link_line(self) -> tuple[str, str]:
        """(текст, роль цвета) для живого индикатора связи.

        Отдельно от :meth:`status_line`, и это не дублирование: та говорит, что
        ответило на опрос - имя хоста, python, scapy, - и остаётся верной ровно
        до тех пор, пока ничего не изменилось. Эта говорит, доступна ли машина
        **сейчас**, и проверяет мелко: TCP до порта SSH.
        """
        target = self.watched()
        # Пустой адрес сюда не долетает: по модели цель без адреса - локальная
        # (см. Target.is_local), и это ловится строкой выше.
        if target.is_local:
            return "◆ локальный запуск - сеть не нужна", "dim"
        if self.watch is None:
            return "◌ проверка не запущена", "dim"
        text, role = self.watch.line()
        return f"{text}  ·  {target.host}", role

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

        # Каталог релиза берётся из цели. Без этого опрос искал TRex по своему
        # списку обычных мест, не находил релиз в /opt/trex-3.08 и сообщал «на цели
        # не видно каталога TRex» - при живом демоне и распакованном релизе.
        # В CLI это передавалось, в меню нет, то есть из меню цель с TRex не
        # открывалась вовсе.
        self.host = inspect(self.transport, trex_dir=self.target.trex_dir)
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
