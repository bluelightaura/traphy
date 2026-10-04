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

from traphy import engines, forms, link
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
    # Кому именно открыт сокет (endpoint() той цели). Нужно потому, что опросить
    # можно и черновик формы: без этого «связь есть» переживало подтверждение
    # другой цели - или наоборот, проверенная связь закрывалась на сохранении
    # той же самой машины только потому, что у неё поменялось имя.
    connected_to: str = ""
    # Отказ, уже названный опросом: блокер движка. Хранится здесь, а не
    # пересчитывается на каждую отрисовку, и запирает всё, что требует связи.
    refused: str = ""
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
    # Последняя разведка генератора. Живёт в сеансе, а не в экране
    # подготовки: шапка главного экрана показывает её же, а опрашивать
    # генератор на каждую перерисовку - это round trip по SSH в цикле.
    generator: Any = None
    version: str = "0.0.0"

    profile_dir: Path = field(default_factory=lambda: Path("profiles"))
    script_dir: Path = field(default_factory=lambda: Path("scripts"))

    @property
    def connected(self) -> bool:
        """Whether we have a live transport, an answer, and nothing in the way.

        The last part is :attr:`refused` - a blocker the probe already named,
        like "no root, no raw socket". Without it the launcher showed a green
        tick and an unlocked "Запустить" for a target whose refusal was known
        the moment it answered, and the run died ten seconds later with the same
        sentence the screen had already been told.
        """
        return (self.transport is not None and bool(self.host and self.host.ok)
                and not self.refused)

    def status_line(self) -> tuple[str, str]:
        """(text, colour role) for the launcher's connection line."""
        if self.connected:
            host = self.host.hostname if self.host else ""
            port = self.target.tx_label()
            where = f"{host} · {port}" if host else port
            return f"✓ {strings.t('reachable')}: {where}", "ok"
        if self.refused:
            # Своими словами движка, без приставки «связи нет»: связь как раз
            # была, не годится машина - и человеку нужна именно эта фраза.
            return f"✗ {ui.trim(self.refused, 50)}", "bad"
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
        # Адреса и логины стенда эта память не держит (prefs.NEVER_REMEMBERED).
        # Выметается при открытии, а не при записи: то, что успела запомнить
        # прежняя версия, иначе так и показывалось бы под полем.
        if prefs_mod.forget_values(self.prefs, *prefs_mod.NEVER_REMEMBERED):
            prefs_mod.save_prefs(self.prefs)
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

    def remember_target(self, target: Target, was: str = "") -> str:
        """Adopt a target and persist it. Returns what went wrong, or "".

        ``was`` is the name this target was stored under. A rename has to move
        the record: writing the new name and leaving the old file behind put two
        indistinguishable rows in the chooser, and the next edit landed on
        whichever of them was read first.

        A name the filesystem refuses comes back as a sentence rather than an
        OSError. This is called straight out of the target form with everything
        the person just typed still in hand, and a crash panel here loses the
        lot - which is exactly what 300 characters in the name field did.
        """
        if self.transport is not None and self.connected_to != target.endpoint():
            # Сокет открыт к другой машине: «связь есть» про неё отвечало бы не
            # на тот вопрос.
            self.disconnect()
        self.target = target
        problem = ""
        try:
            self.store.save(target)
        except OSError as exc:
            problem = f"цель не записана: {exc.strerror or exc}"
        else:
            # Пути, а не имена: «a b» и «a_b» дают один файл, и удаление
            # «прежнего» снесло бы только что записанное.
            if was and self.store.path_for(was) != self.store.path_for(target.name):
                try:
                    self.store.delete(was)
                except OSError as exc:
                    problem = (f"прежняя запись «{was}» осталась: "
                               f"{exc.strerror or exc}")
        self.save_prefs()
        return problem

    def profile_path(self, name: str) -> Path:
        """Where a profile under this name is written.

        Public because the question comes up *before* the write: a screen
        guarding somebody's tuned file has to look at the very path the save
        will use, and a guard on a path the save does not use guards nothing.
        While this was private, the screen repeated the name mangling and the
        two copies could drift apart without anything noticing.
        """
        return self.profile_dir / f"{_safe(name)}.json"

    def select_profile(self, profile: Profile) -> None:
        """Take a profile into this sitting, touching no file.

        Opening a preset to see what is in it is not a decision to keep it. It
        used to be: the profile was written out the moment a preset was picked,
        before a single stream had been shown, so "посмотрю, что в пресете"
        overwrote a file somebody had tuned. Writing answers an explicit
        question - that is :meth:`remember_profile` - and everything else that
        only needs the profile in hand comes through here.
        """
        self.profile = profile

    def remember_profile(self, profile: Profile) -> Path | None:
        """Adopt a profile and write it out. Returns where it landed, or None.

        None means the disk did not take it - nearly always a profile directory
        nobody can write to. The refusal used to be swallowed here, with the
        remembered path quietly emptied, so the screen that had just shown the
        edit could only report "сохранено", and the next sitting opened with
        nothing composed and no explanation. Now the caller is told, and does
        not have to read the file back to find out.
        """
        self.profile = profile
        path = self.profile_path(profile.name)
        saved: Path | None = None
        try:
            profile.save(path)
            self.prefs["profile"] = str(path.resolve())
            saved = path
        except OSError:
            self.prefs["profile"] = ""
        prefs_mod.save_prefs(self.prefs)
        return saved

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
                lambda: probe_reachable(self.watched(), timeout=2.0),
                # Чей ответ это будет. Без подписи показание наследовалось
                # следующим адресом - см. link.Reading.about.
                subject=lambda: self.watched().link_subject())
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
        if not target.is_local:
            if self.watch is None:
                return "◌ проверка не запущена", "dim"
            text, role = self.watch.line()
            # Адрес рядом с показанием, и показание помнит, про кого оно: иначе
            # «отвечает · 0 мс» от прежней машины приклеивалось к новому адресу.
            return f"{text}  ·  {target.host}", role

        # Дальше - цель без SSH-перехода, в том числе и без адреса вовсе (по
        # модели это та же локальная цель, см. Target.is_local). «Сеть не нужна»
        # про неё верно ровно тогда, когда кадры уходят с интерфейса этой самой
        # машины, а про это знает движок, не флаг use_ssh. У Ixia флаг выключен
        # потому, что здесь работает клиент, - шасси и API-сервер при этом стоят
        # в стойке, и «локальный запуск - сеть не нужна» было про них неправдой.
        engine = engines.get(target.engine)
        if engine.uses_ifaces:
            return "◆ локальный запуск - сеть не нужна", "dim"
        # Своего адреса для проверки у генератора тут не спросить: шва на это у
        # движка пока нет, а выдумывать его и стучать раз в две секунды в чужое
        # шасси - то, чего этот инструмент не делает. Поэтому индикатор говорит,
        # чего он не знает, а не притворяется, что знать нечего.
        return f"◇ {engine.title}: связь до генератора проверяет опрос цели", "dim"

    # ---- connection ------------------------------------------------------- #
    def connect(self, target: Target | None = None) -> tuple[bool, str]:
        """Open the transport and probe the target. Returns (ok, message).

        Any previous connection is closed first: a target whose address just
        changed must not keep answering through the old socket.

        ``target`` is the one to dial when it is not the selected one - the
        target form checks the draft being edited. Dialling deliberately does
        not adopt it: the form used to assign it to the session here, so
        pressing "c" accepted a draft nobody had confirmed, and backing out of
        the form with q kept it anyway.
        """
        from traphy.probe import inspect

        who = target or self.target
        self.disconnect()
        try:
            self.transport = open_transport(who, password=self.password)
        except TransportError as exc:
            self.host = HostInfo(ok=False, error=str(exc))
            return False, str(exc)

        # Каталог релиза берётся из цели. Без этого опрос искал TRex по своему
        # списку обычных мест, не находил релиз в /opt/trex-3.08 и сообщал «на цели
        # не видно каталога TRex» - при живом демоне и распакованном релизе.
        # В CLI это передавалось, в меню нет, то есть из меню цель с TRex не
        # открывалась вовсе.
        self.host = inspect(self.transport, trex_dir=who.trex_dir)
        if not self.host.ok:
            self.disconnect()
            return False, self.host.error
        self.connected_to = who.endpoint()
        return True, self._reached(self.host, who)

    def refuse(self, why: str) -> str:
        """Record a refusal the probe already named, and close the link.

        The reason is known the moment the target answers - no root, no Java, no
        Scapy - and a run cannot happen with it standing. It used to be printed
        in the form's status line and nowhere else: the transport stayed open
        and ``host.ok`` stayed true, so the launcher drew "✓ связь есть" and
        unlocked "Запустить" over a refusal it had already been handed.

        Returns the reason, so a caller can report it in the same breath.
        """
        self.disconnect()
        self.refused = why
        return why

    def _reached(self, info: HostInfo, target: Target | None = None) -> str:
        """The "what answered" line, from a probe the caller already checked.

        Takes the info rather than reading ``self.host`` so it cannot be called
        with nothing to describe - an assertion here would vanish under `-O`
        and leave an AttributeError in its place.

        The third part is the engine's to word. It used to be "scapy <версия>"
        or "без scapy" whatever was selected, which on a TRex target named a
        library its client does not use - while the summary line on the same
        screen, asking the engine properly, said the opposite.
        """
        who = target or self.target
        bits = [info.hostname or who.host, f"python {info.python}"]
        said = engines.get(who.engine).describe_host(info)
        if said:
            bits.append(said)
        return " · ".join(bits)

    def disconnect(self) -> None:
        if self.transport is not None:
            self.transport.close()
            self.transport = None
        self.host = None
        self.connected_to = ""
        # Отказ снимается вместе со связью: он был про тот опрос, и держать его
        # дальше значило бы запирать прогон причиной, которой уже не проверяли.
        self.refused = ""


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name) or "profile"
