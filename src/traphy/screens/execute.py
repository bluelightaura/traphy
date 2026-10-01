"""Looking at the script, sending it, and reading what came back.

The script screen shows the generated file itself - not a summary of it - so
what is reviewed is what runs. The run screen watches the ``@traphy`` events
arrive and repaints a counter panel about once a second.

The result screen is where this module earns its keep. It refuses to print a
loss figure as if it were measured when nothing was measuring, and it says
plainly when the achieved rate fell short of the requested one, because a run
that could not reach the rate has not tested the device at that rate.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from traphy import codegen, ui
from traphy.runner import RunResult, RunSpec, execute as do_run, recent_runs
from traphy.session import Session
from traphy.strings import t
from traphy.transport import TransportError, sudo_password


# --------------------------------------------------------------------------- #
# The script
# --------------------------------------------------------------------------- #
def script_screen(session: Session) -> None:
    """Page through the generated script, and save it from here."""
    if not session.profile:
        return
    text = codegen.generate(session.profile)
    lines = text.splitlines()
    head = t("script_head", name=codegen.script_name(session.profile),
             lines=len(lines))
    page = 0
    status = ""
    body = 22

    while True:
        top = max(0, min(page, max(0, len(lines) - body)))
        shown = lines[top:top + body]
        panel = [ui.c(head, "title"), None]  # type: ignore[list-item]
        for i, line in enumerate(shown):
            number = ui.c(f"{top + i + 1:4} ", "dim")
            # Comments and docstrings carry the explanation; dimming them keeps
            # the code itself the thing the eye lands on.
            body_role = "dim" if line.lstrip().startswith("#") else "title"
            panel.append(number + ui.c(ui.trim(line, ui.WIDE - 5), body_role))
        panel.append("")
        if status:
            panel.append(ui.c("  " + status.lstrip("! "),
                              "bad" if status.startswith("!") else "ok"))
        # Через словарь: собранная здесь строка оставалась русской при
        # английском языке, и подвал экрана выходил наполовину переведённым.
        panel.append(ui.c("  " + t("script_pager", a=top + 1,
                                   b=top + len(shown), n=len(lines),
                                   keys=t("keys_scroll")), "dim"))
        ui.draw(ui.panel(panel, ui.WIDE))
        status = ""

        key = ui.read_key()
        if key in ("q", "esc", "quit"):
            return
        if key == "down":
            page = top + 1
        elif key == "up":
            page = max(0, top - 1)
        elif key == "right":
            page = top + body
        elif key == "left":
            page = max(0, top - body)
        elif key == "s":
            status = save_script(session, text)


def save_script(session: Session, text: str | None = None) -> str:
    """Write the script out where the operator asks. Returns a status line."""
    if not session.profile:
        return "! нечего сохранять - трафик не собран"
    text = text if text is not None else codegen.generate(session.profile)
    default = session.script_dir / codegen.script_name(session.profile)
    typed = ui.ask_line(t("script_where", default=default))
    path = Path(typed) if typed else default
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)
    except OSError as exc:
        return f"! не записать {path}: {exc}"
    return t("script_saved", path=path)


# --------------------------------------------------------------------------- #
# The run
# --------------------------------------------------------------------------- #
def run_screen(session: Session, dry_run: bool = False) -> None:
    """Ask how long, send, watch, then show the result."""
    if not session.profile:
        return
    problems = session.profile.validate() + session.target.validate()
    if problems:
        _problem_panel(problems)
        return

    spec = RunSpec(duration=10.0, dry_run=dry_run, save_pcap=True)
    if not dry_run:
        typed = ui.ask_line(t("how_long", default=f"{spec.duration:g}"))
        if typed:
            try:
                spec.duration = max(0.1, float(typed.replace(",", ".")))
            except ValueError:
                _problem_panel([t("bad_input", what=typed)])
                return

    live = _Live(session, spec)
    result = live.go()
    if result is None:
        return
    session.remember_run(session.profile.name, result.summary())
    result_screen(result)


class _Live:
    """Runs the profile on a worker thread and repaints while it goes.

    The run has to happen off the drawing thread: it blocks on a socket for as
    long as the traffic lasts, and a screen that stops repainting for ten
    seconds is indistinguishable from one that has hung.
    """

    def __init__(self, session: Session, spec: RunSpec):
        self.session = session
        self.spec = spec
        self.state: dict[str, Any] = {"stage": t("run_building"), "tx": 0,
                                      "rx": 0, "t": 0.0, "pps": 0.0}
        self.result: RunResult | None = None
        self.error = ""

    def on_event(self, event: dict[str, Any]) -> None:
        kind = event.get("ev")
        if kind == "stream":
            self.state["stage"] = f"{t('run_building')} {event.get('name', '')}"
        elif kind == "ready":
            self.state["stage"] = t("run_sending")
        elif kind == "tick":
            self.state.update(tx=event.get("tx", 0), rx=event.get("rx", 0),
                              t=event.get("t", 0.0), pps=event.get("pps", 0.0))
        elif kind == "done":
            self.state["stage"] = t("run_done")
            self.state.update(tx=event.get("tx", 0), rx=event.get("rx", 0))

    def _work(self) -> None:
        try:
            self.result = do_run(
                self.session.profile, self.session.target, self.spec,
                on_event=self.on_event, password=self.session.password,
                transport=self.session.transport,
                # Обычная стендовая машина не пускает sudo без пароля, и без
                # него прогон падал ещё до старта скрипта. Пароль берётся из
                # окружения и здесь не хранится - см. transport.SUDO_PASSWORD_ENV.
                sudo_password=sudo_password())
        except TransportError as exc:
            self.error = str(exc)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"

    def go(self) -> RunResult | None:
        worker = threading.Thread(target=self._work, daemon=True)
        worker.start()
        try:
            while worker.is_alive():
                ui.draw(self._panel())
                time.sleep(0.25)
        except KeyboardInterrupt:
            # The script's own SIGINT handling stops the send loop and prints a
            # done event, so waiting a moment usually still yields a result.
            self.state["stage"] = t("run_stopped")
            ui.draw(self._panel())
            worker.join(timeout=10)
        worker.join(timeout=1)
        ui.draw(self._panel())

        if self.error:
            _problem_panel([t("run_failed"), self.error])
            return None
        return self.result

    def _panel(self) -> str:
        s = self.state
        session = self.session
        head = t("run_head", name=session.profile.name if session.profile else "",
                 target=session.target.endpoint())
        elapsed = float(s["t"] or 0.0)
        fraction = min(1.0, elapsed / self.spec.duration) if self.spec.duration else 0.0

        lines: list[str] = [ui.c(head, "title"),
                            ui.c("  " + str(s["stage"]), "dim"), None]  # type: ignore[list-item]
        lines.append("  " + ui.bar(fraction, 44) + f"  {elapsed:5.1f} c")
        lines.append("")
        lines.append(_counter(t("l_sent"), f"{int(s['tx']):,}".replace(",", " ")))
        if session.target.measures_rx():
            lines.append(_counter(t("l_recv"), f"{int(s['rx']):,}".replace(",", " ")))
            lost = max(0, int(s["tx"]) - int(s["rx"]))
            share = (lost / s["tx"] * 100.0) if s["tx"] else 0.0
            lines.append(_counter(t("l_loss"), f"{lost:,} ({share:.2f}%)".replace(",", " ")))
        else:
            lines.append(_counter(t("l_recv"), ui.c(t("l_unmeasured"), "warn")))
        lines.append(_counter(t("l_rate"), f"{float(s['pps']):,.0f} pps".replace(",", " ")))
        lines.append("")
        lines.append(ui.c("  " + t("keys_run"), "dim"))
        return ui.panel(lines, ui.WIDE)


def _counter(label: str, value: str) -> str:
    return f"  {ui.pad(label, 16)} {ui.c(value, 'title')}"


# --------------------------------------------------------------------------- #
# The result
# --------------------------------------------------------------------------- #
def result_screen(result: RunResult) -> None:
    """What the run produced, with every caveat spelled out rather than implied."""
    lines: list[str] = [
        ui.c(t("run_done") if result.ok else t("run_failed"),
             "ok" if result.ok else "bad"),
        ui.c(f"  {result.profile} → {result.target} · {result.transport}", "dim"),
        None,  # type: ignore[list-item]
        _counter(t("l_sent"), f"{result.tx_pkts:,}".replace(",", " ")
                 + f"  ({result.tx_bytes / 1e6:.1f} МБ)"),
    ]
    count = f"{result.rx_pkts:,}".replace(",", " ")
    if result.reliable:
        lines.append(_counter(t("l_recv"), count))
        role = "ok" if result.loss_pct < 0.01 else "warn" if result.loss_pct < 1 else "bad"
        lines.append(_counter(t("l_loss"),
                              ui.c(f"{result.loss_pkts} ({result.loss_pct:.3f}%)", role)))
    elif result.rx_source == "none":
        lines.append(_counter(t("l_recv"), ui.c(t("l_unmeasured"), "warn")))
    else:
        # Измерено, но веры нет. Писать тут «не мерялось» значило спорить с
        # предупреждением строкой ниже, которое ту же цифру и цитирует: на
        # стенде экран сообщал «принято: не мерялось», а под ним стояло
        # «принято больше, чем отправлено (142 250 747)».
        lines.append(_counter(t("l_recv"), count + ui.c(
            f"   {t('l_approx')} ({result.rx_source})", "warn")))
        if result.rx_pkts <= result.tx_pkts:
            lines.append(_counter(t("l_loss"), ui.c(
                f"{result.loss_pkts} ({result.loss_pct:.3f}%)   "
                f"{t('l_approx')}", "warn")))
    lines.append(_counter(t("l_rate"),
                          f"{result.achieved_pps:,.0f} pps".replace(",", " ")
                          + (f"  из {result.requested_pps:,.0f} запрошенных".replace(",", " ")
                             if result.requested_pps else "")))
    lines.append(_counter(t("l_elapsed"), f"{result.seconds:.1f} c"))

    warnings = result.warnings()
    # The note is usually the reason a warning gives, so printing both would
    # say the same thing twice at different widths.
    note = result.note if result.note and not any(result.note in w
                                                  for w in warnings) else ""
    if warnings or note:
        lines.append("")
    for chunk in _wrap(note, ui.WIDE - 4) if note else []:
        lines.append(ui.c("  " + chunk, "dim"))
    for warning in warnings:
        for chunk in _wrap(f"• {warning}", ui.WIDE - 4):
            lines.append(ui.c("  " + chunk, "warn"))
    if result.run_dir:
        lines.append("")
        # Only the run's own directory: the full state path is long, constant,
        # and not what anyone is looking for on this screen.
        where = "…/" + "/".join(Path(result.run_dir).parts[-2:])
        lines.append(ui.c("  " + t("run_archive", path=where), "dim"))
    lines.append("")
    lines.append(ui.c("  " + t("keys_any"), "dim"))
    ui.notice(lines, ui.WIDE)


def _wrap(text: str, width: int) -> list[str]:
    """Fold a long warning onto the panel, indenting the continuation."""
    words = text.split()
    out: list[str] = []
    line = ""
    for word in words:
        candidate = f"{line} {word}".strip()
        if ui.width_of(candidate) > width and line:
            out.append(line)
            line = "  " + word
        else:
            line = candidate
    if line:
        out.append(line)
    return out


def _problem_panel(problems: list[str]) -> None:
    lines: list[str] = [ui.c(t("problems"), "bad"), ""]
    for problem in problems:
        for chunk in _wrap(f"• {problem}", ui.WIDE - 4):
            lines.append(ui.c("  " + chunk, "warn"))
    lines += ["", ui.c("  " + t("keys_any"), "dim")]
    ui.notice(lines, ui.WIDE)


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #
def history_screen(session: Session) -> None:
    """The archived runs, newest first, with the same honesty about loss."""
    del session
    runs = recent_runs(12)
    lines: list[str] = [ui.c(t("history_head"), "title"), None]  # type: ignore[list-item]
    if not runs:
        lines.append(ui.c("  " + t("history_empty"), "dim"))
    for run in runs:
        stamp = str(run.get("started_at", ""))[:16]
        name = str(run.get("profile", ""))
        tx = int(run.get("tx_pkts", 0))
        if run.get("reliable"):
            tail = f"потери {float(run.get('loss_pct', 0.0)):.2f}%"
        else:
            tail = ui.c("приём не мерян", "warn")
        lines.append(f"  {ui.pad(stamp, 17)}{ui.pad(name, 16)}"
                     f"{ui.pad(f'tx {tx:,}'.replace(',', ' '), 14)}{tail}")
    lines += ["", ui.c("  " + t("keys_any"), "dim")]
    ui.notice(lines, ui.WIDE)
