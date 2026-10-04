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

import math
import sys
import threading
import time
from pathlib import Path
from typing import Any

from traphy import codegen, engines, ui
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
    # У выбранного движка, не у генератора Scapy. Иначе на цели с TRex этот
    # экран показывал скрипт, который на ней никогда не исполнится, - а прогон
    # рядом брал правильный движок, и расхождение было видно только по итогу.
    engine = engines.get(session.target.engine)
    text = _artefact(engine, session)
    if text is None:
        return
    lines = text.splitlines()
    head = t("script_head", name=engine.script_name(session.profile),
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
        # Подвал разворачивается в столько строк, сколько нужно: по-русски он
        # длиннее панели, и обрезался ровно на «q назад» - единственном
        # указании, как уйти с экрана.
        panel.extend(ui.hint_rows(t("script_pager", a=top + 1,
                                    b=top + len(shown), n=len(lines),
                                    keys=t("keys_scroll")), ui.WIDE))
        ui.draw(ui.panel(panel, ui.WIDE))
        status = ""

        key = ui.read_key()
        if key in ("q", "esc", "quit"):
            return
        if key == "down":
            page = top + 1
        elif key == "up":
            page = max(0, top - 1)
        elif key in ("right", "pgdn"):
            # PageDown - первое, что пробует рука на пейджере. Раньше эта
            # клавиша разбиралась как Esc и закрывала экран.
            page = top + body
        elif key in ("left", "pgup"):
            page = max(0, top - body)
        elif key == "home":
            page = 0
        elif key == "end":
            page = max(0, len(lines) - body)
        elif key == "s":
            status = save_script(session, text)


def _artefact(engine: engines.Engine, session: Session) -> str | None:
    """The artefact for this target, or None after saying why there is none.

    A declared-but-unimplemented engine refuses here, and the refusal already
    carries what to do about it - which is a panel, not a traceback.
    """
    try:
        return engine.generate(session.profile, tag=codegen.DEFAULT_TAG)
    except engines.EngineNotReady as exc:
        _problem_panel([str(exc)])
        return None


def save_script(session: Session, text: str | None = None) -> str:
    """Write the script out where the operator asks. Returns a status line.

    Refuses on the same grounds the run refuses. The stream screen says "все
    потоки выключены - слать нечего" and the dry run declines, while saving
    wrote the file and reported "записано: scripts/imix.py" - with
    ``STREAMS = [ # профиль пуст ]`` inside it. An artefact that cannot send is
    not a saved script, it is a file that will be run on a target and do
    nothing.
    """
    if not session.profile:
        return "! нечего сохранять - трафик не собран"
    problems = session.profile.validate()
    if problems:
        return "! " + problems[0]
    engine = engines.get(session.target.engine)
    if text is None:
        try:
            text = engine.generate(session.profile, tag=codegen.DEFAULT_TAG)
        except engines.EngineNotReady as exc:
            return f"! {exc}"
    default = session.script_dir / engine.script_name(session.profile)
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
# Сколько секунд гнать, если ничего не ввели.
_DEFAULT_SECONDS = 10.0
# Потолок на длительность. "100000" - это 28 часов на общем генераторе, и
# раньше оно принималось молча; "-5" и "0" молча становились 0.1 секунды.
_MAX_SECONDS = 3600.0
# Выше этого прогон подтверждают отдельно: лишний ноль набирается одной
# клавишей, а порты стенда заняты всё это время.
_CONFIRM_SECONDS = 300.0


def run_screen(session: Session, dry_run: bool = False) -> None:
    """Ask how long, send, watch, then show the result."""
    if not session.profile:
        return
    problems = session.profile.validate() + session.target.validate()
    if problems:
        _problem_panel(problems)
        return

    spec = RunSpec(duration=_DEFAULT_SECONDS, dry_run=dry_run, save_pcap=True)
    if not dry_run:
        seconds = _ask_duration(spec.duration)
        if seconds is None:
            return
        spec.duration = seconds

    live = _Live(session, spec)
    result = live.go()
    if result is None:
        return
    session.remember_run(session.profile.name, result.summary())
    result_screen(result, built=live.built)


def _ask_duration(default: float) -> float | None:
    """How many seconds to send for, or None when the operator backed out.

    ``ui.ask_line`` cannot be used here, and the reason is the whole point of
    this function: it turns Ctrl-C and EOF into "", and "" on this prompt means
    "take the default" - so the one gesture a person reaches for to change
    their mind started a ten-second run on a shared generator instead. Nothing
    in the prompt mentioned cancelling, either.
    """
    question = t("how_long", default=f"{default:g}")
    complaint = ""
    while True:
        # Подсказка про отмену - своей фразой перед вопросом: сам вопрос живёт в
        # словаре и переводится, а про отмену в словарной формулировке не
        # сказано вовсе - см. просьбу к strings.py в отчёте.
        typed = _read_line(f"{complaint}Ctrl-C - отмена; {question}")
        if typed is None:
            return None
        if not typed.strip():
            return default
        seconds, complaint = _as_seconds(typed)
        if seconds is None:
            continue
        if seconds > _CONFIRM_SECONDS and not _confirm_long(seconds):
            complaint = ""
            continue
        return seconds


def _as_seconds(typed: str) -> tuple[float | None, str]:
    """Введённое как длительность, либо жалоба, с которой спросят снова.

    Отказ, а не поправка: молча превратить "-5" в 0.1 секунды - значит провести
    прогон, которого не просили, и записать его как заказанный.
    """
    try:
        seconds = float(typed.strip().replace(",", "."))
    except ValueError:
        return None, t("bad_input", what=typed.strip()) + "; "
    if not math.isfinite(seconds) or seconds <= 0:
        return None, f"длительность бывает только положительной ({typed.strip()}); "
    if seconds > _MAX_SECONDS:
        # Введённым, а не разобранным: "1e9" в жалобе как "1e+09" читается
        # ответом не на то, что набрали.
        return None, (f"{typed.strip()} c - дольше потолка {_MAX_SECONDS:g} c, "
                      f"а генератор общий; ")
    return seconds, ""


def _confirm_long(seconds: float) -> bool:
    """Долгий прогон подтверждают явно: порты стенда всё это время заняты."""
    answer = ui.notice([
        ui.c(f"  Прогон на {seconds:g} c - это {seconds / 60:.0f} мин", "warn"),
        ui.c("  Столько будут заняты порты генератора, а он общий.", "dim"),
        "",
        ui.c("  y запускать   любая другая клавиша - назад к вопросу", "dim"),
    ], ui.WIDE)
    return answer in ("y", "д")


def _read_line(message: str) -> str | None:
    """One line from the ordinary terminal; None when the person backed out.

    The same thing :func:`traphy.ui.ask_line` does, with one difference that is
    not cosmetic: cancelling is distinguishable from entering nothing.
    """
    ui.leave_screen()
    try:
        return input(message)
    except (EOFError, KeyboardInterrupt):
        return None
    finally:
        ui.enter_screen()


def _drop_typeahead() -> None:
    """Выбросить то, что нажали, пока экран клавиши не читал.

    Прогон крутит отрисовку и ввода не читает, а ``ui.read_key`` намеренно не
    сбрасывает набранное (TCSANOW), чтобы быстрая прокрутка не теряла нажатий.
    Поэтому любая клавиша, нажатая во время прогона, доезжала до экрана итога и
    гасила его в том же кадре: трафик по общему стенду ушёл, а «замер не
    годится» никто не прочитал. Восстановить вердикт можно только из истории.
    """
    if not ui.interactive():
        return
    import termios

    try:
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except (termios.error, OSError, ValueError):
        # Терминал, который не даёт себя чистить, - не причина не показать итог.
        return


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
        # Сколько кадров скрипт собрал, по его же событию "ready". Для холостого
        # прогона это единственная цифра, которая вообще что-то значит, а в
        # результат она не попадает - "done" там приходит с нулями.
        self.built = 0

    def on_event(self, event: dict[str, Any]) -> None:
        kind = event.get("ev")
        if kind == "stream":
            self.state["stage"] = f"{t('run_building')} {event.get('name', '')}"
        elif kind == "ready":
            self.state["stage"] = t("run_sending")
            self.built = int(event.get("frames", 0) or 0)
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
                # Каждый кадр, а не только на выходе: ввод копится в терминале
                # все эти секунды, и накопленного хватает, чтобы погасить итог.
                _drop_typeahead()
                time.sleep(0.25)
        except KeyboardInterrupt:
            # The script's own SIGINT handling stops the send loop and prints a
            # done event, so waiting a moment usually still yields a result.
            self.state["stage"] = t("run_stopped")
            ui.draw(self._panel())
            worker.join(timeout=10)
        worker.join(timeout=1)
        ui.draw(self._panel())
        _drop_typeahead()

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
def result_screen(result: RunResult, built: int = 0) -> None:
    """What the run produced, with every caveat spelled out rather than implied.

    ``built`` is how many frames the script said it assembled. Only a dry run
    needs it: there the counters are all zero by design, and the frames are the
    only thing that happened.
    """
    lines: list[str] = [
        ui.c(t("run_done") if result.ok else t("run_failed"),
             "ok" if result.ok else "bad"),
        ui.c(f"  {result.profile} → {result.target} · {result.transport}", "dim"),
        None,  # type: ignore[list-item]
    ]
    lines.extend(_dry_rows(result, built) if result.dry_run
                 else _sent_rows(result))

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
        lines.append(ui.c("  " + t("run_archive", path=_short_path(result.run_dir)),
                          "dim"))
    lines.append("")
    lines.append(ui.c("  " + t("keys_any"), "dim"))
    # Последнее перед показом: панель ждёт клавишу, а в терминале лежит то, что
    # нажали за время прогона, - и итог гаснет в том же кадре, в котором встал.
    _drop_typeahead()
    ui.notice(lines, ui.WIDE)


def _sent_rows(result: RunResult) -> list[str]:
    """Счётчики прогона, который действительно слал."""
    rows = [_counter(t("l_sent"), f"{result.tx_pkts:,}".replace(",", " ")
                     + f"  ({result.tx_bytes / 1e6:.1f} МБ)")]
    count = f"{result.rx_pkts:,}".replace(",", " ")
    if result.reliable:
        rows.append(_counter(t("l_recv"), count))
        if result.loss_countable:
            role = ("ok" if result.loss_pct < 0.01 else
                    "warn" if result.loss_pct < 1 else "bad")
            rows.append(_counter(t("l_loss"), ui.c(
                f"{result.loss_pkts} ({result.loss_pct:.3f}%)", role)))
        else:
            # Счёт назвал себя надёжным, а принял больше, чем мы послали.
            # Отрицательные потери обрезаются в ноль, и прогон, по которому
            # мерить нечего, выглядел бы здесь образцовым.
            rows.append(_counter(t("l_loss"), ui.c(
                "не считаются - принято больше, чем отправлено", "bad")))
    elif result.rx_source == "none":
        rows.append(_counter(t("l_recv"), ui.c(t("l_unmeasured"), "warn")))
    else:
        # Измерено, но веры нет. Писать тут «не мерялось» значило спорить с
        # предупреждением строкой ниже, которое ту же цифру и цитирует: на
        # стенде экран сообщал «принято: не мерялось», а под ним стояло
        # «принято больше, чем отправлено (142 250 747)».
        rows.append(_counter(t("l_recv"), count + ui.c(
            f"   {t('l_approx')} ({result.rx_source})", "warn")))
        if result.loss_countable:
            rows.append(_counter(t("l_loss"), ui.c(
                f"{result.loss_pkts} ({result.loss_pct:.3f}%)   "
                f"{t('l_approx')}", "warn")))
    rows.append(_counter(t("l_rate"),
                         f"{result.achieved_pps:,.0f} pps".replace(",", " ")
                         + (f"  из {result.requested_pps:,.0f} запрошенных".replace(",", " ")
                            if result.requested_pps else "")))
    rows.append(_counter(t("l_elapsed"), f"{result.seconds:.1f} c"))
    return rows


def _dry_rows(result: RunResult, built: int) -> list[str]:
    """Что холостой прогон сделал на самом деле.

    Подпись у этого прогона - «собрать кадры, ничего не слать», а экран печатал
    «отправлено 0 · скорость 0 pps · прошло 0.0 c»: три нуля вместо
    единственного, что произошло. Кадры при этом собраны и лежат в архиве
    прогона - проверять адреса ходили в profile.json руками.
    """
    rows = [_counter("собрано кадров",
                     f"{built:,}".replace(",", " ") if built
                     else ui.c("скрипт не сказал сколько", "warn")),
            _counter("ушло в кабель", "ничего - это холостой прогон")]
    if result.requested_pps:
        rows.append(_counter(t("l_rate"),
                             f"{result.requested_pps:,.0f} pps".replace(",", " ")
                             + " в профиле - не слали"))
    samples = result.captures.get("streams", "")
    if samples:
        rows.append(_counter("образцы кадров", _short_path(samples)))
    return rows


def _short_path(path: str) -> str:
    """Only the run's own directory: the full state path is long, constant, and
    not what anyone is looking for on this screen."""
    return "…/" + "/".join(Path(path).parts[-2:])


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
# Сколько колонок остаётся вердикту после времени и имени профиля. Своей
# колонки у tx больше нет: «tx 0» было единственным, что экран говорил про
# прогон, упавший до первого кадра, а вердикт на эти колонки не влезал.
_VERDICT_ROOM = ui.WIDE - 2 - 17 - 13


def history_screen(session: Session) -> None:
    """The archived runs, newest first, with the same honesty about loss."""
    del session
    runs = recent_runs(12)
    lines: list[str] = [ui.c(t("history_head"), "title"), None]  # type: ignore[list-item]
    if not runs:
        lines.append(ui.c("  " + t("history_empty"), "dim"))
    for run in runs:
        stamp = str(run.get("started_at", ""))[:16]
        name = ui.trim(str(run.get("profile", "")), 12)
        lines.append(f"  {ui.pad(stamp, 17)}{ui.pad(name, 13)}{_verdict(run)}")
    lines += ["", ui.c("  " + t("keys_any"), "dim")]
    ui.notice(lines, ui.WIDE)


def _verdict(run: dict[str, Any]) -> str:
    """How that run ended, out of the same ``result.json`` the result screen read.

    The archive hands over all of it - ``rc``, ``measurement_valid``,
    ``disqualified`` - and this screen used to read four fields: time, name, tx
    and loss. Nine runs that died on "нет прав на сырой сокет" all looked like
    "tx 0 · приём не мерян", and a verdict lost to a stray keypress during the
    run had nowhere left to be read. This is that place.
    """
    rc = int(run.get("rc", 0) or 0)
    if rc:
        note = str(run.get("note") or "").strip()
        said = f"упал (rc {rc})" + (f": {note}" if note else "")
        return ui.c(ui.trim(said, _VERDICT_ROOM), "bad")
    if run.get("dry_run"):
        return ui.c(ui.trim("холостой - в кабель не ушло ничего",
                            _VERDICT_ROOM), "dim")
    why = [str(x) for x in (run.get("disqualified") or []) if str(x).strip()]
    if why or run.get("measurement_valid") is False:
        head = why[0] if why else "мерить нечем"
        return ui.c(ui.trim(f"ЗАМЕР НЕ ГОДИТСЯ: {head}", _VERDICT_ROOM), "warn")
    # Дальше прогон нормальный, и tx тут - новость, а не заполнение колонки.
    sent = f"tx {int(run.get('tx_pkts', 0) or 0):,}".replace(",", " ")
    loss = run.get("loss_pct")
    if run.get("reliable") and loss is not None:
        return ui.trim(f"{sent} · потери {float(loss):.2f}%", _VERDICT_ROOM)
    # Ни потерь, ни причины их не считать - значит приём не считал никто.
    return f"{sent} · " + ui.c("приём не мерян", "warn")
