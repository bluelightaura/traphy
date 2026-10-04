"""The launcher: the panel a person lands on and everything it opens.

Rows that touch the wire are locked until the target has actually answered.
That is not decoration - "Запустить" on an unreachable box fails after a
ten-second SSH timeout with a paramiko message, and a padlock with a reason
next to it is a better answer than a stack trace later.

Every screen is guarded. A screen that raises draws a panel saying what broke
and returns to the launcher, because dropping to the shell from an alternate
screen leaves a terminal with no cursor and no explanation. A loop that fails
repeatedly gives up rather than spinning forever on a terminal that can no
longer be read.
"""

from __future__ import annotations

import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from traphy import prefs as prefs_mod
from traphy import strings, ui
from traphy.screens import compose as compose_screens
from traphy.screens import connect as connect_screens
from traphy.screens import execute as execute_screens
from traphy.screens import provision as provision_screens
from traphy.session import Session
from traphy.strings import t

# How many failures in a row the launcher absorbs before it lets the error out.
# Without it, a terminal that can no longer be read would redraw a panel nobody
# can answer - a hang instead of a crash, which is worse.
CRASH_LIMIT = 3


@dataclass(frozen=True)
class Row:
    """One launcher line."""

    key: str
    action: Callable[[Session], None] | None = None
    needs_link: bool = False        # locked until the target answered
    needs_traffic: bool = False     # locked until something is composed
    # Заперто, пока выбранный движок объявлен, но не реализован. Без этого
    # признака замок был только на связи, и «Запустить» на цели с JMeter
    # сообщал «сначала проверь связь с целью» - про то, что вообще ни при чём.
    needs_engine: bool = False
    # Подготовка - про DPDK, большие страницы и демона. У Scapy ничего этого
    # нет, и строка, открывающая пустой экран, хуже отсутствующей.
    needs_trex: bool = False
    cycles: bool = False            # a preference row, not a screen
    # Заголовок раздела. Печатается перед первой строкой раздела и сам строкой
    # не является: по нему не встать курсором и нечего открыть.
    section: str = ""

    def title(self) -> str:
        return t(f"{self.key}_title")

    def hint(self) -> str:
        return t(f"{self.key}_hint")


def rows_for(session: Session) -> tuple[Row, ...]:
    """Строки меню в порядке, в котором их делают для этого движка.

    У TRex подготовка генератора идёт прежде настройки цели: номера портов
    берутся из trex_cfg.yaml, а создаёт его подготовка. Выбирать порт до неё
    значит выбирать из пустого списка - и именно так это и выглядело.
    """
    from traphy import engines

    if not engines.get(session.target.engine).prepared_first:
        return ROWS
    order = {"provision": 0, "setup": 1}
    return tuple(sorted(ROWS, key=lambda r: (ROWS.index(r) if r.key not in order
                                             else -10 + order[r.key])))


def _compose(session: Session) -> None:
    profile = compose_screens.compose_screen(session)
    if profile is not None:
        session.remember_profile(profile)
        compose_screens.streams_screen(session)


def _dry(session: Session) -> None:
    execute_screens.run_screen(session, dry_run=True)


def _save(session: Session) -> None:
    status = execute_screens.save_script(session)
    ui.notice([ui.c("  " + status.lstrip("! "),
                    "bad" if status.startswith("!") else "ok"),
               "", ui.c("  " + t("keys_any"), "dim")], ui.WIDE)


# Порядок - это порядок работы: сначала чем и откуда шлём, потом что именно,
# потом прогон. Раньше это был плоский список, в котором цель, кадр и прогон
# лежали вперемешку, и по нему не было видно, на каком ты шаге.
ROWS: tuple[Row, ...] = (
    Row("setup", connect_screens.target_screen, section="sec_gen"),
    Row("provision", provision_screens.provision_screen, needs_trex=True,
        section="sec_gen"),

    Row("compose", _compose, section="sec_what"),
    Row("streams", compose_screens.streams_screen, needs_traffic=True,
        section="sec_what"),
    # Скрипт, сохранение и прогон - всё, что просит у движка артефакт. У
    # нереализованного его нет, и отказ в середине нажатия хуже замка: он
    # приходит после того, как человек уже решил, что делает.
    Row("script", execute_screens.script_screen, needs_traffic=True,
        needs_engine=True, section="sec_what"),
    Row("save", _save, needs_traffic=True, needs_engine=True,
        section="sec_what"),

    Row("dry", _dry, needs_traffic=True, needs_engine=True, section="sec_run"),
    Row("run", execute_screens.run_screen, needs_link=True, needs_traffic=True,
        needs_engine=True, section="sec_run"),
    Row("history", execute_screens.history_screen, section="sec_run"),

    Row("lang", cycles=True, section="sec_view"),
    Row("theme", cycles=True, section="sec_view"),
)


def _lock(row: Row, session: Session) -> tuple[str, str]:
    """(почему строка заперта, в какой строке меню замок снимается).

    Порядок - это порядок разбирательства. Нереализованный движок идёт первым:
    пока цель слать не умеет, ни собранный трафик, ни связь ничего не меняют, а
    «сначала проверь связь с целью» на цели с JMeter посылает проверять то, что
    ни при чём, - и связь при этом может быть прекрасной.
    """
    if row.needs_trex and session.target.engine != "trex":
        return t("provision_locked"), "setup"
    if row.needs_engine:
        from traphy import engines

        engine = engines.get(session.target.engine)
        if not engine.ready:
            return f"{engine.title}: {t('engine_locked')}", "setup"
    if row.needs_traffic and session.profile is None:
        return t("no_profile"), "compose"
    if row.needs_link and not session.connected:
        return t("locked"), "setup"
    return "", ""


def locked_reason(row: Row, session: Session) -> str:
    """Why this row cannot be used yet, or empty when it can."""
    return _lock(row, session)[0]


def unlock_row(row: Row, session: Session) -> Row | None:
    """The launcher row where this row's lock is lifted, or None.

    A padlock saying "check the target first" names an action, not the screen
    that has it: "c" lives inside the target form and there is no such key out
    here. So the panel points at the row to open, and the operator is not left
    looking for a key the screen does not have.
    """
    where = _lock(row, session)[1]
    return next((r for r in rows_for(session) if r.key == where), None)


def run(version: str = "0.0.0", profile_dir: Path | None = None) -> int:
    """Open the launcher and keep it open until the operator leaves."""
    session = Session(version=version)
    if profile_dir:
        session.profile_dir = profile_dir
    session.load()

    if not ui.interactive():
        print(t("not_a_tty"))
        return 2

    ui.enter_screen()
    session.start_watch()
    cursor = 0
    crashes = 0
    try:
        while True:
            ui.draw(_render(session, cursor))
            # Полсекунды: без таймаута цикл стоит на вводе, и живой индикатор
            # замирал бы до ближайшего нажатия - выглядя при этом ровно так же
            # уверенно, как работающий.
            key = ui.read_key(0.5)
            if not key:
                continue

            # Порядок строк зависит от движка, а движок меняют прямо здесь,
            # в настройке цели. Поэтому список берётся заново на каждом круге,
            # а курсор удерживается в его границах.
            rows = rows_for(session)
            cursor %= len(rows)

            if key in ("q", "quit"):
                return 0
            if key == "up":
                cursor = (cursor - 1) % len(rows)
            elif key == "down":
                cursor = (cursor + 1) % len(rows)
            elif key in ("enter", "right"):
                try:
                    _activate(rows[cursor], session)
                except Exception as exc:
                    crashes += 1
                    _crash_panel(exc)
                    if crashes >= CRASH_LIMIT:
                        raise
    except KeyboardInterrupt:
        return 130
    finally:
        session.stop_watch()
        session.disconnect()
        session.save_prefs()
        ui.leave_screen()


def _activate(row: Row, session: Session) -> None:
    if row.cycles:
        _cycle(row.key, session)
        return
    reason = locked_reason(row, session)
    if reason:
        lines = [ui.c(f"  {row.title()} - {reason}", "warn"), ""]
        where = unlock_row(row, session)
        if where:
            lines += [ui.c(f"  → {where.title()} - {where.hint()}", "title"), ""]
        lines.append(ui.c("  " + t("keys_any"), "dim"))
        ui.notice(lines, ui.WIDE)
        return
    if row.action:
        row.action(session)


def _cycle(key: str, session: Session) -> None:
    """Flip a two-valued preference and remember it immediately."""
    if key == "lang":
        session.prefs["lang"] = strings.toggle_lang()
    elif key == "theme":
        current = str(session.prefs.get("theme", "dark"))
        new = "light" if current == "dark" else "dark"
        session.prefs["theme"] = new
        ui.set_theme(new)
    prefs_mod.save_prefs(session.prefs)


def _render(session: Session, cursor: int) -> str:
    lines: list[str] = [
        ui.title_row("TRaphy", session.version),
        ui.c("  " + _tagline(session), "dim"),
        None,  # type: ignore[list-item]
        ui.c(ui.spread(f"{t('target')}{session.target.endpoint()}",
                       f"({_engine(session)})", ui.WIDTH), "dim"),
    ]
    status, role = session.status_line()
    lines.append(ui.c("  " + status, role))
    # Живая связь отдельной строкой: та, что выше, говорит, что ответило на
    # опрос, и остаётся верной до первого изменения снаружи. Эта говорит, здесь
    # ли машина сейчас.
    ready, ready_role = _generator_line(session)
    # Для движка с подготовкой строка про генератор и есть ответ о связи с ним.
    # Живой индикатор остаётся, только когда ему есть что добавить: на цели с
    # SSH-переходом он меряет настоящий TCP, а на локальной - говорит, что не
    # знает, и две строки «не знаю» подряд читаются как сломанный экран.
    if not (ready and session.watched().is_local):
        live, live_role = session.link_line()
        lines.append(ui.c("  " + live, live_role))
    if ready:
        lines.append(ui.c("  " + ready, ready_role))
    lines.append(ui.c("  " + ui.spread(
        f"{t('profile')}{_profile_line(session)}", "", ui.WIDTH - 2), "dim"))
    last = session.last_run_line()
    if last:
        lines.append(ui.c(f"  ↻ {t('last_run')}: {ui.trim(last, 44)}", "dim"))
    lines.append("")

    group = ""
    for i, row in enumerate(rows_for(session)):
        if row.section and row.section != group:
            if i:
                lines.append("")
            lines.append(ui.c("  " + t(row.section), "dim"))
        group = row.section or group
        lines.append(_row_line(row, session, selected=i == cursor))

    lines.append("")
    lines.extend(ui.hint_rows(t("keys_main"), ui.WIDTH))
    return ui.panel(lines, ui.WIDTH)


def _generator_line(session: Session) -> tuple[str, str]:
    """Готов ли генератор к прогону - для движков, которым его готовят.

    Прежде здесь стояла строка «связь до генератора проверяет опрос цели»,
    верная и бесполезная: она ничего не говорила о том, поднят ли демон и
    отданы ли карты DPDK, а прогон упирается именно в это.
    """
    from traphy import engines

    if not engines.get(session.target.engine).prepared_first:
        return "", "dim"
    gen = session.generator
    if gen is None:
        return "◇ генератор не опрашивался - «Подготовить генератор»", "dim"
    if not getattr(gen, "ok", False):
        return f"✗ генератор: {getattr(gen, 'error', 'не ответил')}", "warn"

    bound = [n for n in gen.nics if n.on_dpdk]
    # Про страницы говорим только когда их нет: строка в шапке короткая, и
    # место в ней достаётся тому, что мешает, а не тому, что в порядке.
    bits = [f"портов DPDK: {len(bound)}"]
    if not gen.hugepages_total:
        bits.append("страниц нет")
    bits.append("демон отвечает" if gen.daemon_running else "демон не поднят")
    role = "ok" if (gen.daemon_running and bound and gen.hugepages_total) else "warn"
    mark = "●" if role == "ok" else "○"

    # Версия - приятно, но не она мешает прогону. Если строка не помещается,
    # обрезать надо её, а не то, что сломано.
    limit = ui.WIDTH - 4
    full = f"{mark} TRex {gen.trex_version} · {' · '.join(bits)}" \
        if gen.trex_version else f"{mark} {' · '.join(bits)}"
    if ui.width_of(full) > limit:
        full = f"{mark} {' · '.join(bits)}"
    return ui.trim(full, limit), role


def _tagline(session: Session) -> str:
    """Чем тут занимаются - словами выбранного движка, а не вообще."""
    from traphy import engines

    return engines.get(session.target.engine).tagline


def _engine(session: Session) -> str:
    """Which generator this target uses - the thing "цель" alone does not say."""
    from traphy import engines

    engine = engines.get(session.target.engine)
    return engine.title if engine.ready else f"{engine.title} ⊘"


def _profile_line(session: Session) -> str:
    if session.profile is None:
        return t("no_profile")
    profile = session.profile
    enabled = len(profile.enabled_streams)
    pps = f"{profile.total_pps(session.target.link_mbit):,.0f}".replace(",", " ")
    # Через словарь, как и всё остальное на этом экране: собранная здесь строка
    # оставалась русской при английском языке, и шапка выглядела полупереведённой.
    line = t("profile_line", name=profile.name, on=enabled,
             all=len(profile.streams), pps=pps)
    # Куда пойдёт трафик - на главном экране, а не только внутри потока. Джун,
    # настроивший перебор адресов, не мог отсюда убедиться, что собрал верно, и
    # каждый раз лазил внутрь. Адрес важнее скорости: ошибка в нём дороже.
    where = compose_screens.destination(profile)
    if where:
        line = f"{line} · {ui.trim(where, 28)}"
    # И признак того, что собранное живёт только в памяти. С виду правишь файл.
    unsaved = compose_screens.unsaved_note(session)
    return f"{line} · {unsaved}" if unsaved else line


def _row_line(row: Row, session: Session, selected: bool) -> str:
    reason = "" if row.cycles else locked_reason(row, session)
    label = row.title()
    hint = row.hint()

    if row.key == "setup":
        # «хост, интерфейсы, связь» верно только для Scapy: у TRex нет
        # интерфейсов, есть индексы портов из trex_cfg.yaml.
        from traphy import engines

        hint = engines.get(session.target.engine).setup_hint

    if row.key == "lang":
        hint = ui.c(strings.lang().upper(), "title")
    elif row.key == "theme":
        hint = ui.c(t("theme_dark") if session.prefs.get("theme", "dark") == "dark"
                    else t("theme_light"), "title")
    elif reason:
        label = f"{label} ⊘"
        hint = reason

    text = ui.row("▸" if selected else " ", label, ui.c(hint, "dim"), ui.WIDTH)
    if reason:
        return ui.dim_row(text, ui.WIDTH)
    if selected:
        return ui.selected_row(text, ui.WIDTH)
    return ui.pad(text, ui.WIDTH)


def _crash_panel(exc: BaseException) -> None:
    """Show a failure as a panel and keep the launcher alive.

    The traceback is written next to the run archives rather than to the
    screen: a person at a menu cannot act on a stack trace, and a file they can
    send on is more use than one they have to photograph.
    """
    path = _write_crash(exc)
    lines = [
        ui.c("  Экран упал", "bad"), "",
        ui.c(f"  {type(exc).__name__}: {exc}", "warn"), "",
    ]
    if path:
        lines.append(ui.c(f"  подробности: {path}", "dim"))
    lines += ["", ui.c("  " + t("keys_any"), "dim")]
    ui.notice(lines, ui.WIDE)


def _write_crash(exc: BaseException) -> Path | None:
    from traphy.target import state_dir

    try:
        path = state_dir() / "errors.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write("".join(traceback.format_exception(exc)) + "\n")
        return path
    except OSError:
        return None
