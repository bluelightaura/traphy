"""Экран подготовки генератора: разведка, порты, план, согласие, выполнение.

Два режима и граница между ними проходит здесь. Разведка и план не меняют на
машине ничего и доступны всегда. Выполнение - отдельное действие, отдельная
клавиша и отдельное подтверждение, в котором перечислено, что сломается.

Порядок выбора портов - это и есть номера портов TRex: первый отмеченный станет
нулевым. Сказано об этом прямо на экране, потому что несовпадение номера в
конфигурации с номером на коробке стоит полдня и ниоткуда не видно.
"""

from __future__ import annotations

from traphy import provision, ui
from traphy.session import Session
from traphy.strings import t

WIDTH = ui.WIDE if hasattr(ui, "WIDE") else ui.WIDTH


def provision_screen(session: Session) -> None:
    """Подготовить генератор к TRex. Возвращает управление по q."""
    state: dict = {"gen": None, "picked": [], "status": "", "role": "dim",
                   # Чем TRex возьмёт карту. От этого зависит и план, и то,
                   # можно ли вообще трогать карту с текущим сеансом.
                   "mode": provision.DPDK}

    def look() -> None:
        """Спросить генератор. Единственное, что делается само при входе."""
        if not session.connected:
            ok, why = session.connect()
            if not ok:
                state["status"] = why
                state["role"] = "warn"
                return
        ui.draw(ui.panel([ui.c("  опрашиваю генератор...", "dim")], WIDTH))
        gen = provision.survey(session.transport, session.target.trex_dir)
        state["gen"] = gen
        session.generator = gen
        if not gen.ok:
            state["status"] = gen.error
            state["role"] = "warn"
            return
        state["status"] = ""
        state["role"] = "dim"
        # Карты, уже отданные DPDK, - готовый ответ на вопрос «какие порты»:
        # обычно их и настраивали в прошлый раз.
        if not state["picked"]:
            state["picked"] = [n.pci for n in gen.nics if n.on_dpdk][:2]

    look()
    cursor = 0
    while True:
        gen = state["gen"]
        cards = gen.nics if gen and gen.ok else []
        if cards:
            cursor %= len(cards)
        ui.draw(_render(session, state, cursor))
        key = ui.read_key()
        if key in ("q", "esc", "quit", "left"):
            return
        if key == "up" and cards:
            cursor = (cursor - 1) % len(cards)
        elif key == "down" and cards:
            cursor = (cursor + 1) % len(cards)
        elif key in ("enter", " ", "space") and cards:
            _toggle(state, cards[cursor])
        elif key == "m":
            _switch(state)
        elif key == "p":
            look()
        elif key == "k":
            _show_commands(state)
        elif key == "d":
            _do(session, state)


def _switch(state: dict) -> None:
    """Сменить способ, которым TRex берёт карту.

    Это не настройка скорости, а выбор платы: DPDK забирает карту у ядра и
    даёт линейную скорость, AF_PACKET оставляет её ядру и упирается примерно
    в миллион пакетов в секунду. Второе честно работает на ноутбуке и в
    виртуалке - и ровно поэтому его легко принять за первое.
    """
    state["mode"] = (provision.AF_PACKET if state["mode"] == provision.DPDK
                     else provision.DPDK)
    name, cost = provision.MODES[state["mode"]]
    state["status"] = f"{name}: {cost}"
    state["role"] = "dim" if state["mode"] == provision.DPDK else "warn"


def _toggle(state: dict, card: provision.Nic) -> None:
    """Отметить или снять порт. Порядок отметки - это номера портов."""
    picked: list[str] = state["picked"]
    if card.pci in picked:
        picked.remove(card.pci)
        return
    if card.carries_session and state["mode"] == provision.DPDK:
        # Отказ произносится в момент попытки, а не прячется в плане: человек
        # жмёт на эту карту именно потому, что она единственная знакомая.
        state["status"] = (f"через {card.name or card.pci} идёт текущий сеанс - "
                           f"отдать её DPDK значит потерять связь с машиной")
        state["role"] = "warn"
        return
    if len(picked) >= 2:
        state["status"] = "двух портов достаточно: приём и отправка"
        state["role"] = "warn"
        return
    picked.append(card.pci)
    state["status"] = ""
    state["role"] = "dim"


def _plan(state: dict) -> provision.Plan | None:
    gen = state["gen"]
    if not gen or not gen.ok:
        return None
    return provision.build_plan(gen, list(state["picked"]),
                                allow_noiommu=bool(state.get("noiommu")),
                                mode=state["mode"])


def _show_commands(state: dict) -> None:
    """Режим «руками»: те же команды, но выполнять их будет человек."""
    plan = _plan(state)
    if plan is None:
        ui.notice([ui.c("  генератор не опрошен", "warn"), ""], WIDTH)
        return
    lines = [ui.c("  Команды подготовки", "title"), ""]
    if plan.refusals:
        lines += [ui.c("  Это выполнять нельзя:", "warn")]
        lines += [ui.c(f"    · {why}", "warn") for why in plan.refusals] + [""]
    if plan.nothing_to_do:
        lines.append(ui.c("  всё уже сделано - подготавливать нечего", "ok"))
    for step in plan.steps:
        lines.append(ui.c(f"  {step.title}", "title"))
        lines.append(f"    {step.command}")
        if step.reversible:
            lines.append(ui.c(f"    обратно: {step.reversible}", "dim"))
        lines.append("")
    if plan.cfg_text:
        lines.append(ui.c("  Содержимое trex_cfg.yaml:", "title"))
        lines += [f"    {row}" for row in plan.cfg_text.splitlines()]
        lines.append("")
    lines += [ui.c(f"  {note}", "dim") for note in plan.notes]
    lines += ["", ui.c("  " + t("keys_any"), "dim")]
    ui.notice(lines, WIDTH)


def _do(session: Session, state: dict) -> None:
    """Выполнить план - после того, как человек прочитал, чем платит."""
    plan = _plan(state)
    if plan is None:
        ui.notice([ui.c("  генератор не опрошен", "warn"), ""], WIDTH)
        return
    if plan.refusals:
        ui.notice([ui.c("  Подготовить нельзя:", "warn"), ""]
                  + [ui.c(f"    · {why}", "warn") for why in plan.refusals]
                  + ["", ui.c("  " + t("keys_any"), "dim")], WIDTH)
        return
    if plan.nothing_to_do:
        ui.notice([ui.c("  всё уже сделано - подготавливать нечего", "ok"), "",
                   ui.c("  " + t("keys_any"), "dim")], WIDTH)
        return

    ask = [ui.c("  Выполнить на генераторе:", "title"), ""]
    ask += [f"    {i}. {s.title}" for i, s in enumerate(plan.steps, 1)]
    breakage = plan.breakage()
    if breakage:
        ask += ["", ui.c("  Это перестанет работать:", "warn")]
        ask += [ui.c(f"    · {line}", "warn") for line in breakage]
    if plan.notes:
        ask += [""] + [ui.c(f"  {note}", "dim") for note in plan.notes]
    ask.append("")
    if not ui.confirm(ask, WIDTH):
        state["status"] = "подготовка отменена - на генераторе ничего не менялось"
        state["role"] = "dim"
        return

    log: list[str] = []

    def progress(event: dict) -> None:
        if event.get("ev") == "step" and event.get("state") == "start":
            ui.draw(ui.panel([ui.c("  " + str(event.get("title", "")), "title"), "",
                              *[f"  {line}" for line in log[-12:]]], WIDTH))

    ok, log = provision.apply(session.transport, plan,
                              state["gen"].cfg_path, on_event=progress)
    tail = [ui.c("  Готово" if ok else "  Остановлено на отказе",
                 "ok" if ok else "warn"), ""]
    tail += [f"  {line}" for line in log]
    tail += ["", ui.c("  " + t("keys_any"), "dim")]
    ui.notice(tail, WIDTH)
    look_again = provision.survey(session.transport, session.target.trex_dir)
    state["gen"] = look_again
    session.generator = look_again
    state["status"] = "генератор опрошен заново" if look_again.ok else look_again.error
    state["role"] = "ok" if ok else "warn"


def _render(session: Session, state: dict, cursor: int) -> str:
    gen = state["gen"]
    lines = [ui.title_row("Подготовка генератора", session.version), ""]

    if gen is None or not gen.ok:
        lines += [ui.c("  " + (state["status"] or "генератор не опрошен"), "warn"), "",
                  ui.c("  p опросить   q назад", "dim")]
        return ui.panel(lines, WIDTH)

    lines += [ui.c(f"  {line}", "dim") for line in gen.summary()]
    name, cost = provision.MODES[state["mode"]]
    lines.append(ui.c(f"  режим: {name} · {cost}",
                      "title" if state["mode"] == provision.DPDK else "warn"))
    lines.append("")
    lines.append(ui.c("  Карты. Порядок отметки задаёт номера портов TRex:", "title"))
    lines.append(ui.c("  первая отмеченная - порт 0, вторая - порт 1.", "dim"))
    lines.append("")

    picked: list[str] = state["picked"]
    for i, card in enumerate(gen.nics):
        if card.pci in picked:
            marker = f"[{picked.index(card.pci)}]"
        elif card.carries_session and state["mode"] == provision.DPDK:
            marker = " ⊘ "
        else:
            marker = "[ ]"
        text = ui.row(marker, card.describe(), "", WIDTH)
        lines.append(ui.selected_row(text, WIDTH) if i == cursor
                     else ui.pad(text, WIDTH))
        # Предупреждение - отдельной строкой, а не в узкой колонке подсказки:
        # обрезанное «связь оборв…» читается как мелкое замечание, хотя речь
        # о потере доступа к машине.
        # В AF_PACKET карта остаётся в ядре, и «связь оборвётся» там неправда.
        note = (card.warning() if state["mode"] == provision.DPDK
                else ("нагрузка пойдёт в канал управления"
                      if card.carries_session else ""))
        if note:
            lines.append(ui.c(f"      {note}", "warn"))

    plan = _plan(state)
    lines.append("")
    if plan is None or not picked:
        lines.append(ui.c("  порты не выбраны", "dim"))
    elif plan.refusals:
        lines.append(ui.c(f"  подготовить нельзя: {plan.refusals[0]}", "warn"))
    elif plan.nothing_to_do:
        lines.append(ui.c("  всё уже сделано", "ok"))
    else:
        lines.append(ui.c(f"  шагов к выполнению: {len(plan.steps)}", "title"))

    if state["status"]:
        lines += ["", ui.c("  " + state["status"], state["role"])]
    lines += ["", ui.c("  ↑/↓ карта   ↵ отметить   k команды   "
                       "m режим   d готовить   q назад", "dim")]
    return ui.panel(lines, WIDTH)
