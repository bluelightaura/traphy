"""A field list you can walk with the arrows and edit with Enter.

Both the target form and the packet editor are the same shape: a column of
labelled values, a cursor, and one editing gesture. Rather than writing that
twice, a screen declares its :class:`Field`s - each with a way to read the
current value, a way to accept a new one, and how it is edited - and hands them
to :func:`edit_form`.

Three edit kinds cover everything the tool needs. ``text`` opens the value
chooser, ``toggle`` flips on Enter without leaving the panel, and ``pick`` opens
the small chooser over a fixed list. A field can also refuse a value: the setter
returns an error string, the panel shows it, and the old value stays.

``text`` used to mean "drop the whole interface and print a bare prompt onto the
scrollback" - for a value that is nearly always either one of two or three usual
ones or the one entered last time. So a text field now offers those first and
keeps typing as the last line of the list rather than the only way in. What has
been entered before is remembered per field, five values deep, and never for a
field marked secret.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field as dc_field

from traphy import prefs as prefs_mod
from traphy import ui
from traphy.strings import t

# What an extra-key callback returns to close the form instead of just
# reporting. A screen uses it for its own "готово" key, which has to leave the
# form the same way backing out does but with the work kept.
FORM_EXIT = "\x00exit"

# A setter returns "" when it accepted the value, or a reason it did not.
Setter = Callable[[str], str]
Getter = Callable[[], str]


@dataclass
class Recall:
    """Значения, которые этот человек уже вводил в поле.

    Обёртка над словарём настроек, а не собственный файл: это та же память
    «не спрашивать дважды», что язык и последняя цель, и лежать ей там же.
    Сохранение - на каждом принятом значении, чтобы плохо закончившийся сеанс
    всё равно помнил.
    """

    prefs: dict
    save: Callable[[], None] | None = None

    def values(self, key: str) -> list[str]:
        recent = self.prefs.get("recent")
        if not isinstance(recent, dict):
            return []
        got = recent.get(key)
        if not isinstance(got, list):
            return []
        return [v for v in got if isinstance(v, str) and v.strip()]

    def add(self, key: str, value: str) -> None:
        prefs_mod.remember_value(self.prefs, key, value)
        if self.save:
            self.save()


# Ноль или один элемент. Ставится сеансом один раз; без него формы работают
# ровно как раньше, только без списка прошлых значений - что и нужно в тестах.
_RECALL: list[Recall] = []


def set_recall(store: Recall | None) -> None:
    """Подключить память значений, которой пользуются формы."""
    _RECALL[:] = [store] if store else []


def recall() -> Recall | None:
    return _RECALL[0] if _RECALL else None


@dataclass
class Field:
    """One editable row."""

    key: str
    label: str
    get: Getter
    set: Setter | None = None            # None => read-only row
    kind: str = "text"                   # text | toggle | pick
    options: list[tuple[str, str]] = dc_field(default_factory=list)  # for pick
    secret: bool = False
    # Обычные значения поля - что предлагается до того, как человек что-либо
    # вводил. Функцией, когда список зависит от состояния: интерфейсы цели
    # известны только после опроса, и посчитанные один раз устареют.
    # Элемент - значение либо пара (значение, пояснение). Пояснение своё нужно
    # там, где оно и есть смысл выбора: у интерфейса это не слово «обычное», а
    # состояние линка и скорость, которые назвала сама цель.
    suggest: tuple = ()  # tuple[str | tuple[str, str], ...] | Callable[[], list]
    # Запоминать принятое значение. Выключено для секретов и там, где прошлое
    # значение ничего не значит.
    remember: bool = True
    # Значение для сравнения и запоминания, когда показ от него отличается:
    # интерфейс показывается как «eno1  (up · 25G)», а сравнивать и запоминать
    # надо «eno1». Без этого в список прошлых значений легли бы подписи.
    raw: Getter | None = None
    # Заголовок группы. Печатается перед первым полем группы и сам полем не
    # является - по нему не встать курсором и его нечего править. Нужен потому,
    # что форма цели описывает две разные вещи - откуда кадры уходят и где их
    # ловят, - и плоским списком из двадцати строк это не читается.
    section: str = ""
    # Строкой - когда пояснение не зависит от значения; функцией - когда
    # зависит. Статическая подсказка под переключателем рассказывает про одно
    # его положение, а видна в обоих, и в одном из них она прямо противоречит
    # тому, что написано рядом.
    hint: str | Callable[[], str] = ""   # shown dim under the value
    visible: Callable[[], bool] | None = None

    def shown(self) -> bool:
        return self.visible() if self.visible else True

    def value(self) -> str:
        """Чем поле является, в отличие от того, как оно показано."""
        return (self.raw() if self.raw else self.get()) or ""

    @property
    def editable(self) -> bool:
        return self.set is not None


def edit_form(title: str, fields: list[Field], *, width: int = ui.WIDTH,
              keys_hint: str = "",
              header: list[str] | Callable[[], list[str]] | None = None,
              extra_keys: dict[str, Callable[[], str]] | None = None,
              label_width: int = 26, tick: float | None = None) -> None:
    """Run the form until the operator backs out of it.

    ``extra_keys`` maps a keypress to a callback returning a status line, which
    is how a screen adds its own verbs - "c" to check the connection on the
    target form, "space" to toggle a stream - without this function knowing
    what they mean.

    ``tick`` redraws every that many seconds even when nobody pressed anything,
    which is what a header showing something live needs. Without it the loop
    blocks on input and a link indicator would sit frozen until a key was
    touched - looking exactly as confident as a working one.
    """
    if not ui.interactive():
        return
    cursor = 0
    status = ""
    while True:
        rows = [f for f in fields if f.shown()]
        if not rows:
            return
        cursor = max(0, min(cursor, len(rows) - 1))
        drawn = header() if callable(header) else header
        ui.draw(_render(title, rows, cursor, status, width, drawn, keys_hint,
                        label_width))
        key = ui.read_key(tick)
        if not key:
            # Таймаут: перерисовать и всё. Статус при этом не гаснет - иначе
            # сообщение об ошибке исчезало бы быстрее, чем его прочитают.
            continue
        status = ""

        if key in ("q", "esc", "quit"):
            return
        if key == "up":
            cursor = (cursor - 1) % len(rows)
        elif key == "down":
            cursor = (cursor + 1) % len(rows)
        elif key == "enter":
            status = _activate(rows[cursor], width)
        elif extra_keys and key in extra_keys:
            status = extra_keys[key]()
            if status == FORM_EXIT:
                return


def _activate(f: Field, width: int) -> str:
    """Edit one field. Returns a status line, empty when nothing to say."""
    if not f.editable:
        return ""
    if f.kind == "toggle":
        return f.set(_flip(f.get()))
    if f.kind == "pick":
        labels = [(label, hint) for _value, label, hint in _options(f)]
        # По значению, а не по показанной строке: поле показывает «Scapy», а
        # пунктом является «scapy», и сравнение с показом всегда промахивалось -
        # курсор вставал на первый пункт вместо текущего.
        current = next((i for i, (v, _l, _h) in enumerate(_options(f))
                        if v == f.value()), 0)
        picked = ui.choose(f.label, labels, cursor=current,
                           keys_hint=t("keys_pick"), width=width)
        if picked is None:
            return ""
        return f.set(_options(f)[picked][0])
    return _edit_text(f, width)


def _edit_text(f: Field, width: int) -> str:
    """Выбрать значение или набрать своё, не выходя из панели.

    Пустой список с одним пунктом «ввести своё» был бы лишним экраном на пути к
    тому же вводу, поэтому когда предлагать нечего - сразу ввод.
    """
    current = f.value().strip()
    standard = [(v, note) for v, note in _suggested(f) if v]
    known = {v for v, _ in standard}
    past = [(v, t("v_recent")) for v in _remembered(f) if v and v not in known]
    if not standard and not past:
        return _type_in(f)

    options: list[tuple[str, str]] = []
    values: list[str | None] = []
    for value, note in standard + past:
        options.append((value, t("v_current") if value == current else note))
        values.append(value)
    options.append((t("v_own"), t("v_own_hint")))
    values.append(None)

    cursor = values.index(current) if current in values else 0
    picked = ui.choose(f.label, options, cursor=cursor,
                       keys_hint=t("keys_value"), width=width)
    if picked is None:
        return ""
    chosen = values[picked]
    return _type_in(f) if chosen is None else _accept(f, chosen)


def _type_in(f: Field) -> str:
    # У секрета текущее значение в приглашении не показываем даже подписью.
    prompt = f"{f.label}: " if f.secret else f"{f.label} [{f.value()}]: "
    typed = ui.ask_line(prompt, secret=f.secret)
    if typed == "":
        return ""
    return _accept(f, typed)


def _accept(f: Field, value: str) -> str:
    """Отдать значение полю и запомнить, если оно его приняло.

    Запоминается то, что осталось в поле, а не то, что набрали: сеттер, который
    приводит значение к виду - опускает регистр MAC, обрезает путь, - иначе
    оставил бы в списке два написания одного значения.
    """
    error = f.set(value)
    if error:
        return error
    if f.remember and not f.secret:
        store = recall()
        if store:
            store.add(f.key, f.value() or value)
    return ""


def _suggested(f: Field) -> list[tuple[str, str]]:
    """Обычные значения поля как пары (значение, пояснение)."""
    got = f.suggest() if callable(f.suggest) else f.suggest
    out: list[tuple[str, str]] = []
    for item in (got or ()):
        if isinstance(item, (tuple, list)) and len(item) == 2:
            out.append((str(item[0]), str(item[1])))
        else:
            out.append((str(item), t("v_standard")))
    return out


def _remembered(f: Field) -> list[str]:
    if f.secret or not f.remember:
        # У секрета памяти нет ни на запись, ни на чтение: список прошлых
        # паролей на экране - это ровно то, чего быть не должно.
        return []
    store = recall()
    return store.values(f.key) if store else []


def _options(f: Field) -> list[tuple[str, str, str]]:
    """Normalise a pick field's options to (value, label, hint) triples."""
    out: list[tuple[str, str, str]] = []
    for item in f.options:
        if len(item) == 3:
            out.append(item)  # type: ignore[arg-type]
        else:
            value, label = item
            out.append((value, label, ""))
    return out


def _fold(text: str, width: int) -> list[str]:
    """Разложить строку по ширине панели, не разрывая слов."""
    out: list[str] = []
    line = ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        out.append(line)
    return out or [""]


def _flip(value: str) -> str:
    return t("no") if value == t("yes") else t("yes")


def _render(title: str, rows: list[Field], cursor: int, status: str,
            width: int, header: list[str] | None, keys_hint: str,
            label_width: int) -> str:
    lines: list[str] = [ui.c(title, "title")]
    if header:
        lines.extend(header)
    lines.append(None)  # type: ignore[arg-type]

    group = ""
    for i, f in enumerate(rows):
        if f.section and f.section != group:
            if i:
                lines.append("")
            lines.append(ui.c("  " + f.section, "dim"))
        group = f.section or group
        marker = "▸" if i == cursor else " "
        value = f.get()
        text = f" {marker} {ui.pad(f.label, label_width)} {value}"
        if i == cursor and f.editable:
            lines.append(ui.selected_row(text, width))
        elif not f.editable:
            lines.append(ui.dim_row(text, width))
        else:
            lines.append(ui.pad(ui.trim(text, width), width))
        text = f.hint() if callable(f.hint) else f.hint
        if text and i == cursor:
            # Переносом, как и строка состояния: подсказка объясняет, чем
            # грозит неверное значение, и грозное стоит в конце - «приём будет
            # нулевой» обрезалось ровно на этом месте.
            pad = " " * (label_width + 4)
            for chunk in _fold(text, width - len(pad)):
                lines.append(ui.c(pad + chunk, "dim"))

    lines.append("")
    if status:
        role = "bad" if status.startswith("!") else "ok"
        # Переносом, а не обрезкой. Сообщение тут несёт не «что случилось», а
        # «что делать» - и ровно эта часть стоит в конце, то есть обрезка
        # съедала единственное полезное: «…— p подхватит».
        for line in _fold(status.lstrip("! "), width - 4):
            lines.append(ui.c("  " + line, role))
    lines.append(ui.c("  " + (keys_hint or t("keys_form")), "dim"))
    return ui.panel(lines, width)


# --------------------------------------------------------------------------- #
# Parsers shared by the forms
# --------------------------------------------------------------------------- #
def as_int(value: str, lo: int, hi: int, what: str) -> tuple[int, str]:
    """Parse an integer inside a range. Returns (value, error-or-empty)."""
    try:
        n = int(value.strip())
    except ValueError:
        return 0, f"! {what}: нужно целое число"
    if not lo <= n <= hi:
        return 0, f"! {what}: допустимо {lo}..{hi}"
    return n, ""


def as_float(value: str, what: str, minimum: float = 0.0) -> tuple[float, str]:
    try:
        x = float(value.strip().replace(",", "."))
    except ValueError:
        return 0.0, f"! {what}: нужно число"
    if x <= minimum:
        return 0.0, f"! {what}: должно быть больше {minimum:g}"
    return x, ""


def as_mac(value: str, what: str) -> tuple[str, str]:
    """Accept a MAC in the usual colon form, and nothing else."""
    parts = value.strip().lower().replace("-", ":").split(":")
    if len(parts) != 6 or not all(len(p) == 2 and _hex(p) for p in parts):
        return "", f"! {what}: нужен MAC вида 00:11:22:33:44:55"
    return ":".join(parts), ""


def _hex(text: str) -> bool:
    return all(ch in "0123456789abcdef" for ch in text)


def as_ip(value: str, what: str) -> tuple[str, str]:
    import ipaddress
    try:
        return str(ipaddress.IPv4Address(value.strip())), ""
    except ipaddress.AddressValueError:
        return "", f"! {what}: нужен адрес IPv4"
