"""The drawing primitives every screen is built from.

Standard library only - no curses, no third-party UI. That keeps the tool light
and, more usefully, keeps it degrading cleanly: on a terminal that will not go
into raw mode, or a pipe, the panels still print and the caller falls back to
plain prompts instead of dying.

Two ideas run through everything here. Display width is counted with escape
sequences skipped and wide characters counted as two, so a panel's right border
stays straight whatever is inside it. And colour is a *role* - "border", "ok",
"sel" - resolved through the current theme, so switching light and dark is one
table lookup rather than a search for hardcoded escapes.
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata
from collections.abc import Iterable

# The standard inner width of a panel. Wide enough for the Russian labels,
# which run a good deal longer than their English equivalents, and still inside
# the 80 columns a terminal is allowed to be.
WIDTH = 60

# Screens that show a table or a tree need more room than the launcher.
WIDE = 72

_THEMES: dict[str, dict[str, tuple[str, ...]]] = {
    # Cyan frame on a dark background, selection black-on-cyan.
    "dark": {
        "border": ("36",),
        "title": ("1",),
        "dim": ("2",),
        "sel": ("30", "46"),
        "ok": ("1", "32"),
        "warn": ("33",),
        "bad": ("1", "31"),
        "accent": ("35",),
    },
    # Blue frame for a light terminal: a dim cyan washes out on white, and the
    # selection goes white-on-blue so it stays legible.
    "light": {
        "border": ("34",),
        "title": ("1",),
        "dim": ("90",),
        "sel": ("97", "44"),
        "ok": ("1", "32"),
        "warn": ("33",),
        "bad": ("1", "31"),
        "accent": ("35",),
    },
}

_STATE: dict[str, str] = {"theme": "dark"}


def set_theme(name: str) -> None:
    if name in _THEMES:
        _STATE["theme"] = name


def theme() -> dict[str, tuple[str, ...]]:
    return _THEMES[_STATE["theme"]]


def use_color() -> bool:
    """Colour only when a person is looking at a terminal that wants it."""
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, *roles: str) -> str:
    """Paint text in one or more theme roles; a no-op when colour is off."""
    if not roles or not use_color():
        return text
    codes: list[str] = []
    palette = theme()
    for role in roles:
        codes.extend(palette.get(role, ()))
    if not codes:
        return text
    return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"


def strip_ansi(text: str) -> str:
    """Drop SGR escapes, so a row can be repainted in a single background."""
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "\x1b":
            end = text.find("m", i)
            i = len(text) if end == -1 else end + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def width_of(text: str) -> int:
    """Columns the text occupies: escapes free, wide characters two."""
    total = 0
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\x1b":
            end = text.find("m", i)
            i = len(text) if end == -1 else end + 1
            continue
        total += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        i += 1
    return total


def pad(text: str, width: int = WIDTH) -> str:
    return text + " " * max(0, width - width_of(text))


def trim(text: str, width: int) -> str:
    """Cut to at most `width` columns, adding an ellipsis when it had to cut."""
    if width_of(text) <= width:
        return text
    out: list[str] = []
    used = 0
    for char in strip_ansi(text):
        step = 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if used + step > width - 1:
            break
        out.append(char)
        used += step
    return "".join(out) + "…"


def spread(left: str, right: str, width: int = WIDTH) -> str:
    """Left flush, right flush, one line - trimming the left half if needed."""
    gap = width - width_of(left) - width_of(right)
    if gap < 1:
        left = trim(left, max(1, width - width_of(right) - 1))
        gap = 1
    return left + " " * gap + right


# --------------------------------------------------------------------------- #
# Panels
# --------------------------------------------------------------------------- #
def panel(lines: Iterable[str], width: int = WIDTH) -> str:
    """Frame a block of rows. ``None`` in the sequence is a horizontal rule,
    which is how a screen separates a header from its body.

    Rows are trimmed as well as padded. A caller that hands in a long path or
    an error message from somewhere else should not be able to blow the border
    open - and one always eventually does, so the geometry is enforced here
    rather than trusted to every screen.
    """
    top = c("╭" + "─" * (width + 2) + "╮", "border")
    rule = c("├" + "─" * (width + 2) + "┤", "border")
    bottom = c("╰" + "─" * (width + 2) + "╯", "border")
    bar = c("│", "border")
    out = [top]
    for line in lines:
        if line is None:
            out.append(rule)
        else:
            out.append(f"{bar} {pad(trim(line, width), width)} {bar}")
    out.append(bottom)
    return "\n".join(out)


def title_row(name: str, version: str) -> str:
    return c("◈ ", "border") + c(f"{name} {version}", "title")


def row(marker: str, label: str, hint: str, width: int = WIDTH,
        label_width: int = 22) -> str:
    """One menu line: marker, label in a fixed column, hint after it."""
    return f" {marker} {pad(label, label_width)} {hint}"


def selected_row(text: str, width: int = WIDTH) -> str:
    """Repaint a whole row as the current choice.

    Inner escapes are stripped first: a reset in the middle would end the
    highlight there and leave the rest of the row on the normal background.
    """
    return c(pad(strip_ansi(text), width), "sel")


def dim_row(text: str, width: int = WIDTH) -> str:
    return c(pad(strip_ansi(text), width), "dim")


# Промежуток между группами подсказки - два пробела и больше. Внутри группы
# («↑/↓ строка») пробел один, поэтому группа цела; точка-разделитель стоит в
# таких же промежутках и становится отдельной группой, то есть собранная строка
# выглядит ровно как была, пока влезает.
_GAPS = re.compile(r"\s{2,}")


def hint_rows(text: str, width: int = WIDTH, indent: str = "  ",
              role: str = "dim") -> list[str]:
    """The key hint as however many rows it needs, instead of a trimmed one.

    A panel trims what does not fit, and the hint is the one row that must not
    be trimmed: what trimming takes is the tail, and the tail is where "q
    назад" sits - the only thing on the screen saying how to leave. Russian
    hints run longer than the English they were written against, and the script
    footer is already past the 72 columns of a wide panel.

    Rows are broken between key groups, never inside one, so "↑/↓ строка" does
    not end up with its arrows on one line and its noun on the next.
    """
    groups = [g for g in _GAPS.split(strip_ansi(text).strip()) if g]
    if not groups:
        return []
    room = max(1, width - width_of(indent))
    rows: list[str] = []
    line = ""
    for group in groups:
        probe = f"{line}   {group}" if line else group
        if line and width_of(probe) > room:
            rows.append(line)
            line = group
        else:
            line = probe
    rows.append(line)
    return [c(indent + r, role) for r in rows]


def bar(fraction: float, width: int = 30) -> str:
    """A filled progress bar. Clamped, because callers compute the fraction."""
    fraction = min(1.0, max(0.0, fraction))
    filled = round(fraction * width)
    return c("█" * filled, "ok") + c("░" * (width - filled), "dim")


# --------------------------------------------------------------------------- #
# Screen and input
# --------------------------------------------------------------------------- #
# Настройки терминала, какими они были до открытия экрана. Пока экран открыт,
# терминал держится без эха и без построчной буферизации - и это не украшение:
# раньше режим возвращался в исходный после КАЖДОГО нажатия, то есть всё время
# перерисовки терминал эхоил и копил ввод построчно. Клавиша, нажатая в этот
# момент, печаталась поверх панели (`^[[B` посреди меню) и не доходила до
# программы, пока не нажмут Enter. Быстрая прокрутка стрелками теряла нажатия.
#
# Сигналы остаются включёнными, в отличие от полного raw-режима: Ctrl-C
# прерывает как обычно, и терминал, который не даёт себя настроить, отвечает
# отказом сразу, а не вешает сессию.
_cooked: list | None = None


def _hold_keys() -> None:
    """Забрать клавиатуру на время экрана."""
    global _cooked
    if _cooked is not None or not interactive():
        return
    import termios

    fd = sys.stdin.fileno()
    try:
        _cooked = termios.tcgetattr(fd)
        quiet = list(_cooked)
        quiet[3] &= ~(termios.ECHO | termios.ICANON)   # lflag
        quiet[6] = list(quiet[6])                       # cc
        quiet[6][termios.VMIN] = 1
        quiet[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSADRAIN, quiet)
    except termios.error:
        _cooked = None


def _release_keys() -> None:
    """Вернуть клавиатуру оболочке. Обязано отработать и после падения."""
    global _cooked
    if _cooked is None:
        return
    import contextlib
    import termios

    with contextlib.suppress(termios.error):
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _cooked)
    _cooked = None


def enter_screen() -> None:
    """Switch to the alternate screen, so the shell scrollback survives."""
    _hold_keys()
    if use_color():
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        sys.stdout.flush()


def leave_screen() -> None:
    _release_keys()
    if use_color():
        sys.stdout.write("\x1b[?25h\x1b[?1049l")
        sys.stdout.flush()


def draw(text: str) -> None:
    """Repaint the screen from the top. One write, so it does not tear."""
    sys.stdout.write("\x1b[H\x1b[2J" + text + "\n")
    sys.stdout.flush()


def interactive() -> bool:
    """Whether raw-mode key handling is possible at all here."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    try:
        import termios  # noqa: F401
        import tty  # noqa: F401
    except ImportError:
        return False
    return True


# Сколько ждать продолжения escape-последовательности. Стрелка приходит одним
# куском, но по медленной сессии хвост может отстать; за голым Esc не придёт
# ничего и никогда - и прежнее «дочитать ровно два байта» на нём вставало
# насмерть: экран оставался жив, но больше не перерисовывался, а начало
# следующей стрелки уходило в эти два байта.
ESC_WAIT = 0.08

# Байты, прочитанные с клавиатуры, но ещё не разобранные. Одно нажатие приходит
# одним куском, но куском приходят и десять: стрелка - это три байта, и быстрая
# прокрутка попадает в одно чтение. Выбросить лишнее - снова потерять нажатия,
# ровно то, из-за чего тут TCSANOW вместо TCSAFLUSH.
_ahead = bytearray()

# Клавиши, приходящие последовательностью. Разбираются все, которые терминал
# вообще присылает, а не только стрелки: неразобранная последовательность
# раньше превращалась в "esc", то есть PageDown закрывал экран.
_CSI: dict[str, str] = {"A": "up", "B": "down", "C": "right", "D": "left",
                        "H": "home", "F": "end"}
_SS3: dict[str, str] = {"P": "f1", "Q": "f2", "R": "f3", "S": "f4",
                        "A": "up", "B": "down", "C": "right", "D": "left",
                        "H": "home", "F": "end"}
_TILDE: dict[int, str] = {1: "home", 2: "insert", 3: "delete", 4: "end",
                          5: "pgup", 6: "pgdn", 7: "home", 8: "end",
                          11: "f1", 12: "f2", 13: "f3", 14: "f4", 15: "f5",
                          17: "f6", 18: "f7", 19: "f8", 20: "f9", 21: "f10",
                          23: "f11", 24: "f12"}


def _take(fd: int, timeout: float | None) -> int | None:
    """One byte from the keyboard, or None when it did not arrive in time.

    Через ``os.read``, а не ``sys.stdin.read``: текстовый поток дочитывает в
    свой буфер всё, что успело прийти, и ``select`` после этого отвечает
    «пусто», хотя хвост стрелки уже лежит в буфере Python. На таком ответе
    голый Esc и стрелка неразличимы - а различить их тут и надо.
    """
    import select

    if not _ahead:
        if timeout is not None:
            ready, _w, _x = select.select([fd], [], [], timeout)
            if not ready:
                return None
        try:
            chunk = os.read(fd, 64)
        except OSError:
            return None
        if not chunk:
            return None
        _ahead.extend(chunk)
    return _ahead.pop(0)


def _char(fd: int, first: int) -> str:
    """Собрать символ из байтов: «д» - это два байта UTF-8, и половина байта
    не равна ни «д», ни чему-либо ещё, что можно сравнить с клавишей."""
    need = 4 if first >= 0xf0 else 3 if first >= 0xe0 else 2 if first >= 0xc0 else 1
    buf = bytearray([first])
    while len(buf) < need:
        nxt = _take(fd, ESC_WAIT)
        if nxt is None:
            break
        buf.append(nxt)
    return buf.decode("utf-8", "replace")


def _escape(fd: int) -> str:
    """Name the key whose sequence has just started, or "" for one unknown.

    Nothing here may wait for a byte that is not coming: a bare Esc is the
    whole key, and the wait for what follows it is a wait with a deadline.

    Неизвестная последовательность - это "", а не "esc": для экрана "esc"
    значит «закрыться», и PageUp в пейджере закрывал пейджер. То же касается
    Alt с буквой - она приходит как Esc и буква.
    """
    nxt = _take(fd, ESC_WAIT)
    if nxt is None or nxt == 0x1b:
        return "esc"                       # голый Esc - это сама клавиша Esc
    if nxt == 0x5b:                        # '[' - CSI
        params = ""
        while True:
            byte = _take(fd, ESC_WAIT)
            if byte is None:
                return ""                  # последовательность обрубило
            if 0x40 <= byte <= 0x7e:       # финальный байт
                final = chr(byte)
                break
            params += chr(byte)
        if final == "~":
            # Параметры модификаторов идут после ';': Ctrl-PageUp - это тот же
            # PageUp, и ждать от него другого поведения экрану незачем.
            head = params.split(";")[0]
            return _TILDE.get(int(head), "") if head.isdigit() else ""
        return _CSI.get(final, "")
    if nxt == 0x4f:                        # 'O' - SS3: F1-F4 и стрелки
        byte = _take(fd, ESC_WAIT)
        return _SS3.get(chr(byte), "") if byte is not None else ""
    return ""


# Целая последовательность, оставшаяся в прочитанном вперёд. Набранным текстом
# она не является: «[B» от второй стрелки - это два символа, которых человек не
# нажимал, и в пароле их к тому же не видно.
_SEQ = re.compile(r"\x1b(\[[0-9;]*[A-Za-z~]|O.|.)")


def _drain() -> str:
    """Прочитанное вперёд - как текст; буфер при этом пустеет.

    Байты, которые человек успел набрать, уже у нас, и ``input()`` их не
    увидит. Поэтому перед приглашением их отдают ему в начало строки - иначе
    быстрый набор терял бы первые символы значения.
    """
    if not _ahead:
        return ""
    text = _SEQ.sub("", bytes(_ahead).decode("utf-8", "replace"))
    _ahead.clear()
    return "".join(ch for ch in text.replace("\r", "\n")
                   if ch.isprintable() or ch == "\n")


def read_key(timeout: float | None = None, *, keep_case: bool = False) -> str:
    """One keypress as a token: up/down/left/right/enter/esc, or a character.

    A key that arrives as an escape sequence comes back named - "up", "pgup",
    "home", "f5" - and a sequence this does not know comes back as "", not as
    "esc": screens close on "esc", and a key nobody taught them must not close
    anything. A bare Esc is still "esc", because the panels promise it.

    Raw mode is entered for exactly one read, so a Ctrl-C or a terminal that
    refuses raw mode surfaces immediately instead of wedging the session.
    Between reads the terminal stays quiet rather than cooked - see
    :func:`_hold_keys` - so type-ahead is neither echoed nor swallowed.

    With ``timeout`` the wait gives up after that many seconds and returns "".
    That is what lets a screen show something that changes on its own - a link
    indicator, a counter - without a keypress to drive the redraw. Without it
    the loop blocks on input, and anything moving on the screen would freeze
    until the operator happened to touch a key.

    ``keep_case`` hands back a typed character as it was typed. Tokens are
    compared in lower case everywhere, so an ordinary read folds the case; a
    list that lets a value be typed into it must not, or "DUT" would start the
    value off as "dut".
    """
    import termios
    import tty

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        # TCSANOW, а не TCSAFLUSH, который tty.setraw ставит по умолчанию:
        # он выбрасывает уже набранный ввод. То есть каждое чтение клавиши
        # стирало всё, что человек успел нажать, пока рисовался экран -
        # быстрая прокрутка стрелками теряла нажатия и выглядела как залипание.
        tty.setraw(fd, termios.TCSANOW)
        first = _take(fd, timeout)
        if first is None:
            return ""
        if first == 0x1b:
            return _escape(fd)
        char = _char(fd, first)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)

    if char in ("\r", "\n"):
        return "enter"
    if char == "\x7f":
        return "backspace"
    if char == "\x03":
        return "quit"
    if char == "\t":
        return "tab"
    return char if keep_case else char.lower()


def ask_line(message: str, secret: bool = False, prefill: str = "") -> str:
    """Read one line on the normal terminal, leaving the panel behind.

    The alternate screen is dropped for the duration so the person can see what
    they are typing against their own scrollback, then restored.

    ``prefill`` is what was typed before the prompt existed. A letter pressed
    in a value list is how the operator says "none of these, I am typing one",
    and it belongs at the head of the line rather than nowhere.
    """
    leave_screen()
    try:
        prefill += _drain()
        head, newline, _rest = prefill.partition("\n")
        if newline:
            # Enter уже нажат: значение набрали целиком до того, как
            # приглашение появилось, и спрашивать больше нечего.
            return head.strip()
        if secret:
            import getpass
            return (prefill + getpass.getpass(message)).strip()
        return (prefill + input(message + prefill)).strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    finally:
        enter_screen()


def notice(lines: list[str], width: int = WIDTH, wait: bool = True) -> str:
    """Draw a small panel and, by default, wait for a key. Returns that key."""
    draw(panel(lines, width))
    return read_key() if wait and interactive() else ""


def confirm(lines: list[str], width: int = WIDTH) -> bool:
    """Ask a yes/no question on a panel. Only an explicit yes is a yes.

    Enter closes a panel everywhere else in the tool - every other one of them
    says "любая клавиша - назад" - so Enter must not also be the key that
    deletes something. A confirmation any key answers is not a confirmation,
    and a terminal that cannot be read answers no.
    """
    draw(panel(lines, width))
    if not interactive():
        return False
    return read_key() in ("y", "д")


def choose(title: str, options: list[tuple[str, str]], cursor: int = 0,
           keys_hint: str = "↑/↓ выбор   ↵ ок   q назад",
           width: int = WIDTH, typing: bool = False) -> int | str | None:
    """A small vertical picker. Returns the chosen index, or None on escape.

    Used wherever a screen needs one answer out of a short list and a whole
    screen would be too much - the rate unit, the layer, the TX mode.

    With ``typing`` a printable character comes back as itself instead of being
    dropped, and the caller opens a prompt with it. A list of values now stands
    where a bare prompt used to, so the habit is to press Enter and start
    typing - and a list that eats the letters and then accepts whatever the
    cursor sat on tells the operator they changed a value when they did not.

    "q" stays "back" even then, because it says so in the hint; a value that
    starts with it is typed through the "ввести своё" row.
    """
    if not interactive():
        return None
    stray = False          # нажали клавишу, которой у списка нет
    while True:
        lines: list[str] = [c(title, "title"), ""]
        for i, (label, hint) in enumerate(options):
            text = row("▸" if i == cursor else " ", label, c(hint, "dim"), width)
            lines.append(selected_row(text, width) if i == cursor else pad(text, width))
        lines.append("")
        # Молча проигнорированное нажатие выглядит ровно как сломанный экран,
        # поэтому на такое подсказка отвечает хотя бы цветом.
        lines.extend(hint_rows(keys_hint, width, role="warn" if stray else "dim"))
        draw(panel(lines, width))
        key = read_key(keep_case=True) if typing else read_key()
        stray = False
        pressed = key.lower()
        if pressed == "up":
            cursor = (cursor - 1) % len(options)
        elif pressed == "down":
            cursor = (cursor + 1) % len(options)
        elif pressed == "enter":
            return cursor
        elif pressed in ("q", "esc", "quit", "left"):
            return None
        elif typing and len(key) == 1 and key.isprintable():
            return key
        elif key:
            stray = True
