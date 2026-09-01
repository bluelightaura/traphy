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


def bar(fraction: float, width: int = 30) -> str:
    """A filled progress bar. Clamped, because callers compute the fraction."""
    fraction = min(1.0, max(0.0, fraction))
    filled = round(fraction * width)
    return c("█" * filled, "ok") + c("░" * (width - filled), "dim")


# --------------------------------------------------------------------------- #
# Screen and input
# --------------------------------------------------------------------------- #
def enter_screen() -> None:
    """Switch to the alternate screen, so the shell scrollback survives."""
    if use_color():
        sys.stdout.write("\x1b[?1049h\x1b[?25l")
        sys.stdout.flush()


def leave_screen() -> None:
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


def read_key() -> str:
    """One keypress as a token: up/down/left/right/enter/esc, or a character.

    Raw mode is entered for exactly one read, so a Ctrl-C or a terminal that
    refuses raw mode surfaces immediately instead of wedging the session.
    """
    import termios
    import tty

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        char = sys.stdin.read(1)
        if char == "\x1b":
            # An arrow arrives as ESC [ A-D; a bare Esc is the key itself.
            seq = sys.stdin.read(2)
            return {"[A": "up", "[B": "down", "[C": "right",
                    "[D": "left"}.get(seq, "esc")
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
    return char.lower()


def ask_line(message: str, secret: bool = False) -> str:
    """Read one line on the normal terminal, leaving the panel behind.

    The alternate screen is dropped for the duration so the person can see what
    they are typing against their own scrollback, then restored.
    """
    leave_screen()
    try:
        if secret:
            import getpass
            return getpass.getpass(message)
        return input(message).strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    finally:
        enter_screen()


def notice(lines: list[str], width: int = WIDTH, wait: bool = True) -> str:
    """Draw a small panel and, by default, wait for a key. Returns that key."""
    draw(panel(lines, width))
    return read_key() if wait and interactive() else ""


def choose(title: str, options: list[tuple[str, str]], cursor: int = 0,
           keys_hint: str = "↑/↓ выбор   ↵ ок   q назад",
           width: int = WIDTH) -> int | None:
    """A small vertical picker. Returns the chosen index, or None on escape.

    Used wherever a screen needs one answer out of a short list and a whole
    screen would be too much - the rate unit, the layer, the TX mode.
    """
    if not interactive():
        return None
    while True:
        lines: list[str] = [c(title, "title"), ""]
        for i, (label, hint) in enumerate(options):
            text = row("▸" if i == cursor else " ", label, c(hint, "dim"), width)
            lines.append(selected_row(text, width) if i == cursor else pad(text, width))
        lines.extend(["", c(keys_hint, "dim")])
        draw(panel(lines, width))
        key = read_key()
        if key == "up":
            cursor = (cursor - 1) % len(options)
        elif key == "down":
            cursor = (cursor + 1) % len(options)
        elif key == "enter":
            return cursor
        elif key in ("q", "esc", "quit", "left"):
            return None
