"""A field list you can walk with the arrows and edit with Enter.

Both the target form and the packet editor are the same shape: a column of
labelled values, a cursor, and one editing gesture. Rather than writing that
twice, a screen declares its :class:`Field`s - each with a way to read the
current value, a way to accept a new one, and how it is edited - and hands them
to :func:`edit_form`.

Three edit kinds cover everything the tool needs. ``text`` prompts on the
normal terminal, ``toggle`` flips on Enter without leaving the panel, and
``pick`` opens the small chooser. A field can also refuse a value: the setter
returns an error string, the panel shows it, and the old value stays.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field as dc_field

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
class Field:
    """One editable row."""

    key: str
    label: str
    get: Getter
    set: Setter | None = None            # None => read-only row
    kind: str = "text"                   # text | toggle | pick
    options: list[tuple[str, str]] = dc_field(default_factory=list)  # for pick
    secret: bool = False
    hint: str = ""                       # shown dim under the value
    visible: Callable[[], bool] | None = None

    def shown(self) -> bool:
        return self.visible() if self.visible else True

    @property
    def editable(self) -> bool:
        return self.set is not None


def edit_form(title: str, fields: list[Field], *, width: int = ui.WIDTH,
              keys_hint: str = "", header: list[str] | None = None,
              extra_keys: dict[str, Callable[[], str]] | None = None,
              label_width: int = 26) -> None:
    """Run the form until the operator backs out of it.

    ``extra_keys`` maps a keypress to a callback returning a status line, which
    is how a screen adds its own verbs - "c" to check the connection on the
    target form, "space" to toggle a stream - without this function knowing
    what they mean.
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
        ui.draw(_render(title, rows, cursor, status, width, header, keys_hint,
                        label_width))
        status = ""
        key = ui.read_key()

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
        current = next((i for i, (v, _l, _h) in enumerate(_options(f))
                        if v == f.get()), 0)
        picked = ui.choose(f.label, labels, cursor=current,
                           keys_hint=t("keys_pick"), width=width)
        if picked is None:
            return ""
        return f.set(_options(f)[picked][0])
    typed = ui.ask_line(f"{f.label} [{f.get()}]: ", secret=f.secret)
    if typed == "":
        return ""
    return f.set(typed)


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


def _flip(value: str) -> str:
    return t("no") if value == t("yes") else t("yes")


def _render(title: str, rows: list[Field], cursor: int, status: str,
            width: int, header: list[str] | None, keys_hint: str,
            label_width: int) -> str:
    lines: list[str] = [ui.c(title, "title")]
    if header:
        lines.extend(header)
    lines.append(None)  # type: ignore[arg-type]

    for i, f in enumerate(rows):
        marker = "▸" if i == cursor else " "
        value = f.get()
        text = f" {marker} {ui.pad(f.label, label_width)} {value}"
        if i == cursor and f.editable:
            lines.append(ui.selected_row(text, width))
        elif not f.editable:
            lines.append(ui.dim_row(text, width))
        else:
            lines.append(ui.pad(ui.trim(text, width), width))
        if f.hint and i == cursor:
            lines.append(ui.c(" " * (label_width + 4) + f.hint, "dim"))

    lines.append("")
    if status:
        role = "bad" if status.startswith("!") else "ok"
        lines.append(ui.c("  " + status.lstrip("! "), role))
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
