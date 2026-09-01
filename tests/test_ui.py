"""Panel geometry: the border must stay straight whatever is inside it."""

from __future__ import annotations

from traphy import ui


def test_display_width_ignores_escapes_and_counts_wide_characters():
    assert ui.width_of("abc") == 3
    assert ui.width_of("\x1b[36mabc\x1b[0m") == 3
    assert ui.width_of("привет") == 6
    assert ui.width_of("日本") == 4


def test_padding_uses_display_width_not_length():
    padded = ui.pad(ui.c("привет", "ok"), 20)
    assert ui.width_of(padded) == 20


def test_trim_adds_an_ellipsis_only_when_it_cut():
    assert ui.trim("короткая", 20) == "короткая"
    cut = ui.trim("очень длинная строка", 10)
    assert cut.endswith("…") and ui.width_of(cut) <= 10


def test_spread_keeps_both_ends_on_one_line():
    line = ui.spread("слева", "справа", 40)
    assert ui.width_of(line) == 40
    assert line.startswith("слева") and line.endswith("справа")


def test_spread_trims_the_left_side_rather_than_pushing_the_border():
    line = ui.spread("о" * 100, "хвост", 30)
    assert ui.width_of(line) == 30
    assert line.endswith("хвост")


def test_every_panel_row_is_the_same_width():
    text = ui.panel([ui.c("заголовок", "title"), None, "  строка",
                     ui.c("  цветная", "ok")], 40)
    widths = {ui.width_of(line) for line in text.splitlines()}
    assert widths == {44}          # 40 inner + two spaces + two borders


def test_an_over_long_row_cannot_break_the_border():
    """Screens hand in paths and foreign error text; geometry is not their job."""
    text = ui.panel(["короткая", "/" + "длинный/" * 40, "х" * 200], 40)
    assert {ui.width_of(line) for line in text.splitlines()} == {44}


def test_a_selected_row_is_repainted_whole():
    """An inner reset would end the highlight partway across the row."""
    painted = ui.selected_row(f"a{ui.c('b', 'ok')}c", 10)
    assert ui.width_of(painted) == 10
    assert ui.strip_ansi(painted).rstrip() == "abc"


def test_bar_is_clamped_to_its_width():
    for fraction in (-1.0, 0.0, 0.5, 1.0, 4.0):
        assert ui.width_of(ui.bar(fraction, 20)) == 20


def test_colour_is_dropped_when_the_terminal_does_not_want_it(monkeypatch):
    monkeypatch.setattr(ui, "use_color", lambda: False)
    assert ui.c("текст", "ok") == "текст"
