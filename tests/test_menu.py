"""The launcher's rules: what is locked, what is remembered, what it draws."""

from __future__ import annotations

from traphy import menu, presets, prefs, strings, ui
from traphy.models import Profile, Stream
from traphy.session import Session
from traphy.target import Target


def fresh() -> Session:
    session = Session(version="9.9.9")
    session.prefs = dict(prefs.load_prefs())
    return session


def test_wire_rows_are_locked_until_the_target_answers():
    session = fresh()
    session.profile = presets.build("l3_ip")
    run_row = next(r for r in menu.ROWS if r.key == "run")
    assert menu.locked_reason(run_row, session) != ""


def test_composing_rows_are_locked_until_something_is_composed():
    session = fresh()
    for key in ("streams", "script", "save", "dry"):
        row = next(r for r in menu.ROWS if r.key == key)
        assert menu.locked_reason(row, session) == strings.t("no_profile")


def test_setup_and_history_are_always_open():
    session = fresh()
    for key in ("setup", "history"):
        row = next(r for r in menu.ROWS if r.key == key)
        assert menu.locked_reason(row, session) == ""


def test_the_launcher_draws_a_square_panel():
    session = fresh()
    session.profile = presets.build("imix")
    rendered = menu._render(session, cursor=0)
    widths = {ui.width_of(line) for line in rendered.splitlines()}
    assert len(widths) == 1


def test_the_panel_says_what_is_composed_and_how_fast():
    session = fresh()
    session.profile = Profile(name="проба", streams=[Stream(rate_value=2500),
                                                     Stream(enabled=False)])
    text = ui.strip_ansi(menu._render(session, cursor=0))
    assert "проба" in text and "1 из 2 потоков" in text


def test_language_and_theme_survive_a_restart():
    session = fresh()
    menu._cycle("lang", session)
    menu._cycle("theme", session)
    assert session.prefs["theme"] == "light"

    reopened = fresh()
    assert reopened.prefs["lang"] == session.prefs["lang"]
    assert reopened.prefs["theme"] == "light"
    strings.set_lang("ru")
    ui.set_theme("dark")


def test_the_selected_target_is_remembered():
    session = fresh()
    session.remember_target(Target(name="стенд", tx_iface="ens1"))
    assert fresh().prefs["target"] == "стенд"

    reopened = Session()
    reopened.load()
    assert reopened.target.name == "стенд"


def test_changing_the_target_drops_the_old_connection():
    """Otherwise "connected" would keep describing a box we no longer mean."""
    session = fresh()
    session.host = type("H", (), {"ok": True, "hostname": "old", "ifaces": []})()
    session.transport = type("T", (), {"close": lambda self: None})()
    assert session.connected
    session.remember_target(Target(name="другой", host="10.0.0.9", use_ssh=True))
    assert not session.connected


def test_a_finished_run_lands_in_the_history_line():
    session = fresh()
    session.remember_run("ip_sweep", "tx=1000")
    assert "ip_sweep" in fresh().last_run_line()
