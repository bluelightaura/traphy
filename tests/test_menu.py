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


# --------------------------------------------------------------------------- #
# Что человек вводил в поле раньше
# --------------------------------------------------------------------------- #
def test_the_newest_value_comes_first():
    p: dict = {}
    for value in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        prefs.remember_value(p, "host", value)
    assert p["recent"]["host"] == ["10.0.0.3", "10.0.0.2", "10.0.0.1"]


def test_a_value_used_again_moves_up_instead_of_doubling():
    """Список - это «чем ты пользуешься». Значение, введённое второй раз,
    вероятнее, а не менее вероятно."""
    p: dict = {}
    for value in ("a", "b", "c", "a"):
        prefs.remember_value(p, "host", value)
    assert p["recent"]["host"] == ["a", "c", "b"]


def test_only_five_are_kept():
    p: dict = {}
    for n in range(9):
        prefs.remember_value(p, "host", f"v{n}")
    assert p["recent"]["host"] == ["v8", "v7", "v6", "v5", "v4"]
    assert len(p["recent"]["host"]) == prefs.MAX_RECENT


def test_nothing_and_whitespace_are_not_values():
    p: dict = {}
    prefs.remember_value(p, "host", "")
    prefs.remember_value(p, "host", "   ")
    prefs.remember_value(p, "", "10.0.0.1")
    assert p.get("recent", {}) == {}


def test_values_are_kept_per_field():
    p: dict = {}
    prefs.remember_value(p, "host", "10.0.0.1")
    prefs.remember_value(p, "python", "python3.9")
    assert p["recent"] == {"host": ["10.0.0.1"], "python": ["python3.9"]}


def test_remembered_values_survive_a_save_and_load():
    p = dict(prefs.load_prefs())
    prefs.remember_value(p, "trex_dir", "/opt/trex-3.08")
    assert prefs.save_prefs(p)
    assert prefs.load_prefs()["recent"]["trex_dir"] == ["/opt/trex-3.08"]


def test_a_mangled_state_file_degrades_to_nothing_remembered():
    """Файл наш, и всё равно читается как чужой: правка руками должна давать
    «ничего не помню», а не падение экрана."""
    path = prefs.state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"recent": {"host": "не список", "ok": ["10.0.0.1", 7]}}',
                    encoding="utf-8")
    loaded = prefs.load_prefs()
    assert loaded["recent"] == {"ok": ["10.0.0.1"]}


def test_the_menu_tells_the_probe_where_the_release_lives(monkeypatch):
    """Найдено на живом генераторе 2026-09-30: демон отвечал, релиз лежал в
    /opt/trex-3.08, а меню сообщало «на цели не видно каталога TRex» и блокировало
    прогон. `inspect()` умеет принимать каталог из цели, CLI его передавал, а
    меню звало без него - то есть из меню цель с TRex не открывалась вовсе.

    Один раз это уже правили, поэтому теперь на это есть тест.
    """
    from traphy import probe, session as session_mod
    from traphy.probe import HostInfo

    seen: dict = {}

    class FakeTransport:
        def close(self) -> None:
            pass

    def fake_inspect(transport, timeout=30, trex_dir=""):
        seen["trex_dir"] = trex_dir
        return HostInfo(ok=True, hostname="tgen", python="3.9")

    monkeypatch.setattr(session_mod, "open_transport",
                        lambda target, password="": FakeTransport())
    monkeypatch.setattr(probe, "inspect", fake_inspect)

    s = fresh()
    s.target = Target(name="bench", engine="trex", use_ssh=True,
                      host="10.0.0.9", trex_dir="/opt/trex-3.08")
    ok, _msg = s.connect()

    assert ok
    assert seen["trex_dir"] == "/opt/trex-3.08", "меню опять не спросило цель"


# --------------------------------------------------------------------------- #
# Живой индикатор связи на главном экране
# --------------------------------------------------------------------------- #
def test_a_local_target_has_no_link_to_watch():
    s = fresh()
    s.target = Target(name="local", use_ssh=False)
    text, role = s.link_line()
    assert "сеть не нужна" in text
    assert role == "dim"


def test_a_target_without_an_address_is_local_by_the_model_and_says_so():
    """Цель без адреса - локальная (Target.is_local), то есть проверять связь
    с ней не нужно и нечего. Отдельной фразы «адрес не задан» тут быть не
    должно: это была бы ветка, в которую не попасть."""
    s = fresh()
    s.target = Target(name="t", use_ssh=True, host="")
    assert "сеть не нужна" in s.link_line()[0]


def test_the_indicator_names_the_machine_it_is_talking_about():
    """На главном экране цель и черновик формы - разные вещи, и человек должен
    видеть, про какую машину строка."""
    from traphy import link

    s = fresh()
    s.target = Target(name="t", use_ssh=True, host="10.0.0.9")
    s.watch = link.Watch(lambda: (True, ""))
    s.watch.measure()
    text, role = s.link_line()
    assert "10.0.0.9" in text
    assert "отвечает" in text
    assert role == "ok"


def test_the_form_points_the_watcher_at_the_draft_being_edited():
    """Пока правят адрес, индикатор обязан говорить про то, что правят, а не
    про сохранённую цель - иначе он отвечает не на тот вопрос."""
    s = fresh()
    s.target = Target(name="saved", use_ssh=True, host="10.0.0.9")
    draft = Target(name="draft", use_ssh=True, host="10.0.0.77")
    assert s.watched().host == "10.0.0.9"
    s.watching = draft
    assert s.watched().host == "10.0.0.77"
    s.watching = None
    assert s.watched().host == "10.0.0.9"


def test_there_is_only_ever_one_watcher():
    """Наблюдатель по экрану значил бы стук в общий стенд из двух мест сразу."""
    s = fresh()
    s.target = Target(name="t", use_ssh=True, host="10.0.0.9")
    s.start_watch()
    first = s.watch
    s.start_watch()
    try:
        assert s.watch is first
    finally:
        s.stop_watch()


def test_the_launcher_shows_the_live_line_under_the_probe_line():
    """Две строки про разное: верхняя - что ответило на опрос, нижняя - здесь
    ли машина сейчас. Одна другую не заменяет."""
    from traphy import link

    s = fresh()
    s.target = Target(name="t", use_ssh=True, host="10.0.0.9")
    s.watch = link.Watch(lambda: (True, ""))
    s.watch.measure()
    drawn = strings_of(menu._render(s, 0))
    probe_line = next(i for i, ln in enumerate(drawn) if "не проверена" in ln)
    live_line = next(i for i, ln in enumerate(drawn) if "отвечает" in ln)
    assert live_line == probe_line + 1


def strings_of(frame: str) -> list[str]:
    import re

    return [re.sub(r"\x1b\[[0-9;]*m", "", ln) for ln in frame.splitlines()]
