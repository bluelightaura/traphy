"""Нажатия: что приходит с клавиатуры и что экран с этим делает.

Проверки идут через настоящий pty, а не через подменённый ``sys.stdin``:
разбор клавиши - это termios, ``select`` и ``os.read`` вместе, и подделка
проверяла бы подделку. Поэтому же каждое чтение делается в отдельном потоке с
ограничением по времени: три из четырёх дефектов, за которыми написан этот
файл, выглядели не как неверный ответ, а как зависший экран, и тест на такое
обязан падать, а не висеть вместе со всем набором.

Трафик тут не при чём: ни один тест никуда не подключается.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable

import pytest

from traphy import forms, menu, strings, ui
from traphy.strings import t


# --------------------------------------------------------------------------- #
# Клавиатура
# --------------------------------------------------------------------------- #
class Keyboard:
    """Тот конец pty, на котором нажимают клавиши."""

    def __init__(self, master: int) -> None:
        self.master = master

    def send(self, text: str) -> None:
        os.write(self.master, text.encode("utf-8"))


class _Stdin:
    """Другой конец pty в роли ``sys.stdin``: экрану нужен только fileno."""

    def __init__(self, fd: int) -> None:
        self.fd = fd

    def fileno(self) -> int:
        return self.fd

    def isatty(self) -> bool:
        return True


@pytest.fixture
def keys(monkeypatch):
    import tty

    master, slave = os.openpty()
    # Сразу raw: в обычном режиме строковая дисциплина сама переведёт «\r»,
    # придержит ввод до перевода строки и выбросит Ctrl-C как сигнал - то есть
    # проверялась бы она, а не разбор клавиш.
    tty.setraw(slave)
    monkeypatch.setattr("sys.stdin", _Stdin(slave))
    ui._ahead.clear()
    try:
        yield Keyboard(master)
    finally:
        ui._ahead.clear()
        os.close(master)
        os.close(slave)


def pressed(timeout: float | None = None, **kw) -> str:
    """Что вернуло одно чтение клавиши."""
    box: list[str] = []
    done(lambda: box.append(ui.read_key(timeout, **kw)),
         "read_key не вернулся - ввод заблокировал экран")
    return box[0]


def done(call: Callable[[], object], what: str) -> None:
    """Выполнить и убедиться, что это вообще закончилось."""
    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(3.0)
    assert not worker.is_alive(), what


def answered(call: Callable[[], object]) -> object:
    """Что вернул экран, с тем же ограничением по времени."""
    box: list[object] = []
    done(lambda: box.append(call()), "экран не вернулся - ввод заблокировал его")
    return box[0]


@pytest.fixture
def screen(monkeypatch) -> list[str]:
    """Экран, который можно читать: перерисовки складываются в список."""
    frames: list[str] = []
    monkeypatch.setattr(ui, "interactive", lambda: True)
    monkeypatch.setattr(ui, "use_color", lambda: True)
    monkeypatch.setattr(ui, "draw", frames.append)
    return frames


# --------------------------------------------------------------------------- #
# Esc и всё, что приходит последовательностью
# --------------------------------------------------------------------------- #
def test_a_bare_esc_does_not_wait_for_bytes_that_never_come(keys):
    """Найдено QA 2026-10-02: после Esc дочитывались ровно два байта, которых
    за голым Esc не бывает. Процесс оставался жив, перерисовки прекращались,
    живой индикатор связи застывал на последнем показании - то есть экран врал
    уверенным тоном. Касалось всех экранов и панели «любая клавиша - назад»."""
    keys.send("\x1b")
    assert pressed() == "esc"


def test_the_arrow_after_a_bare_esc_arrives_whole(keys):
    """Та же находка с другой стороны: двумя дочитанными байтами съедалось
    начало следующей последовательности, и от стрелки оставалась буква B."""
    keys.send("\x1b")
    assert pressed() == "esc"
    keys.send("\x1b[B")
    assert pressed() == "down"
    keys.send("\x1b[A")
    assert pressed() == "up"


@pytest.mark.parametrize(("sequence", "key"), [
    ("\x1b[A", "up"), ("\x1b[B", "down"), ("\x1b[C", "right"), ("\x1b[D", "left"),
    ("\x1b[5~", "pgup"), ("\x1b[6~", "pgdn"),
    ("\x1b[H", "home"), ("\x1b[F", "end"), ("\x1b[1~", "home"), ("\x1b[4~", "end"),
    ("\x1b[2~", "insert"), ("\x1b[3~", "delete"),
    ("\x1b[15~", "f5"), ("\x1b[24~", "f12"), ("\x1bOP", "f1"), ("\x1bOA", "up"),
])
def test_a_key_that_arrives_as_a_sequence_has_a_name(keys, sequence, key):
    """Найдено QA 2026-10-02: неразобранная последовательность отдавалась как
    "esc", то есть PageDown - самая очевидная клавиша для листания - закрывала
    пейджер скрипта. Имя есть у всего, что терминал вообще присылает."""
    keys.send(sequence)
    assert pressed() == key


@pytest.mark.parametrize("sequence", ["\x1b[200~", "\x1b[29~", "\x1bf", "\x1b[Z"])
def test_a_sequence_nobody_taught_is_not_esc(keys, sequence):
    """"esc" для экрана значит «закрыться». Клавиша, которой экран не знает,
    закрывать его не должна - вставка, Alt с буквой и Shift-Tab тоже приходят
    последовательностями."""
    keys.send(sequence)
    assert pressed() == ""


@pytest.mark.parametrize(("sequence", "key"), [
    ("\x1b[1;5A", "up"), ("\x1b[5;5~", "pgup"), ("\x1b[1;2C", "right"),
])
def test_a_modifier_does_not_change_which_key_it_was(keys, sequence, key):
    """Ctrl-PageUp - это PageUp: ждать от него на экране другого смысла не́где."""
    keys.send(sequence)
    assert pressed() == key


def test_fast_scrolling_does_not_lose_keypresses(keys):
    """Три стрелки - девять байт, и в одно чтение они приходят вместе. Лишнее
    тут не выбрасывается, иначе вернулась бы та самая потеря нажатий, из-за
    которой в read_key стоит TCSANOW."""
    keys.send("\x1b[B\x1b[B\x1b[A")
    assert [pressed(), pressed(), pressed()] == ["down", "down", "up"]


@pytest.mark.parametrize(("sent", "key"), [
    ("\r", "enter"), ("\n", "enter"), ("\t", "tab"), ("\x7f", "backspace"),
    ("\x03", "quit"), ("s", "s"), ("д", "д"),
])
def test_the_ordinary_keys_keep_their_names(keys, sent, key):
    """Кириллическая буква - два байта UTF-8, и подтверждение удаления ждёт «д»
    буквой, а не половиной байта."""
    keys.send(sent)
    assert pressed() == key


def test_case_is_folded_unless_the_caller_is_taking_a_value(keys):
    """Клавиши сравниваются в нижнем регистре, а набранное значение - нет:
    иначе «DUT» начиналось бы с «d»."""
    keys.send("O")
    assert pressed() == "o"
    keys.send("O")
    assert pressed(keep_case=True) == "O"


def test_a_timeout_gives_up_instead_of_waiting_for_a_key(keys):
    """Без этого живой индикатор связи стоял бы до ближайшего нажатия."""
    assert pressed(0.05) == ""


def test_an_escape_cut_short_does_not_hang_the_screen(keys):
    """Обрубленная последовательность бывает: пришло «ESC [», хвост не пришёл."""
    keys.send("\x1b[")
    assert pressed() == ""


# --------------------------------------------------------------------------- #
# Список значений: набранное не теряется
# --------------------------------------------------------------------------- #
def test_a_letter_typed_into_a_value_list_comes_back_as_itself(keys, screen):
    """Найдено QA 2026-10-02: список игнорировал буквы молча, а Enter принимал
    то, что под курсором. Человек набирал значение, видел прежнее и уходил
    уверенным, что сменил его."""
    keys.send("o")
    assert answered(lambda: ui.choose("логин", [("root", "")], typing=True)) == "o"


def test_a_list_without_typing_answers_a_stray_key_at_least_with_colour(keys, screen):
    """Молча проигнорированное нажатие выглядит ровно как сломанный экран."""
    keys.send("\x1b[15~")       # F5 - списку не нужна, но она нажата
    keys.send("q")
    assert answered(lambda: ui.choose("единица", [("pps", ""), ("bps", "")])) is None
    warn = "\x1b[" + ";".join(ui.theme()["warn"]) + "m"
    assert warn not in screen[0], "подсветка была до нажатия"
    assert warn in screen[1], "подсказка не ответила на незнакомую клавишу"


def test_typing_q_in_a_value_list_still_means_back(keys, screen):
    """Компромисс, и он назван в подсказке: «q назад». Значение, которое
    начинается с «q», набирают через первую строку списка."""
    keys.send("q")
    assert answered(lambda: ui.choose("адрес", [("10.0.0.5", "")],
                                      typing=True)) is None


def test_the_row_that_types_a_value_comes_first(monkeypatch):
    """Пункт «ввести своё…» стоял последним - за всеми прошлыми значениями."""
    seen: dict = {}

    def fake_choose(title, options, cursor=0, keys_hint="", width=ui.WIDTH,
                    typing=False):
        seen.update(options=options, cursor=cursor, typing=typing)
        return None

    monkeypatch.setattr(ui, "choose", fake_choose)
    field = forms.Field("host", "адрес", lambda: "10.0.0.5", lambda _v: "",
                        suggest=("10.0.0.5", "10.0.0.6"))
    forms._activate(field, ui.WIDE)

    assert seen["options"][0][0] == t("v_own")
    assert seen["typing"] is True
    # Курсор по-прежнему на том значении, которое в поле сейчас.
    assert seen["cursor"] == 1


def test_a_field_with_a_suggestion_takes_what_was_typed_into_it(keys, screen,
                                                                monkeypatch):
    """Воспроизведено QA 2026-10-02 на поле «логин SSH» (suggest=("root",)):
    набрали operator, в поле остался root, и в файл цели уехал root."""
    got = {"value": "root"}
    asked: dict = {}

    def accept(value: str) -> str:
        got["value"] = value
        return ""

    def fake_ask_line(message, secret=False, prefill=""):
        asked.update(message=message, prefill=prefill)
        return prefill + "perator"

    monkeypatch.setattr(ui, "ask_line", fake_ask_line)
    field = forms.Field("ssh_user", "логин SSH", lambda: got["value"], accept,
                        suggest=("root",))
    keys.send("o")
    status = answered(lambda: forms._activate(field, ui.WIDE))

    assert asked["prefill"] == "o", "набранная буква не доехала до приглашения"
    assert got["value"] == "operator"
    assert status == ""


def test_a_secret_field_is_never_typed_into_a_list(monkeypatch):
    """У секрета списка нет вовсе, и подбирать по первой букве тут нечего."""
    seen: dict = {}

    def fake_choose(title, options, cursor=0, keys_hint="", width=ui.WIDTH,
                    typing=False):
        seen["typing"] = typing
        return None

    monkeypatch.setattr(ui, "choose", fake_choose)
    field = forms.Field("ssh_password", "пароль SSH", lambda: "", lambda _v: "",
                        secret=True, remember=False, suggest=("из агента",))
    forms._activate(field, ui.WIDE)
    assert seen["typing"] is False


def test_the_letter_that_opened_the_prompt_stays_in_front_of_the_line(monkeypatch):
    shown: list[str] = []
    monkeypatch.setattr("builtins.input", lambda prompt: shown.append(prompt) or "perator")
    assert ui.ask_line("логин: ", prefill="o") == "operator"
    assert shown == ["логин: o"], "набранное не видно в приглашении"


def test_what_was_typed_before_the_prompt_appeared_is_not_lost(monkeypatch):
    """Байты, прочитанные вперёд, у нас, и input() их не увидит. Быстрый набор
    иначе терял бы середину значения."""
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    ui._ahead.extend(b"perator")
    assert ui.ask_line("логин: ", prefill="o") == "operator"
    assert not ui._ahead


def test_a_keypress_is_not_mistaken_for_what_was_typed(monkeypatch):
    """Вторая стрелка, нажатая вдогонку, лежит в том же буфере. В значение она
    попадать не должна, а в пароль - тем более: там её не видно."""
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    ui._ahead.extend(b"\x1b[Bx")
    try:
        assert ui.ask_line("адрес: ") == "x"
    finally:
        ui._ahead.clear()


def test_a_value_finished_before_the_prompt_is_not_asked_again(monkeypatch):
    def refuse(prompt: str) -> str:
        raise AssertionError("спросили то, что уже набрано")

    monkeypatch.setattr("builtins.input", refuse)
    ui._ahead.extend(b"perator\r")
    try:
        assert ui.ask_line("логин: ", prefill="o") == "operator"
    finally:
        ui._ahead.clear()


# --------------------------------------------------------------------------- #
# Подтверждение: Enter ничего не удаляет
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("sent", "answer"), [
    ("y", True), ("Y", True), ("д", True),
    ("\r", False), ("n", False), ("\x1b", False), (" ", False), ("\x1b[6~", False),
])
def test_only_an_explicit_yes_confirms(keys, screen, sent, answer):
    """Найдено QA 2026-10-02: панель «удалить поток? (y/n)» принимала и Enter,
    хотя на каждой другой панели Enter значит «закрыть». Подтверждение, на
    которое отвечает любая клавиша, подтверждением не является."""
    keys.send(sent)
    panel = [ui.c("  удалить поток «проба»? (y/n)", "warn")]
    assert answered(lambda: ui.confirm(panel, ui.WIDE)) is answer


def test_a_terminal_that_cannot_be_read_answers_no(monkeypatch):
    monkeypatch.setattr(ui, "interactive", lambda: False)
    monkeypatch.setattr(ui, "draw", lambda text: None)
    assert ui.confirm(["удалить?"]) is False


# --------------------------------------------------------------------------- #
# Подвал панели: хвост подсказки не теряется
# --------------------------------------------------------------------------- #
def test_the_footer_of_the_script_screen_keeps_the_key_that_leaves_it():
    """Найдено QA 2026-10-02: русский подвал экрана скрипта длиной 80 колонок
    не влезал в панель шириной 72 и обрезался ровно на «q назад» - единственном
    указании, как уйти."""
    footer = t("script_pager", a=1, b=22, n=300, keys=t("keys_scroll"))
    assert ui.width_of("  " + footer) > ui.WIDE, "подвал больше не длинный"

    rows = ui.hint_rows(footer, ui.WIDE)
    text = ui.strip_ansi("\n".join(rows))
    assert "q назад" in text
    assert "…" not in text
    frame = ui.panel(rows, ui.WIDE)
    assert {ui.width_of(line) for line in frame.splitlines()} == {ui.WIDE + 4}


def test_a_hint_is_broken_between_key_groups_and_not_inside_one():
    rows = ui.hint_rows("↑/↓ строка   ←/→ страница   q назад", 16)
    assert [ui.strip_ansi(r).strip() for r in rows] == [
        "↑/↓ строка", "←/→ страница", "q назад"]


def test_the_form_footer_says_how_to_leave_even_in_russian():
    field = forms.Field("a", "поле", lambda: "1", lambda _v: "")
    frame = forms._render("Цель", [field], 0, "", ui.WIDE, None, "", 26)
    text = ui.strip_ansi(frame)
    assert "q назад" in text
    assert {ui.width_of(line) for line in frame.splitlines()} == {ui.WIDE + 4}


def test_the_launcher_footer_is_not_cut_off():
    session = _session()
    frame = menu._render(session, cursor=0)
    assert "q выход" in ui.strip_ansi(frame)
    assert len({ui.width_of(line) for line in frame.splitlines()}) == 1


# --------------------------------------------------------------------------- #
# Замки главного меню
# --------------------------------------------------------------------------- #
def _session():
    from traphy import prefs
    from traphy.session import Session

    session = Session(version="9.9.9")
    session.prefs = dict(prefs.load_prefs())
    return session


def _row(key: str) -> menu.Row:
    return next(r for r in menu.ROWS if r.key == key)


def test_a_row_is_not_locked_for_the_wrong_reason():
    """Найдено QA 2026-10-02: на цели с JMeter - объявлен, не реализован -
    «Запустить» было заперто подписью «сначала проверь связь с целью», хотя
    связь тут ни при чём и может быть прекрасной."""
    from traphy import presets
    from traphy.target import Target

    session = _session()
    session.profile = presets.build("l3_ip")
    session.target = Target(name="стенд", engine="jmeter")

    reason = menu.locked_reason(_row("run"), session)
    assert "JMeter" in reason
    assert reason != t("locked"), "замок опять не про то"


def test_a_row_that_will_refuse_after_the_keypress_is_locked_before_it():
    """«Показать скрипт» и «Сохранить скрипт» были открыты и отказывали только
    после нажатия - то есть после того, как человек уже решил, что делает."""
    from traphy import presets
    from traphy.target import Target

    session = _session()
    session.profile = presets.build("l3_ip")
    session.target = Target(name="стенд", engine="jmeter")
    for key in ("script", "save", "dry", "run"):
        assert "JMeter" in menu.locked_reason(_row(key), session), key


def test_a_working_engine_locks_nothing_by_itself():
    from traphy import presets

    session = _session()
    session.profile = presets.build("l3_ip")
    for key in ("script", "save", "dry"):
        assert menu.locked_reason(_row(key), session) == ""


def test_a_padlock_says_which_row_opens_it(monkeypatch):
    """Найдено QA 2026-10-02: «сначала проверь связь с целью» называет действие,
    а клавиша «c» живёт внутри формы цели - на главном экране её нет, и из
    подписи это не следует."""
    from traphy import presets

    drawn: list[str] = []
    monkeypatch.setattr(ui, "notice",
                        lambda lines, width=ui.WIDTH: drawn.append("\n".join(lines)))
    session = _session()
    session.profile = presets.build("l3_ip")

    menu._activate(_row("run"), session)
    text = ui.strip_ansi(drawn[0])
    assert t("locked") in text
    assert t("setup_title") in text, "не сказано, куда идти за клавишей"
    assert t("setup_hint") in text


def test_the_row_that_lifts_the_lock_is_the_one_for_that_lock():
    from traphy.target import Target

    session = _session()
    # Нечего слать: отпирается там, где трафик собирают.
    assert menu.unlock_row(_row("run"), session).key == "compose"

    from traphy import presets

    session.profile = presets.build("l3_ip")
    # Связи нет: отпирается в форме цели, где и живёт «c».
    assert menu.unlock_row(_row("run"), session).key == "setup"

    session.target = Target(name="стенд", engine="jmeter")
    # Движок не умеет слать: тоже форма цели, там его и выбирают.
    assert menu.unlock_row(_row("run"), session).key == "setup"
    assert menu.unlock_row(_row("history"), session) is None


def test_the_language_table_has_both_halves_of_what_the_locks_say():
    """Замки печатаются из словаря, а не собираются на экране."""
    for key in ("locked", "no_profile", "setup_title", "setup_hint", "v_own"):
        assert strings.S[key]["en"], key
