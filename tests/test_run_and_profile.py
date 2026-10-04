"""Прогон и профиль: что тут нельзя потерять молча.

Каждый тест ниже стоит за одним случаем, найденным живым проходом, и описывает
его словами того случая, а не словами кода. Общего у них одно: инструмент уже
знал правду - она была в `result.json`, в `validate()`, в собранных кадрах - и
терял её по дороге к человеку. Молча потерянная правда хуже отсутствующей:
прогон по общему стенду состоялся, трафик ушёл, а «замер не годится» никто не
прочитал.

Терминала здесь нет и трафика тоже. Отрисовка в этом интерфейсе - чистая
функция, клавиши подставляются, адреса и имена машин выдуманные.
"""

from __future__ import annotations

import re
import time

import pytest

from traphy import engines, presets, ui
from traphy.models import Profile
from traphy.runner import RunResult
from traphy.runspec import RunSpec
from traphy.screens import compose, execute
from traphy.session import Session
from traphy.strings import t


@pytest.fixture
def session(tmp_path) -> Session:
    """Сеанс с профилем и со своими каталогами - настоящих не касаемся."""
    s = Session(version="0.1.0")
    s.load()
    s.profile = presets.build("l3_ip")
    s.profile_dir = tmp_path / "profiles"
    s.script_dir = tmp_path / "scripts"
    return s


def framed(text: str) -> list[str]:
    """Строки кадра без управляющих последовательностей."""
    return [re.sub(r"\x1b\[[0-9;]*m", "", line) for line in text.splitlines()]


class Panels:
    """Панели вместо экрана: что на них написано и что на них «нажали»."""

    def __init__(self, keys: list[str] = ()):
        self.keys = iter(list(keys))
        self.shown: list[str] = []

    def notice(self, lines, width: int = ui.WIDTH, wait: bool = True) -> str:
        text = "\n".join(x for x in lines if isinstance(x, str))
        self.shown.append("\n".join(framed(text)))
        return next(self.keys, "")

    @property
    def said(self) -> str:
        return "\n".join(self.shown)


def typed(monkeypatch, answers: list[str]) -> list[str]:
    """Ответы на приглашения ввода; возвращает список заданных вопросов."""
    asked: list[str] = []
    answer = iter(answers)

    def fake_input(prompt: str = "") -> str:
        asked.append(prompt)
        return next(answer)

    monkeypatch.setattr("builtins.input", fake_input)
    return asked


def pressed(monkeypatch, keys: list[str]) -> list[str]:
    """Нажатия для экранов с собственным циклом; кадры не рисуем."""
    frames: list[str] = []
    key = iter(keys)
    monkeypatch.setattr(ui, "interactive", lambda: True)
    monkeypatch.setattr(ui, "draw", frames.append)
    monkeypatch.setattr(ui, "read_key", lambda timeout=None: next(key))
    return frames


# --------------------------------------------------------------------------- #
# 1. Сборка не затирает сохранённый профиль с тем же именем
# --------------------------------------------------------------------------- #
def _tuned(path) -> Profile:
    """Профиль, настроенный руками и сохранённый под именем пресета."""
    profile = presets.build("l3_ip")
    profile.streams[0].packet.frame_size = 60
    profile.streams[0].rate_value = 10_000
    profile.save(path)
    return profile


def _compose_preset(session, monkeypatch, key: str = "l3_ip"):
    """Пройти «собрать трафик → из пресета», как это делает меню."""
    monkeypatch.setattr(ui, "choose", lambda *a, **kw: 0)
    monkeypatch.setattr(compose, "preset_screen", lambda: presets.build(key))
    return compose.compose_screen(session)


def test_a_look_at_a_preset_does_not_overwrite_a_tuned_profile(session,
                                                               monkeypatch):
    """Воспроизведено: настроенный l3_ip.json (60 B, 10 000 pps) превращался в
    сток (128 B, 1000 pps) от нажатия «посмотрю, что в пресете». Имена пресетов
    фиксированы, имя из визарда детерминировано - столкновение это норма, а
    сохранял вызывающий сразу после выбора, до экрана потоков."""
    path = session.profile_dir / "l3_ip.json"
    _tuned(path)
    before = path.read_text(encoding="utf-8")

    panels = Panels(["q"])                       # отмена
    monkeypatch.setattr(ui, "notice", panels.notice)

    assert _compose_preset(session, monkeypatch) is None, "сборка продолжилась"
    assert path.read_text(encoding="utf-8") == before, "файл всё-таки изменён"


def test_the_question_names_the_file_and_what_is_in_it(session, monkeypatch):
    """Ни приглашения, ни имени файла на экране не было вовсе - то есть и
    узнать, что именно сейчас потеряется, было негде."""
    path = session.profile_dir / "l3_ip.json"
    _tuned(path)
    panels = Panels(["q"])
    monkeypatch.setattr(ui, "notice", panels.notice)
    _compose_preset(session, monkeypatch)

    said = panels.said
    assert "l3_ip.json" in said, f"имя файла не названо: {said}"
    assert "60B" in said and "10000 pps" in said, f"что потеряется: {said}"
    assert "128B" in said and "1000 pps" in said, f"что станет: {said}"


def test_overwriting_is_possible_but_only_as_an_answer(session, monkeypatch):
    """Сторож не должен мешать работать: «да, перезаписать» - это ответ, и
    после него профиль уходит вызывающему как раньше."""
    _tuned(session.profile_dir / "l3_ip.json")
    monkeypatch.setattr(ui, "notice", Panels(["y"]).notice)
    profile = _compose_preset(session, monkeypatch)
    assert profile is not None and profile.name == "l3_ip"


def test_a_second_name_is_offered_instead_of_a_loss(session, monkeypatch):
    """Единственный выход из столкновения не обязан быть разрушительным: то же
    самое под другим именем - то, чего человек и хотел."""
    path = session.profile_dir / "l3_ip.json"
    _tuned(path)
    before = path.read_text(encoding="utf-8")
    monkeypatch.setattr(ui, "notice", Panels(["n"]).notice)
    monkeypatch.setattr(ui, "ask_line", lambda *a, **kw: "l3_ip_stock")

    profile = _compose_preset(session, monkeypatch)
    assert profile is not None and profile.name == "l3_ip_stock"
    assert path.read_text(encoding="utf-8") == before


def test_a_free_name_is_not_worth_a_question(session, monkeypatch):
    """Вопрос, который задают там, где терять нечего, перестают читать."""
    panels = Panels(["q"])
    monkeypatch.setattr(ui, "notice", panels.notice)
    assert _compose_preset(session, monkeypatch, "imix") is not None
    assert not panels.shown, f"спросили на пустом месте: {panels.said}"


def test_reopening_a_saved_profile_is_not_an_overwrite(session, monkeypatch):
    """Открыть сохранённое и положить обратно то же самое - не перезапись."""
    saved = presets.build("imix")
    path = session.profile_dir / "imix.json"
    saved.save(path)
    panels = Panels(["q"])
    monkeypatch.setattr(ui, "notice", panels.notice)
    monkeypatch.setattr(ui, "choose", lambda *a, **kw: 2)
    monkeypatch.setattr(compose, "load_screen", lambda s: Profile.load(path))

    assert compose.compose_screen(session) is not None
    assert not panels.shown, f"спросили про файл сам о себе: {panels.said}"


# --------------------------------------------------------------------------- #
# 2. Несохранённую правку видно, и о несохранении говорят
# --------------------------------------------------------------------------- #
def test_the_stream_screen_shows_that_the_disk_has_another_version(session):
    """Воспроизведено на каталоге с chmod 500: экран потоков показывал правку,
    на диске её не было, следующий запуск - «трафик не собран». Экран,
    показывающий правку из памяти, обязан сказать, что она только в памяти."""
    session.profile.save(session.profile_dir / "l3_ip.json")
    session.profile.streams[0].packet.frame_size = 60     # правка в памяти

    lines = framed(compose._render_streams(session, session.profile, 0, ""))
    assert any("не сохранены" in ln for ln in lines), lines


def test_a_saved_profile_says_where_it_lies(session):
    """Обратная половина того же: «сохранён» должно быть видно, иначе признак
    несохранённости нечем отличить от обычного вида экрана."""
    session.profile.save(session.profile_dir / "l3_ip.json")
    lines = framed(compose._render_streams(session, session.profile, 0, ""))
    assert any("сохранён: " in ln and "l3_ip.json" in ln for ln in lines), lines


def _unwritable(session):
    """Каталог профилей, в который записать нельзя, без chmod и без root."""
    wall = session.profile_dir.parent / "не_каталог"
    wall.write_text("файл на месте каталога\n", encoding="utf-8")
    session.profile_dir = wall / "profiles"


def test_leaving_the_stream_screen_admits_the_save_did_not_happen(session,
                                                                 monkeypatch):
    """`remember_profile` глотает OSError и просто обнуляет путь, так что
    «сохранено» было единственным, что экран мог сказать в любом случае."""
    _unwritable(session)
    panels = Panels([""])
    monkeypatch.setattr(ui, "notice", panels.notice)

    compose._save_on_exit(session, session.profile)

    said = panels.said
    assert "НЕ сохранена" in said, said
    assert "только в этом сеансе" in said, said


def test_a_save_that_worked_says_nothing_on_the_way_out(session, monkeypatch):
    """Панель на каждом выходе - это панель, которую закрывают не читая."""
    panels = Panels([""])
    monkeypatch.setattr(ui, "notice", panels.notice)
    compose._save_on_exit(session, session.profile)
    assert not panels.shown, f"лишняя панель: {panels.said}"
    assert (session.profile_dir / "l3_ip.json").exists()


def test_the_summary_has_the_word_for_an_unsaved_profile(session):
    """Сводку рисует launcher, решение «сохранён ли» принимается здесь - ему
    нужно из него одно слово."""
    _unwritable(session)
    assert compose.unsaved_note(session) == "не сохранён"
    session.profile_dir = session.profile_dir.parent.parent / "profiles"
    session.profile.save(session.profile_dir / "l3_ip.json")
    assert compose.unsaved_note(session) == ""


# --------------------------------------------------------------------------- #
# 3. Клавиша, нажатая во время прогона, не гасит экран результата
# --------------------------------------------------------------------------- #
def test_the_result_screen_drops_type_ahead_before_it_waits(monkeypatch):
    """Воспроизведено: с `\\r` или пробелом посреди прогона на экране остаётся
    меню, вердикт не прочитан. `_Live.go()` ввод не читает, а `ui.read_key`
    намеренно не сбрасывает набранное - и клавиша доезжала до `ui.notice`,
    гася панель в том же кадре, в котором она встала."""
    order: list[str] = []
    monkeypatch.setattr(execute, "_drop_typeahead",
                        lambda: order.append("сброс"))
    monkeypatch.setattr(ui, "notice",
                        lambda lines, width=ui.WIDTH, wait=True:
                        order.append("панель") or "")

    execute.result_screen(RunResult(profile="l3_ip", rx_source="none",
                                    tx_pkts=1000, seconds=5.0))

    assert order == ["сброс", "панель"], order


def test_the_run_screen_keeps_dropping_type_ahead_while_it_paints(session,
                                                                 monkeypatch):
    """Ввод копится все секунды прогона, а не только в последнем кадре."""
    drops: list[int] = []
    monkeypatch.setattr(execute, "_drop_typeahead", lambda: drops.append(1))
    monkeypatch.setattr(ui, "draw", lambda text: None)

    live = execute._Live(session, RunSpec(duration=0.1))
    monkeypatch.setattr(live, "_work", lambda: time.sleep(0.4))
    assert live.go() is None                     # результата нет, он и не нужен
    assert len(drops) >= 2, f"сбросов всего {len(drops)}"


def test_dropping_type_ahead_costs_nothing_without_a_terminal():
    """Та же функция зовётся из тестов и из пайпа - она обязана молчать."""
    assert execute._drop_typeahead() is None


# --------------------------------------------------------------------------- #
# 4. Приглашение «сколько секунд гнать»
# --------------------------------------------------------------------------- #
def test_ctrl_c_at_the_prompt_cancels_instead_of_starting_a_run(monkeypatch):
    """Воспроизведено: Ctrl-C на приглашении → прогон стартовал на 10 секунд.
    `ui.ask_line` превращает KeyboardInterrupt в "", а "" тут значит «по
    умолчанию» - то есть единственный жест «передумал» запускал прогон."""
    def interrupted(prompt: str = "") -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupted)
    assert execute._ask_duration(10.0) is None


def test_a_closed_input_is_not_a_run_either(monkeypatch):
    """EOF приходит оттуда же и значит то же самое."""
    def closed(prompt: str = "") -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", closed)
    assert execute._ask_duration(10.0) is None


def test_the_prompt_says_how_to_change_your_mind(monkeypatch):
    """Подсказки про отмену в приглашении не было вовсе."""
    asked = typed(monkeypatch, [""])
    assert execute._ask_duration(10.0) == 10.0
    assert "Ctrl-C" in asked[0], asked[0]


@pytest.mark.parametrize("bad", ["-5", "0", "сорок", "1e9", "100000",
                                 "nan", "inf"])
def test_a_duration_that_is_not_one_is_refused_and_asked_again(bad,
                                                               monkeypatch):
    """Воспроизведено: "100000" → 28 часов, "1e9" принималось, "-5" и "0" молча
    становились 0.1. Поправить ввод молча - значит провести прогон, которого не
    просили, и записать его как заказанный."""
    asked = typed(monkeypatch, [bad, "5"])
    assert execute._ask_duration(10.0) == 5.0
    assert len(asked) == 2, "спросили один раз и побежали"
    assert bad in asked[1], f"жалоба не назвала введённое: {asked[1]}"


def test_a_long_run_is_confirmed_before_the_shared_ports_are_taken(monkeypatch):
    """На общем генераторе лишний ноль - это многочасовой прогон, который
    займёт порты; 1000 вместо 100 набирается одной клавишей."""
    asked = typed(monkeypatch, ["1000", "20"])
    panels = Panels(["n"])                       # не подтвердил
    monkeypatch.setattr(ui, "notice", panels.notice)

    assert execute._ask_duration(10.0) == 20.0
    assert len(asked) == 2, "вернулись не к вопросу"
    assert "мин" in panels.said, panels.said


def test_a_long_run_still_runs_when_it_was_meant(monkeypatch):
    """Подтверждение - это вопрос, а не запрет: отвечать «да» должно работать."""
    typed(monkeypatch, ["1000"])
    monkeypatch.setattr(ui, "notice", Panels(["y"]).notice)
    assert execute._ask_duration(10.0) == 1000.0


def test_the_ceiling_is_the_last_word(monkeypatch):
    """Потолок не обходится подтверждением - выше него ответа просто нет."""
    typed(monkeypatch, [f"{execute._MAX_SECONDS + 1:g}", "7"])
    monkeypatch.setattr(ui, "notice", Panels(["y", "y"]).notice)
    assert execute._ask_duration(10.0) == 7.0


# --------------------------------------------------------------------------- #
# 5. Визард: одна клавиша - один смысл
# --------------------------------------------------------------------------- #
def _wizard_ranges(monkeypatch, keys: list[str]) -> bool:
    stream = presets.build("port_sweep").streams[0]
    pressed(monkeypatch, keys)
    return compose.ranges_screen(stream, engines.REGISTRY["trex"],
                                 title="шаг 3", wizard=True)


def test_the_ranges_step_goes_forward_on_the_key_its_neighbours_use(monkeypatch):
    """Шаг 3 подписывался «q дальше» и учил руку, что q ведёт вперёд, - а шаг 4
    на том же нажатии стирал четыре экрана работы."""
    assert _wizard_ranges(monkeypatch, ["n"]) is True


def test_the_ranges_step_asks_before_dropping_the_build(session, monkeypatch):
    """q внутри визарда теперь значит то же, что на шагах 2 и 4, - и спрашивает."""
    panels = Panels([""])                        # любая клавиша - вернуться
    monkeypatch.setattr(ui, "notice", panels.notice)
    assert _wizard_ranges(monkeypatch, ["q", "n"]) is True
    assert "Бросить сборку" in panels.said, panels.said


def test_the_ranges_footer_says_the_same_as_the_other_steps(monkeypatch):
    """Подвал - это то, по чему руку и учат."""
    stream = presets.build("port_sweep").streams[0]
    inside = framed(compose._render_ranges(stream, 0, "", "шаг 3", True))
    assert any("n дальше" in ln for ln in inside), inside
    assert not any("q дальше" in ln for ln in inside), inside

    alone = framed(compose._render_ranges(stream, 0, "", "", False))
    assert any("q назад" in ln for ln in alone), alone


@pytest.mark.parametrize("answer,dropped", [("y", True), ("д", True),
                                            ("x", False), ("enter", False)])
def test_the_build_is_dropped_only_on_an_explicit_yes(answer, dropped,
                                                      monkeypatch):
    monkeypatch.setattr(ui, "interactive", lambda: True)
    monkeypatch.setattr(ui, "notice", Panels([answer]).notice)
    assert compose._abandon(4) is dropped


@pytest.mark.parametrize("screen", ["_ask_fields", "_ask_rate"])
def test_an_unfinished_step_asks_before_it_throws_the_work_away(screen,
                                                               monkeypatch):
    """Шаги 2 и 4 бросали весь визард без подтверждения - на той же клавише,
    которой шаг 3 вёл вперёд."""
    hints: list[str] = []
    monkeypatch.setattr(compose, "edit_form",
                        lambda title, fields, **kw: hints.append(kw["keys_hint"]))
    answers = iter([False, True])                # сначала «вернуться», потом «да»
    monkeypatch.setattr(compose, "_abandon", lambda step: next(answers))

    stream = presets.build("l3_ip").streams[0]
    kwargs = {"stream": stream, "step": 2}
    if screen == "_ask_rate":
        kwargs |= {"engine": engines.REGISTRY["scapy"], "link_mbit": 1000}

    assert getattr(compose, screen)(**kwargs) is False
    assert len(hints) == 2, "экран не вернулся после отказа бросать сборку"
    assert all("q бросить сборку" in hint for hint in hints), hints
    assert not any("q отмена" in hint for hint in hints), hints


# --------------------------------------------------------------------------- #
# 6. История отдаёт вердикт, который у неё уже в руках
# --------------------------------------------------------------------------- #
RUNS = [
    {"started_at": "2026-10-02 11:00:00", "profile": "l3_ip", "tx_pkts": 0,
     "rc": 13, "note": "нет прав на сырой сокет - нужен root"},
    {"started_at": "2026-10-02 11:05:00", "profile": "loopback",
     "tx_pkts": 4001, "rc": 0, "reliable": True, "loss_pct": 0.0,
     "measurement_valid": False,
     "disqualified": ["в счёт приёма попало не только наше"]},
    {"started_at": "2026-10-02 11:10:00", "profile": "imix", "tx_pkts": 0,
     "rc": 0, "dry_run": True},
    {"started_at": "2026-10-02 11:15:00", "profile": "l4_udp",
     "tx_pkts": 10_000, "rc": 0, "reliable": True, "loss_pct": 0.5,
     "measurement_valid": True},
    {"started_at": "2026-10-02 11:20:00", "profile": "l2_ethernet",
     "tx_pkts": 500, "rc": 0, "reliable": False, "loss_pct": None},
]


def _history(monkeypatch) -> str:
    panels = Panels([""])
    monkeypatch.setattr(ui, "notice", panels.notice)
    monkeypatch.setattr(execute, "recent_runs", lambda limit=12: RUNS)
    execute.history_screen(Session())
    return panels.said


def test_the_history_says_a_failed_run_failed(monkeypatch):
    """Воспроизведено: девять прогонов, упавших с «нет прав на сырой сокет»,
    выглядели как «tx 0 · приём не мерян» - то есть как обычный замер без
    приёмного порта. Архив отдаёт `rc` и `note` тем же вызовом."""
    said = _history(monkeypatch)
    assert "rc 13" in said, said
    assert "нет прав" in said, said


def test_the_history_repeats_the_verdict_a_keypress_could_have_eaten(monkeypatch):
    """Единственное место, где потерянный на экране итога вердикт можно
    прочитать снова, - поэтому он тут обязан быть."""
    said = _history(monkeypatch)
    assert "ЗАМЕР НЕ ГОДИТСЯ" in said, said
    assert "в счёт приёма" in said, said


def test_the_history_does_not_dress_a_dry_run_as_a_measurement(monkeypatch):
    said = _history(monkeypatch)
    assert "холостой" in said, said


def test_the_history_still_prints_plain_loss_for_a_good_run(monkeypatch):
    """Сторож от перестраховки: годный прогон обязан читаться как годный."""
    said = _history(monkeypatch)
    assert "потери 0.50%" in said, said
    assert "приём не мерян" in said, "прогон без приёма перестал об этом говорить"


def test_the_history_fits_the_panel(monkeypatch):
    """Вердикт, вылезший из рамки, ломает экран, который и читают ради него."""
    for line in _history(monkeypatch).splitlines():
        assert len(line) <= ui.WIDE + 4, line


# --------------------------------------------------------------------------- #
# 7. Сохранить скрипт, которому нечего слать
# --------------------------------------------------------------------------- #
def test_saving_a_script_with_every_stream_off_is_refused(session, monkeypatch):
    """Воспроизведено: экран потоков пишет «все потоки выключены - слать
    нечего», сухой прогон отказывает, а сохранение писало файл и отвечало
    «записано: scripts/imix.py» - внутри `STREAMS = [ # профиль пуст ]`."""
    for stream in session.profile.streams:
        stream.enabled = False
    monkeypatch.setattr(ui, "ask_line", lambda *a, **kw: "")

    status = execute.save_script(session)
    assert status.startswith("!"), status
    assert "выключены" in status, status
    assert not session.script_dir.exists(), "файл всё-таки записан"


def test_saving_a_profile_that_can_send_still_works(session, monkeypatch):
    """Отказ должен стоять на одном основании с прогоном, а не на своём."""
    monkeypatch.setattr(ui, "ask_line", lambda *a, **kw: "")
    status = execute.save_script(session)
    assert not status.startswith("!"), status
    assert list(session.script_dir.glob("*.py"))


# --------------------------------------------------------------------------- #
# 8. В машинном выводе нет цифры потерь, которой не на чем держаться
# --------------------------------------------------------------------------- #
def test_json_prints_no_loss_where_there_is_nothing_to_subtract_from():
    """Потери зажаты в ноль через max(0, tx - rx), поэтому при rx > tx в JSON
    уезжало `loss_pct: 0.0` с `loss_measured: true` рядом с
    `measurement_valid: false`. Кто собирает отчёт скриптом и берёт loss_pct,
    получал «потери 0%» по дисквалифицированному прогону."""
    r = RunResult(engine="trex", rx_source="flow_stats", reliable=True,
                  tx_pkts=4001, rx_pkts=142_250_747, seconds=4.3)
    d = r.to_dict()
    assert d["loss_pct"] is None and d["loss_pkts"] is None
    assert d["loss_countable"] is False
    assert d["measurement_valid"] is False
    assert d["disqualified"], "причина обязана быть названа"


def test_the_same_run_says_the_same_thing_in_one_line():
    """Сводка и JSON читаются одним человеком - расходиться им нельзя."""
    r = RunResult(engine="trex", rx_source="flow_stats", reliable=True,
                  tx_pkts=4001, rx_pkts=142_250_747, seconds=4.3)
    said = r.summary()
    assert "потери не считаются" in said, said
    assert "0.00%" not in said, said


def test_the_screen_prints_no_loss_there_either(monkeypatch):
    """Экран защищён был только на ветке «измерено, но веры нет» - надёжный
    счёт, принявший больше отправленного, печатал аккуратный ноль зелёным."""
    panels = Panels([""])
    monkeypatch.setattr(ui, "notice", panels.notice)
    execute.result_screen(RunResult(engine="trex", rx_source="flow_stats",
                                    reliable=True, tx_pkts=4001,
                                    rx_pkts=142_250_747, seconds=4.3))
    loss = next(ln for ln in panels.said.splitlines() if t("l_loss") in ln)
    assert "не считаются" in loss, loss
    assert "0.000%" not in loss, loss


def test_a_clean_run_keeps_its_loss_figure():
    """Сторож от перестраховки: выбросить верное вместе с бесполезным нельзя."""
    d = RunResult(rx_source="flow_stats", reliable=True,
                  tx_pkts=1000, rx_pkts=990).to_dict()
    assert d["loss_pct"] == 1.0 and d["loss_countable"] is True
    assert d["measurement_valid"] is True


def test_a_run_that_fell_short_of_the_rate_keeps_what_it_did_measure():
    """Негодный замер цифру потерь не отменяет: она считается от того, что
    реально ушло, и остаётся верной арифметикой."""
    d = RunResult(rx_source="flow_stats", reliable=True, tx_pkts=1000,
                  rx_pkts=990, requested_pps=1000, achieved_pps=300).to_dict()
    assert d["measurement_valid"] is False
    assert d["loss_pct"] == 1.0, "выброшено верное вместе с бесполезным"


def test_nobody_counting_is_still_nobody_counting():
    """Старое правило на месте: не мерили - цифры нет."""
    d = RunResult(tx_pkts=1000, rx_pkts=0, rx_source="none").to_dict()
    assert d["loss_pct"] is None and d["loss_measured"] is False


# --------------------------------------------------------------------------- #
# 9. Холостой прогон показывает собранное, а не нули
# --------------------------------------------------------------------------- #
def _dry_screen(monkeypatch, built: int, samples: str = "") -> str:
    panels = Panels([""])
    monkeypatch.setattr(ui, "notice", panels.notice)
    result = RunResult(profile="l3_ip", target="генератор", dry_run=True,
                       rx_source="none", requested_pps=1000.0,
                       captures={"streams": samples} if samples else {},
                       note="сухой прогон - в кабель ничего не ушло")
    execute.result_screen(result, built=built)
    return panels.said


def test_the_dry_run_counts_the_frames_it_built(monkeypatch):
    """Подпись - «собрать кадры, ничего не слать», а экран печатал
    «отправлено 0 · скорость 0 pps · прошло 0.0 c»: три нуля вместо
    единственного, что произошло. Кадры при этом собраны и лежат в архиве, а
    адреса проверяли, читая profile.json руками."""
    said = _dry_screen(monkeypatch, built=300)
    assert "собрано кадров" in said, said
    assert "300" in said, said
    assert t("l_elapsed") not in said, f"ноль секунд прогона: {said}"
    assert "ушло в кабель" in said, said


def test_the_dry_run_points_at_the_frames_it_left_behind(monkeypatch):
    """Кадры лежат в streams.pcap каталога прогона, и экран об этом молчал."""
    said = _dry_screen(monkeypatch, built=300,
                       samples="/x/state/runs/20261002-120000_l3_ip/streams.pcap")
    assert "streams.pcap" in said, said
    assert "20261002-120000_l3_ip" in said, said


def test_a_dry_run_that_said_nothing_does_not_invent_a_number(monkeypatch):
    """Сказать «собрано 0» там, где скрипт не сказал ничего, - это тот же ноль,
    из-за которого экран и переписан."""
    said = _dry_screen(monkeypatch, built=0)
    assert "не сказал сколько" in said, said


def test_the_run_remembers_what_the_script_said_it_built(session):
    """Цифра приезжает событием "ready" и в результат не попадает: "done" у
    холостого прогона приходит с нулями по устройству."""
    live = execute._Live(session, RunSpec(dry_run=True))
    live.on_event({"ev": "ready", "frames": 300})
    assert live.built == 300


def test_a_real_run_still_shows_its_counters(monkeypatch):
    """Сторож: подмена строк касается только холостого прогона."""
    panels = Panels([""])
    monkeypatch.setattr(ui, "notice", panels.notice)
    execute.result_screen(RunResult(profile="l3_ip", rx_source="flow_stats",
                                    reliable=True, tx_pkts=1000, rx_pkts=990,
                                    seconds=5.0, achieved_pps=200.0))
    said = panels.said
    assert t("l_sent") in said and t("l_recv") in said, said
    assert t("l_elapsed") in said, said
    assert "собрано кадров" not in said, said


# --------------------------------------------------------------------------- #
# 10. Куда шлём - видно, не открывая файл
# --------------------------------------------------------------------------- #
def test_the_destination_of_a_routed_profile_is_its_address():
    """Сводка называла имя, число потоков и скорость - всё, кроме адреса, то
    есть кроме единственного, чем прогон отличается от бессмысленного."""
    profile = presets.build("l3_ip")
    assert compose.destination(profile) == profile.streams[0].packet.ip_dst


def test_a_switched_profile_names_the_mac_it_goes_to():
    """На L2 адресом назначения является MAC, и говорить про IP там нечего."""
    profile = presets.build("l2_ethernet")
    assert compose.destination(profile) == profile.streams[0].packet.eth_dst


def test_an_l4_destination_carries_the_port():
    profile = presets.build("l4_udp")
    packet = profile.streams[0].packet
    assert compose.destination(profile) == f"{packet.ip_dst}:{packet.dport}"


def test_a_walked_destination_is_shown_as_the_range_it_is():
    """Один адрес там, где перебирается /24, - это не «куда шлём»."""
    profile = presets.build("ip_sweep")
    vf = profile.streams[0].vm_fields[0]
    assert compose.destination(profile) == f"{vf.min_value}..{vf.max_value}"


def test_streams_going_to_different_places_say_so():
    """Умолчать про остальные - значит показать не тот адрес."""
    profile = presets.build("l4_udp")
    second = presets.build("l4_udp").streams[0]
    second.name = "udp2"
    second.packet.ip_dst = "203.0.113.9"
    profile.streams.append(second)
    assert compose.destination(profile).endswith("+1")


def test_a_disabled_stream_does_not_speak_for_the_profile():
    """Выключенный поток никуда не шлёт, и адрес у сводки не его."""
    profile = presets.build("l4_udp")
    off = presets.build("l4_udp").streams[0]
    off.name, off.enabled = "udp_off", False
    off.packet.ip_dst = "203.0.113.9"
    profile.streams.insert(0, off)
    assert "203.0.113.9" not in compose.destination(profile)


def test_the_stream_screen_shows_where_the_traffic_goes(session):
    """Убедиться с экрана, что трафик пойдёт куда надо, было нельзя вовсе."""
    lines = framed(compose._render_streams(session, session.profile, 0, ""))
    where = session.profile.streams[0].packet.ip_dst
    assert any("куда:" in ln and where in ln for ln in lines), lines
