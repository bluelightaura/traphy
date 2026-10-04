"""Форма цели: что она сохраняет, что отменяет и о чём не имеет права врать.

Каждый тест ниже стоит за одним случаем, найденным живым проходом. Общее у них
одно: экран знал правду и терял её по дороге к человеку - подпись в подвале
обещала «назад», а черновик сохранялся; индикатор горел зелёным про адрес, с
которым никто не связывался; уже названный отказ оставлял открытой зелёную
галочку и отпирал «Запустить».

Терминала здесь нет и трафика тоже: отрисовка - чистая функция, клавиши
подставляются, проверка связи и опрос цели подделаны. Все адреса, логины и имена
машин выдуманные (192.0.2.0/24 и 198.51.100.0/24 - документационные сети), и это
условие, а не случайность: репозиторий публичный, стенд общий.
"""

from __future__ import annotations

import copy
import json

import pytest

from traphy import engines, forms, link, menu, presets, strings, ui
from traphy import prefs as prefs_mod
from traphy import probe
from traphy import session as session_mod
from traphy.models import Profile
from traphy.probe import HostInfo, Iface
from traphy.screens import connect
from traphy.session import Session
from traphy.target import Target, TargetStore, name_problem

# Машины, которых нет. Имена и адреса придуманы: настоящим тут делать нечего.
HOST = "192.0.2.10"
OTHER = "198.51.100.200"


# --------------------------------------------------------------------------- #
# Обстановка: экран без терминала, стенд без стенда
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def frames(monkeypatch) -> list[str]:
    """Кадры вместо терминала. По ним же и проверяется, что было сказано."""
    drawn: list[str] = []
    monkeypatch.setattr(ui, "draw", drawn.append)
    return drawn


@pytest.fixture(autouse=True)
def nothing_reaches_the_wire(monkeypatch):
    """Ни одной настоящей проверки наружу.

    Генератор и коробки общие, на них работают люди, и наблюдатель стучит раз в
    две секунды - такой тест стучал бы в чужую машину всей своей длиной.
    Подменяется и то, что зовёт наблюдатель, и то, что зовёт «c».
    """
    monkeypatch.setattr(session_mod, "probe_reachable",
                        lambda target, timeout=2.0: (True, "подделка"))
    monkeypatch.setattr(connect, "probe_reachable",
                        lambda target, on_progress=None: (True, "подделка"))


@pytest.fixture(autouse=True)
def no_field_memory():
    """Память полей на время теста отключена: она глобальная, и чужой сеанс в
    ней - это чужие значения в этом тесте."""
    forms.set_recall(None)
    yield
    forms.set_recall(None)


@pytest.fixture
def session(tmp_path) -> Session:
    """Сеанс с собственным каталогом целей и одной выдуманной машиной."""
    s = Session(store=TargetStore(tmp_path / "targets"))
    # accept-new, а не strict: иначе путь «c» упирается в проверку known_hosts
    # этой машины, и тест начинает зависеть от того, чей дом его запускает. Сам
    # отказ по незнакомому ключу проверяется там, где он и живёт.
    s.target = Target(name="gen-a", description="подделка", use_ssh=True,
                      host=HOST, ssh_user="tester", tx_iface="eth1",
                      host_key="accept-new")
    s.store.save(s.target)
    yield s
    s.stop_watch()


@pytest.fixture
def keys(monkeypatch) -> list[str]:
    """Клавиши, которые «нажимают» вместо человека.

    Форма настоящая - edit_form, ui.choose и ui.notice читают ввод одной
    функцией, поэтому подменяется она одна. Когда нажатия кончились, отдаётся
    «q»: тест, забывший закрыть экран, должен падать проверкой, а не висеть.
    """
    pressed: list[str] = []
    monkeypatch.setattr(ui, "interactive", lambda: True)
    monkeypatch.setattr(ui, "read_key",
                        lambda timeout=None: pressed.pop(0) if pressed else "q")
    return pressed


@pytest.fixture
def answers(monkeypatch) -> dict:
    """Цель, которая «отвечает»: подделка транспорта и опроса.

    Что именно она про себя рассказывает, тест меняет через ``answers["host"]`` -
    отказы движка считаются как раз по этому.
    """
    closed: list[bool] = []

    class FakeTransport:
        def close(self) -> None:
            closed.append(True)

    state = {
        "host": HostInfo(ok=True, hostname="gen-a", kernel="linux",
                         python="3.11", has_scapy=True, scapy_version="2.5.0",
                         is_root=True,
                         ifaces=[Iface(name="eth1", state="up")]),
        "closed": closed,
    }
    monkeypatch.setattr(session_mod, "open_transport",
                        lambda target, password="": FakeTransport())
    monkeypatch.setattr(probe, "inspect",
                        lambda transport, timeout=30, trex_dir="": state["host"])
    return state


def open_form(monkeypatch, session: Session, keys: list[str], *presses: str,
              change=None) -> None:
    """Открыть форму цели, поправив черновик так, как это делает человек.

    ``change`` получает поля по ключу и правит их сеттерами, то есть ровно тем
    путём, которым правит форма; после этого «нажимаются» ``presses``.
    """
    real = connect.edit_form

    def instead(title, fields, **kw):
        if change is not None:
            change({f.key: f for f in fields})
        return real(title, fields, **kw)

    monkeypatch.setattr(connect, "edit_form", instead)
    keys[:] = list(presses)
    connect.target_screen(session)


def said(frames: list[str]) -> str:
    """Всё нарисованное, без управляющих последовательностей."""
    return ui.strip_ansi("\n".join(frames))


def on_disk(session: Session, name: str) -> dict:
    return json.loads(session.store.path_for(name).read_text(encoding="utf-8"))


def watcher(session: Session) -> link.Watch:
    """Наблюдатель, собранный самим сеансом, но без фонового потока: поток
    переписывал бы показание под рукой теста."""
    session.start_watch()
    session.stop_watch()
    return session.watch


# --------------------------------------------------------------------------- #
# 1. Показание помнит, про кого оно
# --------------------------------------------------------------------------- #
def test_a_reading_about_another_address_is_not_inherited():
    """Показание с другого адреса не «устарело», оно чужое - ни возрастом, ни
    оговоркой такое не лечится."""
    reading = link.Reading(ok=True, ms=0.4, at=100.0, about=f"{HOST}:22")
    text, role = link.describe(reading, count=1, every=2.0, now=100.0,
                               about=f"{OTHER}:22")
    assert "не проверено" in text and role == "dim"
    assert "отвечает" not in text


def test_the_watcher_stops_answering_for_the_address_that_changed():
    """Наблюдатель помечает каждое показание тем, про кого он спрашивал."""
    whom = {"who": f"{HOST}:22"}
    watch = link.Watch(lambda: (True, ""), subject=lambda: whom["who"])
    watch.measure()
    assert "отвечает" in watch.line()[0]

    whom["who"] = f"{OTHER}:22"
    text, role = watch.line()
    assert "не проверено" in text and role == "dim"


def test_the_indicator_does_not_credit_the_old_box_with_the_new_address(session):
    """Воспроизведение находки: меняешь адрес в форме на заведомо мёртвый - и
    три секунды горит зелёное «отвечает · 0 мс · <новый адрес>», потому что
    ответил прежний объект наблюдения. По часам показание при этом свежее."""
    draft = copy.deepcopy(session.target)
    session.watching = draft
    watcher(session)

    text, role = session.link_line()
    assert "отвечает" in text and role == "ok" and HOST in text

    draft.host = OTHER
    text, role = session.link_line()
    assert "не проверено" in text, text
    assert "отвечает" not in text
    assert OTHER in text, "про какой адрес строка - должно быть видно"
    assert role == "dim"


def test_the_engine_and_the_port_names_do_not_invalidate_a_reading(session):
    """Подпись показания - то, что проверяют, и только: смена движка про
    достижимость коробки не говорит ничего, и гасить индикатор ей незачем."""
    before = session.target.link_subject()
    session.target.engine = "trex"
    session.target.tx_iface = "eth9"
    assert session.target.link_subject() == before


# --------------------------------------------------------------------------- #
# 2. Честная отмена и честное подтверждение
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("leave", ["q", "esc", "quit"])
def test_leaving_the_form_keeps_the_target_as_it_was(monkeypatch, session, keys,
                                                     leave):
    """q, Esc и Ctrl-C - три способа сказать одно и то же, и все три сохраняли.
    Воспроизведение: зашёл в форму, переключил движок на JMeter, вышел - в файле
    цели «engine»: «jmeter»."""
    open_form(monkeypatch, session, keys, leave, "x",
              change=lambda f: f["engine"].set("jmeter"))

    assert session.target.engine == "scapy"
    assert on_disk(session, "gen-a")["engine"] == "scapy"


def test_an_unsaved_change_is_not_lost_without_a_word(monkeypatch, session, keys,
                                                     frames):
    """Отмена не имеет права молча съесть двадцать набранных полей: вопрос
    дешевле, чем набрать их заново."""
    open_form(monkeypatch, session, keys, "q", "s",
              change=lambda f: f["engine"].set("jmeter"))

    assert "не сохранена" in said(frames), "вопроса на экране не было"
    assert session.target.engine == "jmeter", "«s» в вопросе не сохранило"
    assert on_disk(session, "gen-a")["engine"] == "jmeter"


def test_a_form_nobody_touched_leaves_without_questions(monkeypatch, session,
                                                        keys, frames):
    """Спрашивать там, где терять нечего, - это второе нажатие на выход из
    экрана, куда зашли посмотреть."""
    open_form(monkeypatch, session, keys, "q")
    assert "не сохранена" not in said(frames)


def test_s_is_the_one_key_that_saves(monkeypatch, session, keys):
    open_form(monkeypatch, session, keys, "s", "x",
              change=lambda f: f["engine"].set("jmeter"))

    assert session.target.engine == "jmeter"
    assert on_disk(session, "gen-a")["engine"] == "jmeter"


def test_the_footer_says_what_the_keys_actually_do(session):
    """Расхождение подписи и поведения и стоило черновика, поэтому подпись - под
    проверкой, вместе с тем, что она влезает в панель."""
    assert "s сохранить" in connect.KEYS
    assert "q отмена" in connect.KEYS
    assert ui.width_of("  " + connect.KEYS) <= ui.WIDE


def test_checking_the_link_does_not_adopt_the_draft(monkeypatch, session, keys,
                                                    answers):
    """«c» отвечает на «отвечает ли машина», а не на «эту цель и берём». Пока он
    присваивал черновик сеансу, выход по «q» уже ничего не отменял."""
    open_form(monkeypatch, session, keys, "c", "q", "x",
              change=lambda f: f["host"].set(OTHER))

    assert session.target.host == HOST
    assert on_disk(session, "gen-a")["host"] == HOST


def test_the_link_opened_for_a_discarded_draft_is_closed(monkeypatch, session,
                                                         keys, answers):
    """Иначе главный экран показывает «связь есть» про машину, которую только
    что отвергли."""
    open_form(monkeypatch, session, keys, "c", "q", "x",
              change=lambda f: f["host"].set(OTHER))

    assert session.transport is None
    assert not session.connected


def test_confirming_keeps_the_link_just_proven(monkeypatch, session, keys,
                                               answers):
    """Проверил связь и сохранил цель - связь обязана остаться: закрывать её на
    подтверждении значит заставлять опрашивать ту же машину дважды."""
    open_form(monkeypatch, session, keys, "c", "s")

    assert session.connected
    assert session.target.name == "gen-a"


# --------------------------------------------------------------------------- #
# 3. Названный отказ запирает
# --------------------------------------------------------------------------- #
def test_a_blocker_named_at_c_locks_the_run(session, answers):
    """Причина отказа известна сразу после опроса - она и должна запирать. «c»
    говорил «нет root - сырой сокет не открыть», а главный экран показывал
    зелёную галочку и открытый «Запустить»."""
    answers["host"] = HostInfo(ok=True, hostname="gen-a", python="3.11",
                               has_scapy=True, is_root=False, can_sudo=False,
                               ifaces=[Iface(name="eth1", state="up")])
    draft = copy.deepcopy(session.target)

    line = connect._connect_with_progress(session, draft)

    assert line.startswith("!") and "root" in line
    assert session.transport is None, "транспорт остался открытым"
    assert answers["closed"], "сокет не закрыли"
    assert not session.connected

    text, role = session.status_line()
    assert role == "bad" and "root" in text, text

    session.profile = presets.build("l3_ip")
    run_row = next(r for r in menu.ROWS if r.key == "run")
    assert menu.locked_reason(run_row, session) == strings.t("locked")


def test_a_target_that_answers_cleanly_is_not_locked(session, answers):
    line = connect._connect_with_progress(session, copy.deepcopy(session.target))

    assert not line.startswith("!"), line
    assert session.connected


def test_a_new_probe_clears_the_old_refusal(session, answers):
    """Отказ был про тот опрос. Держать его дальше - запирать прогон причиной,
    которой уже не проверяли."""
    answers["host"] = HostInfo(ok=True, hostname="gen-a", python="3.11",
                               has_scapy=False, is_root=True,
                               ifaces=[Iface(name="eth1", state="up")])
    connect._connect_with_progress(session, copy.deepcopy(session.target))
    assert session.refused

    answers["host"] = HostInfo(ok=True, hostname="gen-a", python="3.11",
                               has_scapy=True, is_root=True,
                               ifaces=[Iface(name="eth1", state="up")])
    connect._connect_with_progress(session, copy.deepcopy(session.target))
    assert not session.refused
    assert session.connected


def test_a_refusal_about_the_selected_target_survives_backing_out(monkeypatch,
                                                                 session, keys,
                                                                 answers):
    """Черновик не трогали - значит опрашивали ту же машину, и причина отказа
    остаётся при ней: на главном экране должно стоять «нет root», а не «связь не
    проверена», иначе замок есть, а объяснения к нему нет."""
    answers["host"] = HostInfo(ok=True, hostname="gen-a", python="3.11",
                               has_scapy=True, is_root=False, can_sudo=False,
                               ifaces=[Iface(name="eth1", state="up")])

    open_form(monkeypatch, session, keys, "c", "q")

    assert "root" in session.refused
    assert not session.connected
    text, role = session.status_line()
    assert role == "bad" and "root" in text, text


def test_what_was_learned_about_a_discarded_draft_goes_with_it(monkeypatch,
                                                              session, keys,
                                                              answers):
    answers["host"] = HostInfo(ok=True, hostname="gen-a", python="3.11",
                               has_scapy=True, is_root=False, can_sudo=False,
                               ifaces=[Iface(name="eth1", state="up")])

    open_form(monkeypatch, session, keys, "c", "q", "x",
              change=lambda f: f["host"].set(OTHER))

    assert not session.refused, "отказ про отвергнутую машину остался за целью"
    assert session.host is None


def test_a_target_that_stopped_answering_says_so(monkeypatch, session, answers):
    """Та же болезнь рядом: прежний сокет оставался открытым, а на главном экране
    стояло «связь не проверена» - вместо «не отвечает», которое «c» только что и
    выяснил."""
    monkeypatch.setattr(connect, "probe_reachable",
                        lambda target, on_progress=None: (False, "не отвечает за 4 c"))

    line = connect._connect_with_progress(session, copy.deepcopy(session.target))

    assert line.startswith("!") and "не отвечает" in line
    assert session.transport is None
    assert not session.connected
    assert "не отвечает" in session.status_line()[0]


# --------------------------------------------------------------------------- #
# 4. Имя, которого файловая система не возьмёт
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,why", [
    ("", "пустое"),
    ("   ", "пустое"),
    ("ц" * 300, "длиннее"),
    ("стенд/один", "нельзя"),
    ("плохо\tимя", "нельзя"),
    ("...", "ни буквы"),
])
def test_a_name_that_cannot_become_a_file_is_refused(name, why):
    assert why in name_problem(name), name_problem(name)


def test_an_ordinary_name_is_not_in_the_way():
    for name in ("gen-a", "стенд_2", "trex 3.08"):
        assert name_problem(name) == ""


def test_the_name_field_refuses_and_keeps_the_old_value(session):
    """300 символов в поле «имя цели» роняли экран на записи, и вместе с панелью
    падения терялась вся форма. Отказ в поле оставляет человека в форме."""
    draft = copy.deepcopy(session.target)
    field = {f.key: f for f in connect._fields(session, draft)}["name"]

    problem = field.set("ц" * 300)

    assert problem.startswith("!") and "длиннее" in problem
    assert draft.name == "gen-a", "поле приняло то, что записать нельзя"


def test_s_will_not_let_an_unwritable_name_out(monkeypatch, session, keys,
                                               frames):
    """Имя могло приехать и из файла, набранного не здесь, - отказ нужен и на
    выходе, а не только в поле."""
    session.target.name = "ц" * 300

    open_form(monkeypatch, session, keys, "s", "q")

    assert "длиннее" in said(frames)
    assert "target" not in session.prefs, "цель всё-таки приняли"


def test_an_unwritable_name_comes_back_as_a_sentence(session):
    """Последний рубеж: даже если такое имя дойдёт до записи, это должна быть
    фраза в панели, а не OSError и потерянная форма."""
    problem = session.remember_target(Target(name="ц" * 300))

    assert problem and "не записана" in problem
    assert not list(session.store.dir.glob("*.tmp")), "остался обрывок записи"


# --------------------------------------------------------------------------- #
# 5. Удаление и переименование
# --------------------------------------------------------------------------- #
def test_renaming_moves_the_record_instead_of_leaving_a_twin(monkeypatch,
                                                             session, keys):
    """Два файла про одну цель - это две неразличимые строки в выборке, и правка
    попадает в ту, которую прочитали первой."""
    open_form(monkeypatch, session, keys, "s", "x",
              change=lambda f: f["name"].set("gen-b"))

    assert session.store.list() == ["gen-b"]
    assert session.target.name == "gen-b"
    assert on_disk(session, "gen-b")["host"] == HOST


def test_a_rename_says_what_it_moved(monkeypatch, session, keys, frames):
    open_form(monkeypatch, session, keys, "s", "x",
              change=lambda f: f["name"].set("gen-b"))
    assert "gen-a → gen-b" in said(frames)


def test_a_saved_target_can_be_deleted(session, keys):
    """`TargetStore.delete` не звал никто: лишнюю цель убрать было нечем."""
    session.store.save(Target(name="gen-b", host=OTHER))
    keys[:] = ["down", "enter", "y"]

    line = connect._delete_saved(session, draft_name="gen-a")

    assert "удалена" in line and "gen-b" in line
    assert session.store.list() == ["gen-a"]


def test_deleting_asks_first_and_takes_no_for_an_answer(session, keys):
    """Файл цели держит адрес, логин и номера портов, набранные руками."""
    keys[:] = ["enter", "n"]

    line = connect._delete_saved(session)

    assert "оставлена" in line
    assert session.store.list() == ["gen-a"]


def test_deleting_the_target_being_edited_says_what_happened(session, keys):
    keys[:] = ["enter", "y"]
    line = connect._delete_saved(session, draft_name="gen-a")
    assert "черновиком" in line


def test_the_target_chooser_offers_the_delete_row(monkeypatch, session, keys):
    seen: dict = {}

    def fake_choose(title, options, cursor=0, keys_hint="", width=0):
        seen["options"] = options
        return None

    monkeypatch.setattr(ui, "choose", fake_choose)
    open_form(monkeypatch, session, keys, "t", "q")

    assert any("удалить" in label for label, _hint in seen["options"])


# --------------------------------------------------------------------------- #
# 6. «Локальный запуск» - это про движок, а не про флаг SSH
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("engine", ["trex", "ixia", "jmeter"])
def test_an_engine_that_is_not_this_machines_nic_claims_no_such_thing(session,
                                                                      engine):
    """У Ixia use_ssh выключен потому, что здесь работает клиент, - а шасси и
    API-сервер стоят в стойке. «Локальный запуск - сеть не нужна» было про них
    прямой неправдой."""
    session.target = Target(name="rack", engine=engine, use_ssh=False,
                            ixia_api_host="192.0.2.50",
                            ixia_chassis="192.0.2.51")

    text, role = session.link_line()

    assert "сеть не нужна" not in text, text
    assert engines.get(engine).title in text
    assert role == "dim"


def test_a_local_scapy_target_still_says_there_is_nothing_to_cross(session):
    """Это как раз тот случай, когда сеть действительно не нужна: кадры уходят с
    интерфейса этой самой машины."""
    session.target = Target(name="here", engine="scapy", use_ssh=False)
    assert "сеть не нужна" in session.link_line()[0]


def test_a_remote_target_is_still_watched(session):
    """Шов спрашивается только там, где пересекать нечего: по SSH проверять есть
    что, и индикатор обязан показывать проверку."""
    session.target = Target(name="gen-a", engine="trex", use_ssh=True, host=HOST)
    watcher(session)
    text, _role = session.link_line()
    assert HOST in text and "отвечает" in text


# --------------------------------------------------------------------------- #
# 7. Память полей не держит инвентарь стенда
# --------------------------------------------------------------------------- #
def test_addresses_and_logins_are_not_remembered_at_all(session):
    """Список «вводилось раньше» виден на экране при правке поля, то есть снимок
    формы выносил наружу перечень машин."""
    draft = copy.deepcopy(session.target)
    draft.engine = "ixia"
    fields = {f.key: f for f in connect._fields(session, draft)}

    for key in ("host", "ssh_user", "ssh_key", "ixia_api", "ixia_user",
                "ixia_chassis"):
        assert not fields[key].remember, f"{key} всё ещё запоминается"
    # А то, что не называет машину, - запоминается: иначе это не решение, а
    # отключённая функция.
    assert fields["python"].remember


def test_the_trex_daemon_address_is_not_remembered_either(session):
    draft = copy.deepcopy(session.target)
    draft.engine = "trex"
    fields = {f.key: f for f in connect._fields(session, draft)}
    assert not fields["trex_server"].remember
    assert fields["trex_dir"].remember


def test_what_an_earlier_build_remembered_is_swept_on_open(tmp_path):
    """Решение - не запоминать вовсе. Но уже записанное иначе так и показывалось
    бы под полем, поэтому оно выметается при открытии меню - и из файла тоже."""
    stale = dict(prefs_mod.load_prefs())
    stale["recent"] = {"host": [HOST], "ssh_user": ["tester"],
                       "python": ["python3.11"]}
    assert prefs_mod.save_prefs(stale)

    s = Session(store=TargetStore(tmp_path / "targets"))
    s.load()

    assert "host" not in s.prefs["recent"]
    assert "ssh_user" not in s.prefs["recent"]
    assert s.prefs["recent"]["python"] == ["python3.11"]
    assert "host" not in prefs_mod.load_prefs()["recent"], "в файле осталось"


def test_forgetting_a_field_is_possible_and_says_whether_it_had_to():
    """Возврат нужен, чтобы выметание на старте не перезаписывало файл каждый
    старт: «ничего не изменилось» должно оставаться видно по его дате."""
    p: dict = {"recent": {"host": [HOST], "python": ["python3.11"]}}

    assert prefs_mod.forget_values(p, "host")
    assert p["recent"] == {"python": ["python3.11"]}
    assert not prefs_mod.forget_values(p, "host")

    assert prefs_mod.forget_values(p)
    assert p["recent"] == {}


def test_a_password_is_still_neither_written_nor_remembered(session):
    """Это уже было сделано хорошо, и ломать его нельзя."""
    draft = copy.deepcopy(session.target)
    field = {f.key: f for f in connect._fields(session, draft)}["ssh_password"]

    field.set("не-настоящий-пароль")

    assert field.secret and not field.remember
    assert session.password == "не-настоящий-пароль"
    assert "пароль" not in json.dumps(draft.to_dict(), ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Сеанс и профиль: кто решает, когда писать на диск
# --------------------------------------------------------------------------- #
def test_saving_a_profile_says_where_it_landed(session, tmp_path):
    """Экран, показавший правку, обязан знать, дошла ли она до диска - иначе
    «сохранено» остаётся единственным, что он может сказать."""
    session.profile_dir = tmp_path / "profiles"

    path = session.remember_profile(Profile(name="проба"))

    assert path == session.profile_path("проба")
    assert path.exists()


def test_a_directory_that_will_not_take_it_comes_back_as_none(session, tmp_path):
    """Обычно это права на каталог профилей. Молчаливое «сохранено» в этом
    случае - потерянная работа и следующий запуск без объяснений."""
    wall = tmp_path / "не_каталог"
    wall.write_text("не каталог", encoding="utf-8")
    session.profile_dir = wall / "profiles"

    assert session.remember_profile(Profile(name="проба")) is None
    assert session.profile is not None, "в сеансе профиль остаётся"
    assert session.prefs["profile"] == ""


def test_the_path_asked_before_the_write_is_the_one_written(session, tmp_path):
    """Сторож перезаписи смотрит на путь до записи: если это другой путь, он не
    сторожит ничего. Имя тут нарочно такое, какое приводится к файлу."""
    session.profile_dir = tmp_path / "profiles"
    asked = session.profile_path("моя цель/1")

    written = session.remember_profile(Profile(name="моя цель/1"))

    assert written == asked
    assert asked.exists()


def test_taking_a_profile_into_the_sitting_writes_nothing(session, tmp_path):
    """«Посмотрю, что в пресете» затирало настроенный файл - запись шла по
    выбору пресета, до того как человек увидел хоть один поток."""
    session.profile_dir = tmp_path / "profiles"
    session.profile_path("проба").parent.mkdir(parents=True)
    session.profile_path("проба").write_text("настроенное руками",
                                             encoding="utf-8")

    session.select_profile(Profile(name="проба"))

    assert session.profile is not None
    assert session.profile_path("проба").read_text(
        encoding="utf-8") == "настроенное руками"
