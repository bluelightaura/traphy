"""Targets: what makes one valid, and that saving one never loses a field."""

from __future__ import annotations

from traphy.strings import t
from traphy.target import Nic, Target, TargetStore, host_key_known, probe_reachable


def test_a_loopback_target_is_local_even_with_ssh_ticked():
    """SSH-ing to yourself is a slower way to run a subprocess, so we do not."""
    assert Target(use_ssh=True, host="127.0.0.1").is_local
    assert Target(use_ssh=True, host="10.0.0.9").is_local is False


def test_validation_catches_a_half_filled_ssh_target():
    problems = Target(use_ssh=True, host="", ssh_user="").validate()
    assert any("адрес" in p for p in problems)
    assert any("логин" in p for p in problems)


def test_a_missing_key_file_is_named():
    problems = Target(ssh_key="/nope/id_ed25519").validate()
    assert any("не найден" in p for p in problems)


def test_same_interface_for_send_and_receive_is_flagged_on_a_remote_target():
    target = Target(use_ssh=True, host="10.0.0.9", ssh_user="root",
                    tx_iface="eth0", rx_iface="eth0")
    assert any("одном интерфейсе" in p for p in target.validate())


def test_rx_absent_means_loss_cannot_be_measured():
    assert Target(rx_iface="").measures_rx() is False
    assert Target(rx_iface="eth1").measures_rx() is True


def test_store_round_trip(tmp_path):
    store = TargetStore(tmp_path)
    original = Target(name="стенд 1", use_ssh=True, host="10.0.0.9",
                      ssh_user="root", tx_iface="ens1", rx_iface="ens2",
                      link_mbit=10000, nics=[Nic("к свитчу", "ens1")])
    store.save(original)
    assert store.list() == ["стенд_1"]         # only the space is replaced
    loaded = store.load("стенд 1")
    assert loaded.to_dict() == original.to_dict()


def test_unreadable_target_does_not_raise(tmp_path):
    store = TargetStore(tmp_path)
    (tmp_path / "broken.json").write_text("{ не json", encoding="utf-8")
    assert store.try_load("broken") is None


def test_seed_is_local_and_carries_no_remembered_address(tmp_path):
    """A repository that ships someone's bench IP is how that IP goes public."""
    seed = TargetStore(tmp_path).ensure_seed()
    assert seed.is_local
    assert seed.host in ("127.0.0.1", "")
    assert seed.use_ssh is False


def test_seed_is_not_recreated_when_one_exists(tmp_path):
    store = TargetStore(tmp_path)
    store.save(Target(name="bench", use_ssh=True, host="10.0.0.9", ssh_user="root"))
    assert store.ensure_seed().name == "bench"


def test_probe_of_a_local_target_needs_no_network():
    ok, why = probe_reachable(Target())
    assert ok and "локальный" in why


def test_probe_of_an_unresolvable_name_says_so():
    ok, why = probe_reachable(
        Target(use_ssh=True, host="no-such-host.invalid", ssh_user="x"), timeout=1)
    assert not ok and "не разрешается" in why


def test_host_key_lookup_handles_a_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    assert host_key_known("example.org") is False


def test_a_target_defaults_to_the_strict_host_key_mode():
    assert Target().host_key == "strict"
    assert Target().host_key_fingerprint == ""


def test_an_older_target_file_is_read_into_the_new_modes():
    """Builds before the modes existed stored a boolean. False meant "accept
    anything and remember nothing" - the one behaviour no mode offers now, and
    accept-new is what that setting was always reaching for."""
    assert Target.from_dict({"strict_host_key": True}).host_key == "strict"
    assert Target.from_dict({"strict_host_key": False}).host_key == "accept-new"


def test_an_explicit_mode_wins_over_the_old_boolean():
    d = {"strict_host_key": True, "host_key": "accept-new"}
    assert Target.from_dict(d).host_key == "accept-new"


def test_a_pinned_fingerprint_survives_a_round_trip():
    target = Target(name="t", host_key_fingerprint="SHA256:abc")
    assert Target.from_dict(target.to_dict()).host_key_fingerprint == "SHA256:abc"


# --------------------------------------------------------------------------- #
# Пароль SSH: в сеансе, не в файле
# --------------------------------------------------------------------------- #
def _connect_fields(session, target):
    from traphy.screens.connect import _fields

    session.target = target
    return {f.key: f for f in _fields(session, target) if f.shown()}


def remote() -> Target:
    return Target(name="стенд", use_ssh=True, host="10.0.0.9", ssh_user="user")


def test_the_password_field_appears_for_a_remote_target():
    from traphy.session import Session

    fields = _connect_fields(Session(), remote())
    assert "ssh_password" in fields
    assert fields["ssh_password"].secret is True
    # Память паролей - ровно то, чего быть не должно.
    assert fields["ssh_password"].remember is False


def test_the_password_field_is_absent_when_sending_from_this_machine():
    from traphy.session import Session

    fields = _connect_fields(Session(), Target(name="local", use_ssh=False))
    assert "ssh_password" not in fields


def test_a_typed_password_lives_on_the_session_and_not_in_the_target():
    """Файл цели лежит в каталоге состояния, его легко скопировать и показать.
    Пароль в нём - утечка, которую никто не заметит."""
    from traphy.session import Session

    session, target = Session(), remote()
    field = _connect_fields(session, target)["ssh_password"]

    assert field.set("хитрыйпароль") != ""          # сообщает, что принял
    assert session.password == "хитрыйпароль"
    assert session.password_from == "typed"
    assert "хитрыйпароль" not in target.to_json()
    assert "password" not in target.to_dict()


def test_the_shown_value_is_a_word_and_never_the_password():
    from traphy.session import Session

    session, target = Session(), remote()
    field = _connect_fields(session, target)["ssh_password"]
    assert field.get() == t("pw_unset")
    field.set("хитрыйпароль")
    assert "хитрый" not in field.get()


def test_a_password_can_be_taken_back_out():
    from traphy.session import Session

    session, target = Session(), remote()
    field = _connect_fields(session, target)["ssh_password"]
    field.set("хитрыйпароль")
    assert "убран" in field.set("-")
    assert session.password == ""
    assert session.password_from == ""


def test_the_password_from_the_environment_reaches_the_menu(monkeypatch):
    """До этого его читал только CLI: меню передавало в paramiko пустую строку,
    и цель с парольным входом из меню не открывалась вовсе."""
    from traphy.session import Session
    from traphy.transport import SSH_PASSWORD_ENV

    monkeypatch.setenv(SSH_PASSWORD_ENV, "изокружения")
    session = Session()
    session.load()
    assert session.password == "изокружения"
    assert session.password_from == "env"


def test_a_password_typed_in_the_form_is_not_overwritten_by_the_environment(
        monkeypatch):
    from traphy.session import Session
    from traphy.transport import SSH_PASSWORD_ENV

    monkeypatch.setenv(SSH_PASSWORD_ENV, "изокружения")
    session = Session()
    session.password, session.password_from = "набранный", "typed"
    session.load()
    assert session.password == "набранный"


# --------------------------------------------------------------------------- #
# Подхват настроек с самой цели
# --------------------------------------------------------------------------- #
def found(**kw):
    from traphy.probe import HostInfo

    base = dict(ok=True, has_trex=True, has_trex_stl=True,
                trex_dir="/opt/trex-3.08", trex_version="v3.08",
                trex_daemon=True, trex_ports=2, trex_link_mbit=25000)
    base.update(kw)
    return HostInfo(**base)


def bare() -> Target:
    """Цель, заведённая как её заводит человек: машина и логин, больше ничего."""
    return Target(name="проба", engine="trex", use_ssh=True,
                  host="10.0.0.9", ssh_user="кто-то")


def test_the_target_takes_what_the_machine_can_tell_about_itself():
    t = bare()
    changed = t.adopt(found())
    assert t.trex_dir == "/opt/trex-3.08"
    assert t.trex_server == "127.0.0.1"
    assert (t.trex_port_tx, t.trex_port_rx) == (0, 1)
    assert t.link_mbit == 25000
    assert len(changed) == 3          # каталог, порт приёма, скорость


def test_what_changed_is_said_out_loud():
    """Молчаливо переписанное поле - это поле, в котором потом ищут свою же
    опечатку."""
    said = " ".join(bare().adopt(found()))
    assert "/opt/trex-3.08" in said
    assert "25000" in said


def test_a_directory_without_the_control_plane_is_not_adopted():
    """Каталог есть, а управляющей библиотеки в нём нет - это не релиз, и
    подставлять его значит менять «не нашли» на «нашли не то»."""
    t = bare()
    t.adopt(found(has_trex_stl=False, trex_dir="/opt/каталог"))
    assert t.trex_dir == "/opt/trex"   # осталось умолчание


def test_one_port_means_there_is_nothing_to_receive_on():
    """Порт приёма был задан, а у демона он один - значит ловить нечем, и
    сказать это надо вслух: иначе прогон молча посчитает потери по порту,
    которого нет."""
    t = bare()
    t.trex_port_rx = 1
    said = t.adopt(found(trex_ports=1))
    assert t.trex_port_rx == -1
    assert any("один порт" in line for line in said)


def test_a_daemon_that_does_not_answer_leaves_its_address_alone():
    t = bare()
    t.trex_server = "10.0.0.9"
    t.adopt(found(trex_daemon=False))
    assert t.trex_server == "10.0.0.9"


def test_a_link_speed_nobody_announced_is_not_invented():
    """Это число пересчитывает проценты линии в pps. Догадка в нём тихо
    перекашивает весь замер, поэтому ноль - повод не трогать поле."""
    t = bare()
    t.link_mbit = 1000
    t.adopt(found(trex_link_mbit=0))
    assert t.link_mbit == 1000


def test_nothing_the_machine_cannot_know_is_touched():
    """Адрес, логин и режим ключа хоста цель про себя не знает - подставить
    туда догадку значит сломать вход ради удобства."""
    t = bare()
    t.host_key = "strict"
    t.ssh_key = "~/.ssh/особый"
    t.adopt(found())
    assert (t.host, t.ssh_user, t.host_key, t.ssh_key) == (
        "10.0.0.9", "кто-то", "strict", "~/.ssh/особый")


def test_adopting_twice_changes_nothing_the_second_time():
    t = bare()
    t.adopt(found())
    assert t.adopt(found()) == []


def test_a_disagreement_is_found_without_changing_anything():
    """Узнать о расхождении надо раньше, чем прогон не пойдёт - и не ценой
    того, что под руками молча поменялись поля."""
    t = bare()
    apart = t.disagrees_with(found())
    assert apart, "расхождение не замечено"
    assert t.trex_dir == "/opt/trex", "цель поменялась, хотя её не просили"
    assert t.link_mbit == 1000


def test_a_target_that_matches_the_machine_disagrees_about_nothing():
    t = bare()
    t.adopt(found())
    assert t.disagrees_with(found()) == []
