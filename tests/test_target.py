"""Targets: what makes one valid, and that saving one never loses a field."""

from __future__ import annotations

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
