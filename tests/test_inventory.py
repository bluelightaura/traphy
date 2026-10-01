"""Asking an engine about its generator - including when it cannot answer."""

from __future__ import annotations

from traphy import engines
from traphy.engines import inventory
from traphy.target import Target


def test_speed_reads_as_the_operator_says_it():
    assert inventory.Port(label="0", speed_mbit=25000).describe().endswith("25G")
    assert "1G" in inventory.Port(label="0", speed_mbit=1000).describe()
    assert "2500M" in inventory.Port(label="0", speed_mbit=2500).describe()


def test_a_held_port_names_who_has_it():
    port = inventory.Port(label="1/2", held_by="чужой прогон")
    assert not port.free
    assert "занят: чужой прогон" in port.describe()
    assert inventory.Port(label="1/2").free


def test_cannot_ask_is_not_the_same_as_no_ports():
    """An empty table would read like a dead chassis. It has to say why."""
    answer = inventory.cannot_ask("нечего спрашивать")
    assert not answer.known
    assert not answer.usable
    assert answer.summary() == "нечего спрашивать"


def test_not_asked_keeps_configuration_labelled_as_configuration():
    answer = inventory.not_asked([inventory.Port(label="0")], "не опрашивался")
    assert answer.known
    assert not answer.up          # nobody talked to the generator
    assert not answer.usable
    assert answer.ports


def test_scapy_says_it_has_no_generator_to_ask():
    answer = inventory.ask(engines.get("scapy"), Target())
    assert not answer.known
    assert "probe" in answer.summary()


def test_trex_reports_the_ports_from_the_target():
    target = Target(engine="trex", trex_port_tx=0, trex_port_rx=1)
    answer = inventory.ask(engines.get("trex"), target)
    assert [p.label for p in answer.ports] == ["0", "1"]
    assert all("trex_cfg.yaml" in p.note for p in answer.ports)
    assert "не опрашивался" in answer.note


def test_trex_without_a_receive_port_lists_only_the_one():
    target = Target(engine="trex", trex_port_tx=0, trex_port_rx=-1)
    answer = inventory.ask(engines.get("trex"), target)
    assert [p.label for p in answer.ports] == ["0"]


def test_ixia_leaves_ownership_unknown_rather_than_free():
    """Reporting an unasked port as free is how a colleague's run gets taken."""
    target = Target(engine="ixia", ixia_chassis="ch1",
                    ixia_port_tx="1/1", ixia_port_rx="1/2",
                    ixia_api_host="api")
    answer = inventory.ask(engines.get("ixia"), target)
    assert [p.label for p in answer.ports] == ["1/1", "1/2"]
    assert "занятость портов" in answer.note
    assert not answer.up


def test_every_registered_engine_answers_something():
    for key in engines.REGISTRY:
        answer = inventory.ask(engines.get(key), Target(engine=key))
        assert answer.summary()
