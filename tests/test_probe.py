"""Asking a target what it has, and what it makes of the answer."""

from __future__ import annotations

import json
import sys

from traphy.probe import HostInfo, Iface, inspect
from traphy.transport import Completed, LocalTransport, Transport


class Fixed(Transport):
    def __init__(self, payload=None, rc=0, stderr=""):
        self.payload, self.rc, self.stderr = payload, rc, stderr

    def run_stream(self, script, args, on_line, timeout=300, sudo=False,
                   secret=""):
        line = ""
        if self.payload is not None:
            line = "@traphy " + json.dumps(self.payload)
            on_line(line)
        return Completed(self.rc, line, self.stderr)


def test_the_local_machine_answers_its_own_probe():
    """The probe must run under whatever Python the target has, with no deps."""
    info = inspect(LocalTransport(python=sys.executable))
    assert info.ok
    assert info.python.startswith("3.")
    assert info.ifaces, "хотя бы один интерфейс должен найтись"
    assert any(i.name == "lo" for i in info.ifaces)


def test_a_silent_target_is_reported_not_guessed():
    info = inspect(Fixed(payload=None, rc=1, stderr="python3: command not found"))
    assert info.ok is False
    assert "command not found" in info.error


def test_virtual_interfaces_are_kept_out_of_the_picker():
    info = HostInfo(ok=True, ifaces=[Iface("lo"), Iface("docker0"),
                                     Iface("veth3a"), Iface("ens1f0")])
    assert [i.name for i in info.usable_ifaces()] == ["ens1f0"]


def test_when_there_is_nothing_real_everything_is_offered():
    """A container may genuinely have only a veth; an empty list helps nobody."""
    info = HostInfo(ok=True, ifaces=[Iface("lo"), Iface("veth9c1")])
    assert [i.name for i in info.usable_ifaces()] == ["lo", "veth9c1"]


def test_blockers_name_what_to_fix():
    info = HostInfo(ok=True, has_scapy=False, is_root=False, can_sudo=False,
                    ifaces=[Iface("ens1", state="down")])
    blockers = info.blockers()
    assert any("Scapy" in b for b in blockers)
    assert any("root" in b for b in blockers)
    assert any("не поднят" in b for b in blockers)


def test_a_ready_target_has_no_blockers():
    info = HostInfo(ok=True, has_scapy=True, is_root=True,
                    ifaces=[Iface("ens1", state="up")])
    assert info.blockers() == []


def test_iface_description_mentions_state_and_speed():
    text = Iface("ens1", mac="00:11:22:33:44:55", state="up",
                 speed_mbit=10000, mtu=9000).describe()
    assert "up" in text and "10000" in text and "9000" in text
