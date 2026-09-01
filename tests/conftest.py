"""Shared fixtures: a scratch state directory and a fake Scapy.

Every test that touches saved state gets its own ``XDG_STATE_HOME`` so a run of
the suite never reads or writes the developer's real targets and run archives.
"""

from __future__ import annotations

import sys
import types

import pytest


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Point all persisted state at a throwaway directory."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    return tmp_path / "state"


class FakeSocket:
    """Stands in for ``conf.L2socket``: records frames instead of sending."""

    def __init__(self, iface="", **_kw):
        self.iface = iface
        self.sent: list[bytes] = []
        self.closed = False

    def send(self, raw):
        self.sent.append(raw)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_scapy(monkeypatch):
    """Install a minimal ``scapy.all`` so a generated script can be exec'd.

    The point is to exercise the script's own pacing, counting and burst logic
    without root or a NIC. Frames are represented by their byte string, which
    is all the engine ever does with them.
    """
    import scapy.all as real

    sockets: list[FakeSocket] = []

    class Conf:
        @staticmethod
        def L2socket(iface="", **kw):
            sock = FakeSocket(iface, **kw)
            sockets.append(sock)
            return sock

    module = types.ModuleType("scapy.all")
    for name in ("Ether", "IP", "TCP", "UDP", "Dot1Q"):
        setattr(module, name, getattr(real, name))
    module.conf = Conf()
    module.wrpcap = lambda *a, **k: None
    module.AsyncSniffer = _FakeSniffer
    monkeypatch.setitem(sys.modules, "scapy.all", module)
    module.sockets = sockets
    return module


class _FakeSniffer:
    """A sniffer that catches a fixed number of frames, set by the test."""

    catches = 0

    def __init__(self, **kw):
        self.kw = kw
        self.results = []
        self.started = False

    def start(self):
        self.started = True
        self.results = [b"x"] * _FakeSniffer.catches

    def stop(self):
        return self.results


@pytest.fixture
def sniffer_catches(monkeypatch):
    """Let a test say how many frames the receive side will see."""
    def setter(n: int) -> None:
        _FakeSniffer.catches = n
    setter(0)
    yield setter
    setter(0)


def run_script(source: str, argv: list[str]) -> dict:
    """Execute a generated script in a fresh namespace, return its globals."""
    namespace: dict = {"__name__": "generated"}
    exec(compile(source, "generated.py", "exec"), namespace)
    namespace["_rc"] = namespace["main"](argv)
    return namespace
