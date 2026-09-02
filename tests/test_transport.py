"""Shipping a script somewhere and running it there."""

from __future__ import annotations

import glob

import pytest

from traphy.target import Target
from traphy.transport import LocalTransport, TransportError, open_transport


def test_output_is_streamed_line_by_line():
    seen: list[str] = []
    done = LocalTransport().run_stream(
        "for i in range(3): print('line', i)", [], seen.append)
    assert done.ok
    assert seen == ["line 0", "line 1", "line 2"]


def test_arguments_survive_spaces_and_cyrillic():
    done = LocalTransport().run("import sys; print('|'.join(sys.argv[1:]))",
                                ["два слова", "«кавычки»"])
    assert done.stdout.strip() == "два слова|«кавычки»"


def test_the_exit_code_comes_back():
    assert LocalTransport().run("import sys; sys.exit(9)", []).rc == 9
    assert LocalTransport().run("raise SystemExit(0)", []).ok


def test_stderr_is_kept_separate():
    done = LocalTransport().run(
        "import sys; print('out'); print('err', file=sys.stderr)", [])
    assert "out" in done.stdout and "err" in done.stderr


def test_the_temporary_script_is_removed_afterwards():
    """A predictable leftover under /tmp is a symlink attack on a shared box."""
    before = set(glob.glob("/tmp/traphy.*"))
    LocalTransport().run("print('hi')", [])
    assert set(glob.glob("/tmp/traphy.*")) == before


def test_a_hanging_script_is_abandoned_not_waited_on():
    with pytest.raises(TransportError, match="не завершился"):
        LocalTransport().run("import time; time.sleep(30)", [], timeout=1)


def test_open_transport_picks_local_for_a_loopback_target():
    assert isinstance(open_transport(Target()), LocalTransport)


def test_open_transport_reports_a_bad_remote_host_as_a_message():
    target = Target(use_ssh=True, host="no-such-host.invalid", ssh_user="x")
    with pytest.raises(TransportError):
        open_transport(target)


class _FakeClient:
    """Records what SshTransport asks paramiko to do."""

    def __init__(self):
        self.kwargs: dict = {}
        self.policy = None
        self.loaded_system = False

    def load_system_host_keys(self):
        self.loaded_system = True

    def load_host_keys(self, path):
        pass

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.kwargs = kwargs

    def close(self):
        pass


def _fake_paramiko(monkeypatch, client):
    """Install a paramiko stub so the SSH path can be tested without a server."""
    import sys
    import types

    module = types.ModuleType("paramiko")
    module.SSHClient = lambda: client
    module.RejectPolicy = type("RejectPolicy", (), {})
    module.WarningPolicy = type("WarningPolicy", (), {})
    module.AuthenticationException = type("AuthenticationException", (Exception,), {})
    module.SSHException = type("SSHException", (Exception,), {})
    monkeypatch.setitem(sys.modules, "paramiko", module)
    return module


def test_legacy_ssh_rsa_is_refused_on_every_connection(monkeypatch):
    """ssh-rsa is SHA-1 signed and deprecated; paramiko offers it unless told not to.

    This is the property that lets the dependency audit ignore PYSEC-2026-2858
    honestly, so it is asserted rather than left to a comment.
    """
    from traphy.transport import DISABLED_ALGORITHMS, SshTransport

    client = _FakeClient()
    _fake_paramiko(monkeypatch, client)
    SshTransport(host="10.0.0.9", user="root")

    assert client.kwargs["disabled_algorithms"] == DISABLED_ALGORITHMS
    assert "ssh-rsa" in DISABLED_ALGORITHMS["keys"]
    assert "ssh-rsa" in DISABLED_ALGORITHMS["pubkeys"]


def test_an_unknown_host_is_rejected_by_default(monkeypatch):
    """Strict is the default: a host absent from known_hosts is not trusted."""
    from traphy.transport import SshTransport

    client = _FakeClient()
    module = _fake_paramiko(monkeypatch, client)
    SshTransport(host="10.0.0.9", user="root")
    assert isinstance(client.policy, module.RejectPolicy)

    SshTransport(host="10.0.0.9", user="root", strict_host_key=False)
    assert isinstance(client.policy, module.WarningPolicy)
