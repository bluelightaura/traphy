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
        self.raises: Exception | None = None
        self.server_key = FakeKey()
        self.closed = False

    def load_system_host_keys(self):
        self.loaded_system = True

    def load_host_keys(self, path):
        pass

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        self.kwargs = kwargs
        if self.raises is not None:
            raise self.raises

    def get_transport(self):
        return self

    def get_remote_server_key(self):
        return self.server_key

    def close(self):
        self.closed = True


def _fake_paramiko(monkeypatch, client):
    """Install a paramiko stub so the SSH path can be tested without a server."""
    import sys
    import types

    module = types.ModuleType("paramiko")
    module.SSHClient = lambda: client
    module.RejectPolicy = type("RejectPolicy", (), {})
    module.WarningPolicy = type("WarningPolicy", (), {})
    module.MissingHostKeyPolicy = type("MissingHostKeyPolicy", (), {})
    module.AuthenticationException = type("AuthenticationException", (Exception,), {})
    module.SSHException = type("SSHException", (Exception,), {})
    module.BadHostKeyException = type("BadHostKeyException",
                                      (module.SSHException,), {})
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


class FakeKey:
    """A host key with just enough surface for the fingerprint helpers."""

    def __init__(self, blob: bytes = b"host-key-one"):
        import base64 as _b64
        self._b64 = _b64.b64encode(blob).decode()

    def get_name(self):
        return "ssh-ed25519"

    def get_base64(self):
        return self._b64


def test_strict_is_the_default_and_refuses_an_unknown_host(monkeypatch):
    from traphy.transport import SshTransport

    client = _FakeClient()
    module = _fake_paramiko(monkeypatch, client)
    transport = SshTransport(host="10.0.0.9", user="root")
    assert isinstance(client.policy, module.RejectPolicy)
    assert transport.host_key_mode == "strict"


def test_accept_new_remembers_the_key_instead_of_forgetting_it(monkeypatch, tmp_path):
    """The old non-strict mode accepted anything and wrote nothing down, so
    every later connection was just as blind. This one writes it down."""
    import traphy.transport as tr
    from traphy.transport import SshTransport

    known = tmp_path / ".ssh" / "known_hosts"
    monkeypatch.setattr(tr, "known_hosts_path", lambda: known)

    client = _FakeClient()
    module = _fake_paramiko(monkeypatch, client)
    SshTransport(host="10.0.0.9", user="root", host_key="accept-new")
    assert not isinstance(client.policy, module.RejectPolicy)

    key = FakeKey()
    client.policy.missing_host_key(client, "10.0.0.9", key)
    written = known.read_text(encoding="utf-8")
    assert written.startswith("10.0.0.9 ssh-ed25519 ")
    assert key.get_base64() in written


def test_a_non_standard_port_is_written_the_openssh_way(monkeypatch, tmp_path):
    import traphy.transport as tr

    known = tmp_path / ".ssh" / "known_hosts"
    monkeypatch.setattr(tr, "known_hosts_path", lambda: known)
    tr.remember_host_key("10.0.0.9", 2222, FakeKey())
    assert known.read_text(encoding="utf-8").startswith("[10.0.0.9]:2222 ")


def test_remembering_appends_rather_than_rewriting(monkeypatch, tmp_path):
    """Somebody's known_hosts holds comments and hashed entries we cannot
    reproduce. Rewriting it would be worse than the convenience is worth."""
    import traphy.transport as tr

    known = tmp_path / ".ssh" / "known_hosts"
    known.parent.mkdir(parents=True)
    known.write_text("# мои записи\nexample.org ssh-ed25519 AAAA\n", encoding="utf-8")
    monkeypatch.setattr(tr, "known_hosts_path", lambda: known)
    tr.remember_host_key("10.0.0.9", 22, FakeKey())
    text = known.read_text(encoding="utf-8")
    assert "# мои записи" in text
    assert "example.org" in text
    assert "10.0.0.9" in text


def test_an_unknown_mode_falls_back_to_strict(monkeypatch):
    from traphy.transport import SshTransport

    client = _FakeClient()
    module = _fake_paramiko(monkeypatch, client)
    transport = SshTransport(host="10.0.0.9", user="root", host_key="чепуха")
    assert transport.host_key_mode == "strict"
    assert isinstance(client.policy, module.RejectPolicy)


def test_a_changed_key_is_refused_in_every_mode(monkeypatch):
    """Unknown and changed mean opposite things. No mode forgives the second."""
    from traphy.transport import SshTransport, TransportError

    for mode in ("strict", "accept-new"):
        client = _FakeClient()
        module = _fake_paramiko(monkeypatch, client)
        client.raises = module.BadHostKeyException()
        with pytest.raises(TransportError) as exc:
            SshTransport(host="10.0.0.9", user="root", host_key=mode)
        assert "ИЗМЕНИЛСЯ" in str(exc.value)


def test_a_pinned_fingerprint_that_does_not_match_closes_the_session(monkeypatch):
    from traphy.transport import SshTransport, TransportError

    client = _FakeClient()
    _fake_paramiko(monkeypatch, client)
    with pytest.raises(TransportError) as exc:
        SshTransport(host="10.0.0.9", user="root",
                     pinned_fingerprint="SHA256:совсем-другое")
    assert "отпечаток" in str(exc.value)
    assert client.closed


def test_a_pinned_fingerprint_that_matches_lets_the_session_stand(monkeypatch):
    from traphy.transport import SshTransport, fingerprint

    client = _FakeClient()
    _fake_paramiko(monkeypatch, client)
    expected = fingerprint(FakeKey())
    SshTransport(host="10.0.0.9", user="root", pinned_fingerprint=expected)
    assert not client.closed


def test_a_fingerprint_reads_the_way_openssh_prints_one():
    from traphy.transport import fingerprint, same_fingerprint

    got = fingerprint(FakeKey())
    assert got.startswith("SHA256:")
    assert not got.endswith("=")
    # The prefix is optional when pinning: people paste it both ways.
    assert same_fingerprint(got, got.removeprefix("SHA256:"))
    assert not same_fingerprint(got, "SHA256:другое")
    assert not same_fingerprint(got, "")




def test_a_password_is_tried_instead_of_the_agent_not_after_it(monkeypatch):
    """Keys offered ahead of a password eat the server's MaxAuthTries, and the
    password is never reached - which reads as a wrong password."""
    from traphy.transport import SshTransport

    client = _FakeClient()
    _fake_paramiko(monkeypatch, client)
    SshTransport(host="10.0.0.9", user="root", password="секрет")  # nosec B106
    assert client.kwargs["allow_agent"] is False
    assert client.kwargs["look_for_keys"] is False


def test_without_a_password_the_agent_is_still_used(monkeypatch):
    from traphy.transport import SshTransport

    client = _FakeClient()
    _fake_paramiko(monkeypatch, client)
    SshTransport(host="10.0.0.9", user="root")
    assert client.kwargs["allow_agent"] is True
    assert client.kwargs["look_for_keys"] is True


def test_a_sudo_password_makes_sudo_read_stdin_instead_of_refusing():
    """``sudo -n`` is right only while nobody has a password to offer.

    An ordinary bench account is not in sudoers with NOPASSWD, and with -n the
    run fails before the script starts - which looked like a broken target.
    """
    from traphy.transport import _wrap

    with_secret = _wrap("print(1)", [], "python3", sudo=True, secret="пароль")
    without = _wrap("print(1)", [], "python3", sudo=True)
    assert "sudo -S -p ''" in with_secret
    assert "sudo -n" in without


def test_the_secret_never_reaches_the_command_line():
    """The whole reason it goes down stdin: a shared machine has a ps."""
    from traphy.transport import _wrap

    cmd = _wrap("print(1)", ["--iface", "eth0"], "python3", sudo=True,
                secret="пароль-который-не-должен-всплыть")
    assert "пароль-который-не-должен-всплыть" not in cmd


def test_stdin_carries_the_secret_to_the_script():
    seen = LocalTransport().run_stream(
        "import sys; print('получено:', sys.stdin.readline().strip())",
        [], lambda _l: None, secret="из-stdin")
    assert "получено: из-stdin" in seen.stdout


def test_stdin_is_closed_even_when_there_is_no_secret():
    """A script that reads stdin must see EOF rather than hang forever."""
    done = LocalTransport().run_stream(
        "import sys; print('конец:', repr(sys.stdin.read()))",
        [], lambda _l: None, timeout=10)
    assert done.ok
    assert "конец: ''" in done.stdout


def test_a_local_target_runs_in_the_interpreter_that_has_scapy():
    """Системный python3 обычно без Scapy: traphy живёт в venv, и Scapy
    приезжает туда же. Локальный прогон в системном питоне падал на импорте."""
    import sys

    from traphy.transport import local_python

    assert local_python("python3") == sys.executable
    assert local_python("python") == sys.executable
    assert local_python("") == sys.executable
    # Названный явно - уважается: человек мог хотеть именно тот релиз.
    assert local_python("/opt/py39/bin/python3") == "/opt/py39/bin/python3"
