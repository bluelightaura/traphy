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
