"""Getting a script onto the machine that will send the traffic, and running it.

Two transports, one interface. :class:`LocalTransport` runs the script as a
subprocess here; :class:`SshTransport` runs it on another box over SSH. Callers
do not branch on which - they call :func:`open_transport` and then
``run_stream``, and the only visible difference is what :meth:`describe` says.

The script is never left lying around under a predictable name. It is piped in
base64-encoded (so quoting and Cyrillic survive the shell), written into a
freshly created private directory, executed, and removed - including when the
run fails. A fixed ``/tmp/traphy.py`` on a shared box is a symlink attack
waiting for a second user.

Host keys are checked. A host that is not already in ``known_hosts`` is
refused with an explanation, not silently trusted; blind auto-add is how an
SSH session ends up talking to whoever answered.
"""

from __future__ import annotations

import base64
import contextlib
import errno
import os
import select
import shlex
# Running a script on another machine is the whole feature; the shell-out is
# the point, not an oversight.
import subprocess  # nosec B404
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

# How long a command may run before it is abandoned. A traffic run sets this
# from its own duration; the default only covers short probes.
DEFAULT_TIMEOUT = 300

# Algorithms refused on every SSH connection. ssh-rsa signs with SHA-1 and is
# long deprecated, but paramiko still negotiates it unless told not to - both
# as a host key and as a user signature.
DISABLED_ALGORITHMS: dict[str, list[str]] = {
    "keys": ["ssh-rsa"],
    "pubkeys": ["ssh-rsa"],
}

LineCB = Callable[[str], None]


@dataclass
class Completed:
    """What a finished command left behind."""

    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class TransportError(RuntimeError):
    """A transport could not be opened or a command could not be started.

    Carries a message meant for the operator, not a stack trace: every place
    that raises this knows what the person should do about it.
    """


class Transport:
    """The two-method interface every caller actually uses."""

    def describe(self) -> str:  # pragma: no cover - trivial
        return "транспорт"

    def run_stream(self, script: str, args: list[str], on_line: LineCB,
                   timeout: int = DEFAULT_TIMEOUT, sudo: bool = False) -> Completed:
        raise NotImplementedError

    def run(self, script: str, args: list[str],
            timeout: int = DEFAULT_TIMEOUT, sudo: bool = False) -> Completed:
        """Run without watching, for callers that only want the outcome."""
        return self.run_stream(script, args, lambda _line: None, timeout, sudo)

    def close(self) -> None:
        pass

    def __enter__(self) -> Transport:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _wrap(script: str, args: list[str], python: str, sudo: bool) -> str:
    """The shell one-liner that materialises the script, runs it, removes it.

    Everything variable is quoted before it reaches a shell: the script travels
    as base64, and the interpreter and every argument go through ``shlex.quote``.
    That is what makes the ``sh -c`` and the paramiko ``exec_command`` below
    safe to hand a constructed string.

    ``sudo -n`` rather than plain ``sudo``: a password prompt on a non-interactive
    SSH channel hangs forever with nothing on screen, so it is better to fail
    immediately and tell the operator to fix their sudoers or their key.
    """
    blob = base64.b64encode(script.encode("utf-8")).decode("ascii")
    argv = " ".join(shlex.quote(a) for a in args)
    runner = f"sudo -n {shlex.quote(python)}" if sudo else shlex.quote(python)
    return (
        'd=$(mktemp -d /tmp/traphy.XXXXXXXX) || exit 70; '
        'f="$d/run.py"; '
        'trap \'rm -rf "$d"\' EXIT INT TERM; '
        f'printf %s {shlex.quote(blob)} | base64 -d > "$f" || exit 71; '
        f'{runner} -u "$f" {argv}'
    )


def _pump(stream, on_line: LineCB, deadline: float) -> list[str]:
    """Read whole lines off a pipe until it closes, or the deadline passes.

    Iterating the pipe directly would block indefinitely on a script that
    wedges without printing - the timeout would only be noticed once the
    process had already ended, which is never. Waiting on the descriptor with
    a bounded select is what makes the timeout real.
    """
    lines: list[str] = []
    buffer = b""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        try:
            ready, _w, _x = select.select([stream], [], [], min(0.5, remaining))
        except OSError as exc:
            if exc.errno == errno.EINTR:
                continue
            raise
        if not ready:
            continue
        chunk = os.read(stream.fileno(), 65536)
        if not chunk:
            break
        buffer += chunk
        *whole, buffer = buffer.split(b"\n")
        for raw in whole:
            line = raw.decode("utf-8", "replace").rstrip("\r")
            lines.append(line)
            on_line(line)
    if buffer:
        line = buffer.decode("utf-8", "replace").rstrip("\r")
        lines.append(line)
        on_line(line)
    return lines


def _kill(proc: subprocess.Popen) -> None:
    """End a run that overstayed, giving it a moment to go quietly first."""
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


class LocalTransport(Transport):
    """The sending machine is this one - no SSH to ourselves."""

    def __init__(self, python: str = "python3"):
        self.python = python

    def describe(self) -> str:
        return "локально, без SSH"

    def run_stream(self, script: str, args: list[str], on_line: LineCB,
                   timeout: int = DEFAULT_TIMEOUT, sudo: bool = False) -> Completed:
        cmd = _wrap(script, args, self.python, sudo)
        try:
            # cmd comes from _wrap, which quotes everything variable.
            proc = subprocess.Popen(  # nosec B603
                ["/bin/sh", "-c", cmd], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise TransportError(f"не удалось запустить оболочку: {exc}") from exc

        try:
            lines = _pump(proc.stdout, on_line, time.monotonic() + timeout)
        except TimeoutError:
            _kill(proc)
            raise TransportError(f"скрипт не завершился за {timeout} c") from None
        except KeyboardInterrupt:
            _kill(proc)
            raise

        rc = proc.wait()
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        return Completed(rc, "\n".join(lines), err)


class SshTransport(Transport):
    """The sending machine is somewhere else, reached with paramiko."""

    def __init__(self, host: str, user: str, port: int = 22,
                 key_filename: str = "", password: str = "",  # nosec B107
                 python: str = "python3", strict_host_key: bool = True):
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise TransportError(
                "для SSH нужен paramiko: pip install 'traphy[ssh]'") from exc

        self.host, self.user, self.port = host, user, port
        self.python = python
        self._client = paramiko.SSHClient()
        self._client.load_system_host_keys()
        known = Path.home() / ".ssh" / "known_hosts"
        if known.exists():
            with contextlib.suppress(OSError):
                self._client.load_host_keys(str(known))
        # Strict refuses an unknown host outright. Non-strict warns and accepts
        # it for this session only - still never written to known_hosts, so a
        # relaxed run does not quietly pin whatever answered.
        self._client.set_missing_host_key_policy(
            paramiko.RejectPolicy() if strict_host_key else paramiko.WarningPolicy()
        )
        try:
            self._client.connect(
                hostname=host, port=port, username=user,
                password=password or None,
                key_filename=key_filename or None,
                timeout=10, allow_agent=True, look_for_keys=True,
                # Legacy ssh-rsa is SHA-1 signed and has been deprecated for
                # years; paramiko still offers it for compatibility. Turning it
                # off for both host keys and user keys is what lets this tool
                # honestly say it is not exposed to PYSEC-2026-2858.
                disabled_algorithms=DISABLED_ALGORITHMS,
            )
        except paramiko.AuthenticationException as exc:
            raise TransportError(
                f"{user}@{host}: логин не принят - проверь ключ или агента") from exc
        except paramiko.SSHException as exc:
            raise TransportError(_ssh_hint(host, user, exc)) from exc
        except OSError as exc:
            raise TransportError(f"{host}:{port} недоступен - {exc}") from exc

    def describe(self) -> str:
        return f"SSH {self.user}@{self.host}:{self.port}"

    def run_stream(self, script: str, args: list[str], on_line: LineCB,
                   timeout: int = DEFAULT_TIMEOUT, sudo: bool = False) -> Completed:
        cmd = _wrap(script, args, self.python, sudo)
        try:
            # See _wrap: the script travels base64-encoded and every argument
            # goes through shlex.quote, so there is nothing left unquoted for
            # a shell to reinterpret.
            _stdin, stdout, stderr = self._client.exec_command(  # nosec B601
                cmd, timeout=timeout)
        except Exception as exc:
            raise TransportError(f"команда не запустилась на {self.host}: {exc}") from exc

        deadline = time.monotonic() + timeout
        lines: list[str] = []
        try:
            for raw in iter(stdout.readline, ""):
                line = raw.rstrip("\n")
                lines.append(line)
                on_line(line)
                if time.monotonic() > deadline:
                    raise TimeoutError
        except (TimeoutError, OSError) as exc:
            stdout.channel.close()
            raise TransportError(
                f"{self.host}: скрипт не завершился за {timeout} c") from exc
        rc = stdout.channel.recv_exit_status()
        err = stderr.read().decode("utf-8", "replace")
        return Completed(rc, "\n".join(lines), err)

    def close(self) -> None:
        # Closing must never raise: it runs on the way out of a failed run too.
        with contextlib.suppress(Exception):
            self._client.close()


def _ssh_hint(host: str, user: str, exc: Exception) -> str:
    """Turn paramiko's host-key refusal into something actionable."""
    text = str(exc)
    if "not found in known_hosts" in text or "Server" in text:
        return (f"ключ хоста {host} не в known_hosts - подключись один раз "
                f"вручную (ssh {user}@{host}) или сними строгую проверку в цели")
    return f"SSH к {host}: {text}"


def open_transport(target, password: str = "") -> Transport:  # nosec B107
    """The right transport for a target. Raises :class:`TransportError`.

    ``target`` is a :class:`~traphy.target.Target`; it is taken structurally so
    this module does not have to import the model.
    """
    if target.is_local:
        return LocalTransport(python=target.python)
    return SshTransport(
        host=target.host, user=target.ssh_user, port=target.ssh_port,
        key_filename=str(Path(target.ssh_key).expanduser()) if target.ssh_key else "",
        password=password, python=target.python,
        strict_host_key=target.strict_host_key,
    )


def ssh_available() -> bool:
    """Whether the SSH path can be used at all in this install."""
    try:
        import paramiko  # noqa: F401
    except ImportError:
        return False
    return True
