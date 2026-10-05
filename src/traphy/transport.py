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
import hashlib
import os
import re
import select
import shlex
# Running a script on another machine is the whole feature; the shell-out is
# the point, not an oversight.
import subprocess  # nosec B404
import sys
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

# What to do about a host key we have never seen. Two modes, and neither of
# them covers the third case on purpose:
#
# * ``strict`` - an unknown host is refused. Nothing is written anywhere.
# * ``accept-new`` - an unknown host is accepted once, said out loud, and
#   remembered, so the next connection is checked against it.
#
# A host key that has *changed* is refused under both, always. Unknown and
# changed look similar in a traceback and mean opposite things: the first is a
# machine nobody has met yet, the second is a machine that is not the one we
# met last time. Collapsing them into one switch is how "just turn off the
# checking" becomes the habit that hides the second case forever.
HOST_KEY_MODES = ("strict", "accept-new")
DEFAULT_HOST_KEY_MODE = "strict"

# Пароли приходят из окружения, а не из файла цели и не из аргументов.
# Причина та же, по которой их там нет у Ixia: файл цели человек показывает
# коллеге и кладёт в заметки, а аргумент виден в ps на общей машине.
SSH_PASSWORD_ENV = "TRAPHY_SSH_PASSWORD"  # nosec B105
SUDO_PASSWORD_ENV = "TRAPHY_SUDO_PASSWORD"  # nosec B105
# Пароль telnet - отдельной переменной. telnet несёт его открытым текстом, и
# путать с паролем SSH, который уходит зашифрованным, нельзя.
TELNET_PASSWORD_ENV = "TRAPHY_TELNET_PASSWORD"  # nosec B105


def ssh_password() -> str:
    """Пароль SSH из окружения, если он там есть."""
    return os.environ.get(SSH_PASSWORD_ENV, "")


def sudo_password() -> str:
    """Пароль sudo на цели из окружения, если он там есть."""
    return os.environ.get(SUDO_PASSWORD_ENV, "")


def telnet_password() -> str:
    """Пароль telnet из окружения. Открытым текстом по сети - см. транспорт."""
    return os.environ.get(TELNET_PASSWORD_ENV, "")


def known_hosts_path() -> Path:
    """The file new keys are remembered in - the ordinary OpenSSH one."""
    return Path.home() / ".ssh" / "known_hosts"


def fingerprint(key) -> str:
    """A key as OpenSSH prints it: ``SHA256:`` and unpadded base64."""
    raw = base64.b64decode(key.get_base64())
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def same_fingerprint(actual: str, expected: str) -> bool:
    """Compare a pinned fingerprint, with or without the ``SHA256:`` prefix.

    People paste these out of an ssh banner, out of a wiki page and out of a
    chat message, and the prefix survives about half those trips. Refusing a
    correct fingerprint over punctuation would teach exactly one lesson: stop
    pinning fingerprints.
    """
    def bare(text: str) -> str:
        return text.strip().removeprefix("SHA256:").rstrip("=")

    return bool(expected) and bare(actual) == bare(expected)


def remember_host_key(host: str, port: int, key) -> None:
    """Append one host key to known_hosts, leaving the rest of the file alone.

    Deliberately an append rather than paramiko's ``save()``: that rewrites the
    whole file from what it happens to have loaded, and a tool that quietly
    reformats somebody's known_hosts - dropping comments, hashed entries and
    keys it did not parse - has done more damage than the convenience is worth.
    """
    entry = host if port == 22 else f"[{host}]:{port}"
    line = f"{entry} {key.get_name()} {key.get_base64()}\n"
    path = known_hosts_path()
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)


def _missing_key_policy(paramiko, mode: str, host: str, port: int,
                        learned: list[str]):
    """The policy object for this mode; anything unrecognised means strict."""
    if mode != "accept-new":
        return paramiko.RejectPolicy()

    class AcceptNew(paramiko.MissingHostKeyPolicy):
        """Accept a host we have never seen - once, loudly, and remembered."""

        def missing_host_key(self, client, hostname, key):
            remember_host_key(host, port, key)
            learned.append(fingerprint(key))

    return AcceptNew()

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
                   timeout: int = DEFAULT_TIMEOUT, sudo: bool = False,
                   secret: str = "") -> Completed:  # nosec B107
        raise NotImplementedError

    def run(self, script: str, args: list[str],
            timeout: int = DEFAULT_TIMEOUT, sudo: bool = False,
            secret: str = "") -> Completed:  # nosec B107
        """Run without watching, for callers that only want the outcome."""
        return self.run_stream(script, args, lambda _line: None, timeout, sudo,
                               secret)

    def close(self) -> None:
        pass

    def __enter__(self) -> Transport:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _wrap(script: str, args: list[str], python: str, sudo: bool,
          secret: str = "") -> str:  # nosec B107
    """The shell one-liner that materialises the script, runs it, removes it.

    Everything variable is quoted before it reaches a shell: the script travels
    as base64, and the interpreter and every argument go through ``shlex.quote``.
    That is what makes the ``sh -c`` and the paramiko ``exec_command`` below
    safe to hand a constructed string.

    ``sudo -n`` rather than plain ``sudo``: a password prompt on a non-interactive
    SSH channel hangs forever with nothing on screen, so it is better to fail
    immediately and tell the operator to fix their sudoers or their key.

    Unless a secret is coming. Then it is ``sudo -S`` with the prompt silenced,
    because sudo reads the password from stdin and passes the rest through to
    the script - and stdin is the one channel that is neither written to a file
    nor visible in ``ps`` on a shared machine, which is where a bench password
    must not appear. A prompt still cannot hang: the password is already on its
    way before the process starts.
    """
    blob = base64.b64encode(script.encode("utf-8")).decode("ascii")
    argv = " ".join(shlex.quote(a) for a in args)
    if sudo:
        runner = f"sudo -S -p '' {shlex.quote(python)}" if secret \
            else f"sudo -n {shlex.quote(python)}"
    else:
        runner = shlex.quote(python)
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
                   timeout: int = DEFAULT_TIMEOUT, sudo: bool = False,
                   secret: str = "") -> Completed:  # nosec B107
        cmd = _wrap(script, args, self.python, sudo, secret)
        try:
            # cmd comes from _wrap, which quotes everything variable.
            proc = subprocess.Popen(  # nosec B603
                ["/bin/sh", "-c", cmd], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, stdin=subprocess.PIPE,
            )
        except OSError as exc:
            raise TransportError(f"не удалось запустить оболочку: {exc}") from exc

        # Closed either way: a script that reads stdin must see the end of it
        # rather than waiting for input that is never coming.
        with contextlib.suppress(OSError):
            if secret:
                proc.stdin.write(secret.encode("utf-8") + b"\n")
            proc.stdin.close()

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
                 python: str = "python3",
                 host_key: str = DEFAULT_HOST_KEY_MODE,
                 pinned_fingerprint: str = ""):
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise TransportError(
                "для SSH нужен paramiko: pip install 'traphy[ssh]'") from exc

        self.host, self.user, self.port = host, user, port
        self.python = python
        self.host_key_mode = host_key if host_key in HOST_KEY_MODES \
            else DEFAULT_HOST_KEY_MODE
        # Filled in when this connection was the first to meet the host, so a
        # caller can say so rather than leaving a new key silently pinned.
        self.learned_fingerprint = ""

        self._client = paramiko.SSHClient()
        self._client.load_system_host_keys()
        known = known_hosts_path()
        if known.exists():
            with contextlib.suppress(OSError):
                self._client.load_host_keys(str(known))
        learned: list[str] = []
        self._client.set_missing_host_key_policy(
            _missing_key_policy(paramiko, self.host_key_mode, host, port, learned))
        try:
            self._client.connect(
                hostname=host, port=port, username=user,
                password=password or None,
                key_filename=key_filename or None,
                timeout=10,
                # A password means the password; a named key means that key.
                # Offering agent and on-disk keys on top of either looks
                # helpful and is how both quietly break:
                #  - every key counts against the server's MaxAuthTries (six
                #    by default), so a developer with three keys loaded gets
                #    "логин не принят" before the password is ever tried;
                #  - an agent holding a key that cannot sign - an RSA key when
                #    this tool disables ssh-rsa - aborts the whole connection
                #    with "key cannot be used for signing" before the named key
                #    gets its turn. "Use this key" has to mean only this key.
                allow_agent=not (password or key_filename),
                look_for_keys=not (password or key_filename),
                # Legacy ssh-rsa is SHA-1 signed and has been deprecated for
                # years; paramiko still offers it for compatibility. Turning it
                # off for both host keys and user keys is what lets this tool
                # honestly say it is not exposed to PYSEC-2026-2858.
                disabled_algorithms=DISABLED_ALGORITHMS,
            )
        except paramiko.BadHostKeyException as exc:
            # The one case no mode forgives. Refused before authentication, so
            # no password or key has been offered to whoever answered.
            raise TransportError(
                f"ключ хоста {host} ИЗМЕНИЛСЯ - так выглядит подмена машины. "
                f"Если она действительно переустановлена, убери её строку из "
                f"{known_hosts_path()} вручную и подключись заново") from exc
        except paramiko.AuthenticationException as exc:
            # Назвать ВСЕ три способа, а не только тот, который уже не сработал.
            # Прежняя формулировка советовала проверить ключ и агента - и
            # умалчивала про поле «пароль SSH», которое стоит на том же экране
            # строкой выше. Человек с неавторизованным ключом читал её как
            # «чини ключ» и упирался в неё раз за разом.
            how = ("задай пароль - в настройке цели поле «пароль SSH», "
                   "или переменной TRAPHY_SSH_PASSWORD"
                   if not password else
                   "пароль не подошёл - проверь его, либо задай ключ")
            raise TransportError(
                f"{user}@{host}: логин не принят. {how}; "
                f"ключ можно положить на хост через ssh-copy-id") from exc
        except paramiko.SSHException as exc:
            raise TransportError(_ssh_hint(host, user, exc, self.host_key_mode)) from exc
        except OSError as exc:
            raise TransportError(f"{host}:{port} недоступен - {exc}") from exc

        if learned:
            self.learned_fingerprint = learned[0]
        self._check_pinned(pinned_fingerprint)

    def _check_pinned(self, expected: str) -> None:
        """Refuse a host that is not the exact one the target named.

        Pinning is stronger than known_hosts and answers a different question:
        known_hosts says "the same machine as last time", a pinned fingerprint
        says "this machine". On a shared bench where boxes get reinstalled,
        that difference is the whole point.
        """
        if not expected:
            return
        transport = self._client.get_transport()
        key = transport.get_remote_server_key() if transport else None
        actual = fingerprint(key) if key is not None else ""
        if not same_fingerprint(actual, expected):
            self._client.close()
            raise TransportError(
                f"отпечаток {self.host} не совпал с закреплённым в цели: "
                f"ожидался {expected}, машина показала {actual or 'ничего'}")

    def describe(self) -> str:
        return f"SSH {self.user}@{self.host}:{self.port}"

    def fetch(self, remote_path: str, local_path: Path) -> bool:
        """SFTP over the session that is already open - no second login."""
        try:
            sftp = self._client.open_sftp()
        except Exception:  # pragma: no cover - server without the subsystem
            return False
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(remote_path, str(local_path))
        except (OSError, EOFError):
            return False
        finally:
            with contextlib.suppress(Exception):
                sftp.close()
        return True

    def run_stream(self, script: str, args: list[str], on_line: LineCB,
                   timeout: int = DEFAULT_TIMEOUT, sudo: bool = False,
                   secret: str = "") -> Completed:  # nosec B107
        cmd = _wrap(script, args, self.python, sudo, secret)
        try:
            # See _wrap: the script travels base64-encoded and every argument
            # goes through shlex.quote, so there is nothing left unquoted for
            # a shell to reinterpret.
            stdin, stdout, stderr = self._client.exec_command(  # nosec B601
                cmd, timeout=timeout)
        except Exception as exc:
            raise TransportError(f"команда не запустилась на {self.host}: {exc}") from exc

        # The password goes over the already-encrypted channel and never
        # reaches a command line, a file or the process table on the target.
        with contextlib.suppress(Exception):
            if secret:
                stdin.write(secret + "\n")
                stdin.flush()
            stdin.channel.shutdown_write()

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


# Байты протокола telnet. Нужны не ради поддержки опций, а чтобы вынуть их из
# потока: сервер шлёт переговоры об опциях вперемешку с текстом, и без разбора
# они попадали бы в вывод как мусор.
_IAC, _DONT, _DO, _WONT, _WILL, _SB, _SE = (255, 254, 253, 252, 251, 250, 240)


def _telnet_filter(data: bytes, sock) -> bytes:
    """Выкинуть переговоры об опциях, на каждое предложение ответив отказом.

    Минимальный, но корректный клиент: опции мы не поддерживаем ни одной, и на
    любое DO/WILL отвечаем WONT/DONT. Этого хватает для строчного режима, в
    котором работает консоль, и ничем не грозит: сервер просто остаётся при
    своих умолчаниях.
    """
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte != _IAC:
            out.append(byte)
            i += 1
            continue
        if i + 1 >= len(data):
            break
        cmd = data[i + 1]
        if cmd in (_DO, _DONT, _WILL, _WONT) and i + 2 < len(data):
            opt = data[i + 2]
            answer = _WONT if cmd in (_DO, _DONT) else _DONT
            with contextlib.suppress(OSError):
                sock.sendall(bytes([_IAC, answer, opt]))
            i += 3
        elif cmd == _SB:                      # подпереговоры - до IAC SE
            end = data.find(bytes([_IAC, _SE]), i)
            i = end + 2 if end != -1 else len(data)
        else:
            i += 2
    return bytes(out)


class TelnetTransport(Transport):
    """Отправляющая машина доступна только по telnet.

    Это запасной вход, а не равноправный. Весь смысл в одной фразе: telnet
    передаёт логин и пароль открытым текстом, их видит любой на пути. Поэтому
    он здесь ради лабораторных генераторов, на которых поднят один telnetd и
    добраться иначе нельзя, - и ни для чего больше. Где есть SSH, берётся SSH.

    Логинится в интерактивную оболочку, прогоняет тот же base64-свёрток, что и
    SSH, и ловит конец по маркеру с кодом возврата: у telnet нет отдельного
    канала статуса, как у SSH, - только то, что команда сама напечатает.
    """

    _CTRL_C = b"\x03"

    def __init__(self, host: str, user: str, port: int = 23,
                 password: str = "", python: str = "python3",  # nosec B107
                 prompt: str = r"[$#>]\s*$", connect_timeout: int = 10):
        import socket as _socket

        self.host, self.user, self.port = host, user, port
        self.python = python
        self._prompt = re.compile(prompt.encode() if isinstance(prompt, str)
                                  else prompt)
        try:
            self._sock = _socket.create_connection((host, port),
                                                   timeout=connect_timeout)
        except OSError as exc:
            raise TransportError(f"{host}:{port} недоступен по telnet - {exc}") from exc
        self._sock.settimeout(1.0)
        try:
            self._login(user, password)
        except TransportError:
            self.close()
            raise

    def _read_until(self, pattern, timeout: float) -> bytes:
        """Читать, вычищая опции telnet, пока не совпадёт образец или таймаут."""
        rx = pattern if hasattr(pattern, "search") else re.compile(pattern, re.I)
        buf, deadline = bytearray(), time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = self._sock.recv(4096)
            except TimeoutError:
                if rx.search(bytes(buf)):
                    return bytes(buf)
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += _telnet_filter(chunk, self._sock)
            if rx.search(bytes(buf)):
                return bytes(buf)
        return bytes(buf)

    def _send(self, line: str) -> None:
        with contextlib.suppress(OSError):
            self._sock.sendall(line.encode() + b"\r")

    def _login(self, user: str, password: str) -> None:
        # Консоль могла остаться в середине чужого недовведённого логина -
        # сбросить ввод и дождаться чистого приглашения, а не лить поверх.
        with contextlib.suppress(OSError):
            self._sock.sendall(self._CTRL_C)
        self._send("")
        greet = self._read_until(rb"(login|username|password)\s*:\s*$|" +
                                 self._prompt.pattern, 10)
        if self._prompt.search(greet):
            return                             # уже в оболочке (без логина)
        if re.search(rb"(login|username)\s*:", greet, re.I):
            self._send(user)
            self._read_until(rb"password\s*:", 8)
            self._send(password)
        elif re.search(rb"password\s*:", greet, re.I):
            self._send(password)
        after = self._read_until(self._prompt.pattern +
                                 rb"|(incorrect|denied|bad password|failed)", 12)
        if re.search(rb"(incorrect|denied|bad password|failed|no such)", after, re.I):
            raise TransportError(
                f"{user}@{self.host}: логин по telnet не принят - проверь имя, "
                f"пароль (переменная {TELNET_PASSWORD_ENV}) и что это та машина")
        if not self._prompt.search(after):
            raise TransportError(
                f"{user}@{self.host}: приглашение оболочки не пришло - "
                f"возможно, консоль занята другим сеансом")

    def describe(self) -> str:
        return f"telnet {self.user}@{self.host}:{self.port} (открытый текст!)"

    def run_stream(self, script: str, args: list[str], on_line: LineCB,
                   timeout: int = DEFAULT_TIMEOUT, sudo: bool = False,
                   secret: str = "") -> Completed:  # nosec B107
        cmd = _wrap(script, args, self.python, sudo, secret)
        # У telnet нет канала кода возврата - обрамляем вывод маркерами сами:
        # начало, чтобы отрезать эхо самой команды, и конец с $? в нём.
        start, end = "__TRX_B__", "__TRX_E__"
        self._send(f"echo {start}; {cmd}; echo {end}$?{end}")

        # sudo -S читает пароль со stdin, а stdin здесь - тот же tty: шлём его
        # следующей строкой. Над открытым каналом это, конечно, не секрет.
        if secret:
            time.sleep(0.3)
            self._send(secret)

        tail = re.compile(re.escape(end).encode() + rb"(\d+)" + re.escape(end).encode())
        raw = self._read_until(tail, timeout)
        match = tail.search(raw)
        if match is None:
            raise TransportError(
                f"{self.host}: команда не завершилась за {timeout} c по telnet")
        rc = int(match.group(1))

        text = raw.decode("utf-8", "replace")
        body = text.split(start, 1)[-1].split(end, 1)[0]
        lines = [ln.rstrip("\r") for ln in body.splitlines()]
        # Первая строка - эхо «echo __TRX_B__» с остатком команды; её не отдаём.
        collected = []
        for ln in lines:
            if start in ln or ln.strip() == "":
                continue
            collected.append(ln)
            on_line(ln)
        return Completed(rc, "\n".join(collected), "")

    def fetch(self, remote_path: str, local_path: Path) -> bool:
        """Забрать файл через base64 по той же оболочке - SFTP у telnet нет."""
        marker = "__TRX_F__"
        self._send(f"echo {marker}; base64 {shlex.quote(remote_path)} 2>/dev/null; "
                   f"echo {marker}")
        raw = self._read_until(re.escape(marker).encode() + rb".*" +
                               re.escape(marker).encode(), 60)
        text = raw.decode("utf-8", "replace")
        parts = text.split(marker)
        if len(parts) < 3:
            return False
        blob = "".join(parts[1].split())
        try:
            data = base64.b64decode(blob, validate=False)
        except (ValueError, TypeError):       # мусор вместо base64 = нет файла
            return False
        if not data:
            return False
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(data)
        except OSError:
            return False
        return True

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._sock.close()


def _ssh_hint(host: str, user: str, exc: Exception,
              mode: str = DEFAULT_HOST_KEY_MODE) -> str:
    """Turn paramiko's host-key refusal into something actionable.

    The advice differs by mode on purpose. Under ``strict`` there are two
    honest ways forward and both are named; suggesting "turn the checking off"
    is not one of them, because the mode that exists instead of that remembers
    what it accepted.
    """
    text = str(exc)
    if "not found in known_hosts" in text or "Server" in text:
        if mode == "strict":
            return (f"ключ хоста {host} не в known_hosts - подключись один раз "
                    f"вручную (ssh {user}@{host}) либо поставь в цели режим "
                    f"accept-new, он примет ключ один раз и запомнит его")
        return (f"ключ хоста {host} не принят - {text}")
    return f"SSH к {host}: {text}"


def open_transport(target, password: str = "") -> Transport:  # nosec B107
    """The right transport for a target. Raises :class:`TransportError`.

    ``target`` is a :class:`~traphy.target.Target`; it is taken structurally so
    this module does not have to import the model.
    """
    if target.is_local:
        return LocalTransport(python=local_python(target.python))
    if getattr(target, "transport", "ssh") == "telnet":
        return TelnetTransport(
            host=target.host, user=target.ssh_user, port=target.ssh_port,
            password=password or telnet_password(), python=target.python)
    return SshTransport(
        host=target.host, user=target.ssh_user, port=target.ssh_port,
        key_filename=str(Path(target.ssh_key).expanduser()) if target.ssh_key else "",
        password=password, python=target.python,
        host_key=target.host_key,
        pinned_fingerprint=target.host_key_fingerprint,
    )


def local_python(named: str) -> str:
    """Какой интерпретатор запускать здесь, когда цель локальная.

    Скрипту нужен Scapy. Системный ``python3`` его обычно не имеет: traphy
    ставят в venv, и Scapy приезжает туда же как её зависимость. Поэтому,
    пока цель не назвала интерпретатор явно, берётся тот, в котором traphy
    сейчас и работает - он Scapy заведомо видит.

    На удалённой машине так делать нельзя: путь отсюда там ничего не значит.
    """
    return sys.executable if named in ("", "python3", "python") else named


def ssh_available() -> bool:
    """Whether the SSH path can be used at all in this install."""
    try:
        import paramiko  # noqa: F401
    except ImportError:
        return False
    return True
