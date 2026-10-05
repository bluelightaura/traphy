"""Вход по telnet: логин в оболочку, прогон свёртка, забор файла.

Проверяется против поддельного telnetd в потоке - настоящий сокет, настоящие
переговоры об опциях, настоящий разбор маркеров. Подделка сервера, а не
транспорта: иначе тест проверял бы сам себя.

Ни одного обращения в сеть наружу: сервер слушает localhost на случайном порту.
"""
from __future__ import annotations

import base64
import socket
import threading
import time

import pytest

from traphy.transport import TelnetTransport, TransportError

IAC, DO, WILL = 255, 253, 251
PROMPT = b"gen# "


class FakeTelnetd:
    """Маленький telnetd: приветствие, логин, оболочка, ответы по маркерам."""

    def __init__(self, user="root", password="test-pw-9", good=True):  # nosec B106 - фейковый пароль поддельного telnetd
        self.user, self.password, self.good = user, password, good
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        self.seen: list[str] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _recv_line(self, conn) -> str:
        buf = b""
        conn.settimeout(5.0)
        while not buf.endswith(b"\r") and not buf.endswith(b"\n"):
            try:
                chunk = conn.recv(256)
            except (TimeoutError, OSError):
                break
            if not chunk:
                break
            # выкинуть ответы клиента об опциях (IAC x y)
            out = b""
            i = 0
            while i < len(chunk):
                if chunk[i] == IAC and i + 2 < len(chunk):
                    i += 3
                else:
                    out += chunk[i:i + 1]
                    i += 1
            buf += out
        return buf.strip().decode("utf-8", "replace")

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        with conn:
            # немного переговоров об опциях - проверяем, что клиент их съест
            conn.sendall(bytes([IAC, DO, 3, IAC, WILL, 1]))
            conn.sendall(b"\r\nUser Access Verification\r\nUsername: ")
            self._recv_line(conn)                 # приглашение могло быть
            user = self._recv_line(conn) or self._recv_line(conn)
            conn.sendall(b"\r\nPassword: ")
            pwd = self._recv_line(conn)
            if not self.good or user.split()[-1:] != [self.user] or pwd != self.password:
                conn.sendall(b"\r\n  %No such user or bad password.\r\nUsername: ")
                time.sleep(0.2)
                return
            conn.sendall(b"\r\n" + PROMPT)
            while True:
                line = self._recv_line(conn)
                if not line:
                    break
                self.seen.append(line)
                if "__TRX_B__" in line:
                    conn.sendall(b"__TRX_B__\r\nhello from telnet\r\n"
                                 b"second line\r\n__TRX_E__0__TRX_E__\r\n" + PROMPT)
                elif "__TRX_F__" in line and "base64" in line:
                    blob = base64.b64encode(b"PCAP-BYTES-\x00\x01").decode()
                    conn.sendall(b"__TRX_F__\r\n" + blob.encode()
                                 + b"\r\n__TRX_F__\r\n" + PROMPT)
                elif "exit" in line:
                    break

    def close(self):
        with __import__("contextlib").suppress(OSError):
            self._srv.close()


@pytest.fixture
def telnetd():
    srv = FakeTelnetd()
    yield srv
    srv.close()


def test_logs_in_and_reaches_the_shell(telnetd):
    t = TelnetTransport("127.0.0.1", "root", port=telnetd.port, password="test-pw-9")  # nosec B106 - фейковый пароль поддельного telnetd
    assert "telnet" in t.describe()
    t.close()


def test_describe_warns_it_is_cleartext(telnetd):
    t = TelnetTransport("127.0.0.1", "root", port=telnetd.port, password="test-pw-9")  # nosec B106 - фейковый пароль поддельного telnetd
    assert "открытый текст" in t.describe()
    t.close()


def test_wrong_password_is_refused_with_a_reason():
    srv = FakeTelnetd(good=False)
    try:
        with pytest.raises(TransportError) as exc:
            TelnetTransport("127.0.0.1", "root", port=srv.port, password="нет")  # nosec B106 - неверный пароль для теста отказа
        assert "не принят" in str(exc.value)
    finally:
        srv.close()


def test_runs_a_command_and_streams_its_lines(telnetd):
    t = TelnetTransport("127.0.0.1", "root", port=telnetd.port, password="test-pw-9")  # nosec B106 - фейковый пароль поддельного telnetd
    seen = []
    done = t.run_stream("print('x')", [], seen.append)
    assert done.rc == 0
    assert "hello from telnet" in seen
    assert "second line" in seen
    # эхо самой команды с маркером наружу не отдаётся
    assert not any("__TRX_B__" in line for line in seen)
    t.close()


def test_the_command_actually_carried_the_script(telnetd):
    t = TelnetTransport("127.0.0.1", "root", port=telnetd.port, password="test-pw-9")  # nosec B106 - фейковый пароль поддельного telnetd
    t.run_stream("print('x')", [], lambda _l: None)
    sent = "\n".join(telnetd.seen)
    # свёрток уезжает base64 внутри echo-обрамления
    assert "__TRX_B__" in sent and "base64 -d" in sent
    t.close()


def test_fetch_pulls_a_file_over_the_shell(telnetd, tmp_path):
    t = TelnetTransport("127.0.0.1", "root", port=telnetd.port, password="test-pw-9")  # nosec B106 - фейковый пароль поддельного telnetd
    out = tmp_path / "rx.pcap"
    assert t.fetch("/tmp/rx.pcap", out) is True
    assert out.read_bytes() == b"PCAP-BYTES-\x00\x01"
    t.close()


def test_a_dead_host_is_reported_not_hung():
    # Порт, на котором никто не слушает: отказ, а не зависание.
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    with pytest.raises(TransportError) as exc:
        TelnetTransport("127.0.0.1", "root", port=port, password="x",
                        connect_timeout=2)
    assert "недоступен" in str(exc.value)


def test_open_transport_picks_telnet_for_a_telnet_target(monkeypatch):
    """Поле transport='telnet' на удалённой цели ведёт в TelnetTransport."""
    from traphy import transport
    from traphy.target import Target

    chosen = {}

    def fake_telnet(**kw):
        chosen["telnet"] = kw
        return "TELNET"

    def fake_ssh(**kw):
        chosen["ssh"] = kw
        return "SSH"

    monkeypatch.setattr(transport, "TelnetTransport", fake_telnet)
    monkeypatch.setattr(transport, "SshTransport", fake_ssh)
    monkeypatch.setenv("TRAPHY_TELNET_PASSWORD", "test-pw-9")

    target = Target(use_ssh=True, transport="telnet", host="203.0.113.5",
                    ssh_user="root", ssh_port=2008)
    assert transport.open_transport(target) == "TELNET"
    assert chosen["telnet"]["host"] == "203.0.113.5"
    assert chosen["telnet"]["port"] == 2008

    # а без поля - по-прежнему SSH
    chosen.clear()
    ssh_target = Target(use_ssh=True, transport="ssh", host="203.0.113.5",
                        ssh_user="root")
    assert transport.open_transport(ssh_target) == "SSH"
