"""Ask the target what it has: interfaces, root, Scapy, Python.

The setup screen would otherwise make a person type an interface name from
memory and find out it was wrong only when a run failed with "no such device".
Instead, once the connection is up, TRaphy ships a small stdlib-only script
that reads ``/sys/class/net`` and reports back - so ports are *picked from what
is actually there*, with their MAC, link state and negotiated speed alongside.

The probe deliberately imports nothing beyond the standard library and does not
need root. It has to succeed on a box where Scapy is missing, because reporting
that Scapy is missing is one of the things it is for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from traphy.transport import Transport, TransportError

# Interfaces that are never a sensible place to point a traffic generator, so
# the picker hides them unless there is nothing else to show.
BORING_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "cni", "flannel",
                   "tailscale", "wg", "tun", "tap")


@dataclass
class Iface:
    """One interface on the target, as the target itself describes it."""

    name: str
    mac: str = ""
    state: str = ""            # up | down | unknown
    speed_mbit: int = 0        # 0 when the driver will not say
    mtu: int = 0
    driver: str = ""

    @property
    def is_up(self) -> bool:
        return self.state == "up"

    @property
    def interesting(self) -> bool:
        """Whether this is a plausible place to send test traffic from."""
        return not self.name.startswith(BORING_PREFIXES)

    def describe(self) -> str:
        bits = [self.mac or "-"]
        bits.append("up" if self.is_up else self.state or "?")
        if self.speed_mbit:
            bits.append(f"{self.speed_mbit} Мбит/с")
        if self.mtu and self.mtu != 1500:
            bits.append(f"MTU {self.mtu}")
        return " · ".join(bits)


@dataclass
class TrexPort:
    """Один порт генератора, как его описывает сам демон.

    Отдельно от :class:`Iface` потому, что это не интерфейс хоста: карту забрал
    DPDK, из ``/sys/class/net`` она исчезла, и рассказать про неё может только
    демон. Номер порта - индекс в его собственном списке, тот самый, который
    оператор вбивает в цель.

    Пустое поле значит «демон не сказал», а не «нет». Разница дорогая: врать
    тут можно в обе стороны - выдуманный «линк up» посылает искать поломку в
    коробке, выдуманный «занят» - искать владельца, которого нет.
    """

    index: int = 0
    link: str = ""             # up | down | "" когда не сказал
    speed_mbit: int = 0        # 0 = не сказал
    driver: str = ""
    owner: str = ""            # пусто = свободен, насколько демон знает
    state: str = ""            # IDLE | TX | DOWN - словами самого демона
    service: bool | None = None   # None = не сказал

    @property
    def free(self) -> bool:
        return not self.owner

    @property
    def link_known(self) -> bool:
        return self.link in ("up", "down")

    @property
    def is_up(self) -> bool:
        return self.link == "up"

    def describe(self) -> str:
        bits = [f"порт {self.index}"]
        if self.driver:
            bits.append(self.driver)
        if self.speed_mbit:
            bits.append(f"{self.speed_mbit // 1000}G" if
                        self.speed_mbit >= 1000 and self.speed_mbit % 1000 == 0
                        else f"{self.speed_mbit}M")
        bits.append(f"линк {self.link}" if self.link_known
                    else "линк не сказан")
        if self.owner:
            bits.append(f"занят: {self.owner}")
        if self.service:
            bits.append("сервисный режим")
        # Состояние словами демона - только когда оно добавляет новое. «линк
        # down · down» ничего не уточняет, а выглядит как две разные беды.
        state = self.state.lower()
        if state and state not in ("idle", "", self.link):
            bits.append(state)
        return " · ".join(bits)


@dataclass
class HostInfo:
    """What we learned about the target in one round trip."""

    ok: bool = False
    error: str = ""
    hostname: str = ""
    kernel: str = ""
    python: str = ""
    has_scapy: bool = False
    scapy_version: str = ""
    is_root: bool = False
    can_sudo: bool = False
    ifaces: list[Iface] = field(default_factory=list)

    # What the other engines need, collected on the same round trip so that
    # setting a target up for TRex or JMeter is answerable without a second.
    has_java: bool = False
    has_jmeter: bool = False

    # TRex is three separate questions, and collapsing them into one boolean
    # is how "TRex is installed" ends up meaning "the run will work". The
    # directory can be there without the control plane in it, and both can be
    # there with the daemon down - three different things to go and fix.
    has_trex: bool = False          # a release directory exists
    trex_dir: str = ""              # where it is
    trex_version: str = ""          # what it says it is, when it says
    has_trex_stl: bool = False      # the control plane is inside it
    # Что-то слушает на порту управления. Ровно это и ничего больше: порт
    # открыт. Говорить ли с демоном - отдельный вопрос, см. trex_rpc.
    trex_daemon: bool = False
    # Демон ответил на настоящий запрос. Без этого прогон не пойдёт, даже если
    # порт открыт.
    trex_rpc: bool = False
    trex_rpc_error: str = ""
    trex_rpc_ports: int = 0
    # Сколько портов отдано демону, по его cfg. Номер порта у TRex - индекс в
    # этом списке; карты забрал DPDK, и узнать это больше неоткуда.
    trex_ports: int = 0
    # Скорость линии по объявлению самого демона (port_bandwidth_gb). Ноль
    # значит "не сказал" - и ноль лучше догадки: это число пересчитывает
    # проценты линии в pps, и ошибка в нём тихо перекашивает весь замер.
    trex_link_mbit: int = 0
    # Порты генератора поимённо, как их описал демон: линк, скорость, драйвер,
    # владелец. До этого про порты было известно ровно одно - сколько их; номер
    # оператор вбивал на память, а «занят» и «линк упал» выяснялись отказом
    # посреди прогона.
    trex_port_info: list[TrexPort] = field(default_factory=list)

    # Ixia needs nothing on the target beyond the client library, because the
    # traffic is not produced there - it comes out of a chassis elsewhere.
    has_ixnetwork: bool = False
    ixnetwork_version: str = ""

    def usable_ifaces(self) -> list[Iface]:
        """Real NICs first; falls back to everything when there are none.

        A container or a VM may genuinely have nothing but a veth, and refusing
        to list anything there would be worse than listing something odd.
        """
        real = [i for i in self.ifaces if i.interesting]
        return real or list(self.ifaces)

    def blockers(self, engine: str = "scapy") -> list[str]:
        """What would stop a run right now, worded as something to fix.

        Which answers apply depends on the engine - Scapy wants Scapy and a raw
        socket, JMeter wants a JVM - so the judgement lives with the engine and
        this only carries the facts.
        """
        from traphy import engines

        return engines.get(engine).blockers(self)


# The probe itself. Kept as a string because it runs *there*, under whatever
# Python the target has, and must not depend on anything TRaphy installed here.
PROBE_SCRIPT = '''\
import importlib, json, os, platform, socket, subprocess, sys

def read(path, default=""):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return default

def ifaces():
    out = []
    base = "/sys/class/net"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    for name in names:
        d = base + "/" + name
        speed = read(d + "/speed", "0")
        try:
            speed = max(0, int(speed))
        except ValueError:
            speed = 0
        driver = ""
        try:
            driver = os.path.basename(os.readlink(d + "/device/driver"))
        except OSError:
            pass
        try:
            mtu = int(read(d + "/mtu", "0") or 0)
        except ValueError:
            mtu = 0
        out.append({
            "name": name,
            "mac": read(d + "/address"),
            "state": read(d + "/operstate", "unknown"),
            "speed_mbit": speed,
            "mtu": mtu,
            "driver": driver,
        })
    return out

def scapy():
    try:
        import scapy
        return True, getattr(scapy, "VERSION", "?")
    except Exception:
        return False, ""

def ixnetwork():
    try:
        import ixnetwork_restpy
        return True, getattr(ixnetwork_restpy, "__version__", "?")
    except Exception:
        return False, ""

def which(name):
    for base in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True
    return False

def trex_dirs():
    """Plausible unpacked releases, the one the target named coming first.

    Guessing at all is a fallback. The target already knows where TRex is -
    the operator typed it in - and a probe that searches its own list instead
    reports "no TRex here" about a machine whose daemon is answering, which is
    both wrong and the kind of wrong that sends somebody to reinstall a
    working release.

    A release is often /opt/trex/v3.04 rather than /opt/trex itself, so the
    versioned subdirectories count too, newest name first.
    """
    out = []
    told = sys.argv[1] if len(sys.argv) > 1 else ""
    for base in ([told] if told else []) + ["/opt/trex", "/usr/local/trex",
                                            "/opt/trex-core"]:
        if not os.path.isdir(base):
            continue
        out.append(base)
        try:
            for name in sorted(os.listdir(base), reverse=True):
                path = os.path.join(base, name)
                if os.path.isdir(path):
                    out.append(path)
        except OSError:
            pass
    # Релиз часто распакован просто в /opt/trex-3.08 - не в "trex" и не внутри
    # него. Список известных имён такой машине говорит "здесь нет TRex" при
    # живом демоне, поэтому один уровень под /opt осматривается целиком.
    # Проверка дешёвая: интересует только каталог с control plane внутри.
    for root in ("/opt", "/usr/local", "/srv"):
        try:
            names = sorted(os.listdir(root), reverse=True)
        except OSError:
            continue
        for name in names:
            path = os.path.join(root, name)
            if path in out or not os.path.isdir(path):
                continue
            if os.path.isdir(os.path.join(path, "automation",
                                          "trex_control_plane")):
                out.append(path)
    return out

def trex_facts():
    found = ""
    stl = False
    for path in trex_dirs():
        if not found:
            found = path
        if os.path.isdir(os.path.join(path, "automation", "trex_control_plane")):
            found, stl = path, True
            break
    version = ""
    if found:
        version = read(os.path.join(found, "VERSION"))
        if not version:
            tail = os.path.basename(found)
            version = tail if tail[:1] == "v" else ""
    facts = {
        "has_trex": bool(found),
        "trex_dir": found,
        "trex_version": version,
        "has_trex_stl": stl,
        "trex_daemon": answers(4501),
    }
    facts.update(trex_cfg_facts())
    if stl:
        facts.update(trex_rpc(found))
    return facts

def trex_rpc(trex_dir):
    """Отвечает ли демон НА ЗАПРОСЫ, а не просто держит порт открытым.

    Открытый TCP на 4501 доказывает ровно одно: там кто-то слушает. Этого
    достаточно, чтобы написать «связь есть», и недостаточно, чтобы прогон
    пошёл: демон, который ещё поднимается или завис, порт держит, а на запрос
    отвечает отказом транспорта. Так один прогон и умер - «связь проверена», а
    запустить нельзя.

    Поэтому здороваемся по-настоящему: подключиться и спросить число портов.
    Порты при этом не захватываются, чужой прогон не трогается.
    """
    for relative in ("automation/trex_control_plane/interactive",
                     "automation/trex_control_plane/stl"):
        path = os.path.join(trex_dir, relative)
        if os.path.isdir(path) and path not in sys.path:
            sys.path.insert(0, path)
    api = None
    for name in ("trex.stl.api", "trex_stl_lib.api"):
        try:
            api = importlib.import_module(name)
            break
        except Exception:
            continue
    if api is None:
        return {"trex_rpc": False, "trex_rpc_error": "библиотека не импортируется"}
    client = None
    try:
        client = api.STLClient(server="127.0.0.1", sync_port=4501)
        client.connect()
        count = int(client.get_port_count())
        return {"trex_rpc": True, "trex_rpc_ports": count,
                "trex_port_rows": port_rows(client, count)}
    except Exception as exc:
        return {"trex_rpc": False, "trex_rpc_error": str(exc)[:200] or type(exc).__name__}
    finally:
        try:
            if client is not None:
                client.disconnect()
        except Exception:
            pass

def port_attr(client, index):
    """Атрибуты одного порта, как их отдаёт этот релиз. {} - не отдал.

    Имя параметра у разных релизов разное, поэтому зовётся и так, и так, а
    отказ обоих - это пустой ответ, а не поломка опроса: порт, про который
    демон не рассказал, лучше показать без подробностей, чем не показать
    вовсе.
    """
    for kw in (True, False):
        try:
            value = client.get_port_attr(port=index) if kw \
                else client.get_port_attr(index)
        except Exception:
            continue
        if isinstance(value, dict):
            return value
    return {}

def owner_of(client, index, attr):
    """Кто держит порт. Пусто - свободен, насколько об этом можно судить.

    Владелец - единственное в этом опросе, что говорит про людей, а не про
    железо: генератор общий, и отобранный у коллеги порт посреди его замера -
    то, что traphy умеет и никогда не делает молча.
    """
    for key in ("owner", "owner_name", "user"):
        value = attr.get(key)
        if value:
            return str(value)
    getter = getattr(client, "get_owner", None)
    if getter is None:
        return ""
    try:
        value = getter(index)
    except Exception:
        return ""
    return str(value or "")

def speed_mbit(value):
    """Скорость порта в мегабитах, как бы демон её ни назвал.

    TRex говорит гигабитами (40 - это 40G), но у разных релизов и сборок цифра
    приезжала и мегабитами. Граница по 1000 разделяет их однозначно: порта на
    1000 Гбит/с не бывает, а на 1000 Мбит/с бывает сплошь.
    """
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return 0
    if number <= 0:
        return 0
    return number * 1000 if number < 1000 else number

def port_rows(client, count):
    """Линк, скорость, драйвер и владелец по каждому порту демона.

    Порты не захватываются: опрос не имеет права испортить чужой прогон -
    тот самый, чьего владельца он и показывает.
    """
    rows = []
    for index in range(count):
        attr = port_attr(client, index)
        link = attr.get("link", attr.get("link_status", ""))
        if isinstance(link, dict):
            link = link.get("status", link.get("link", ""))
        service = None
        for key in ("service", "service_mode", "is_service_mode"):
            if key in attr:
                raw = attr[key]
                service = (str(raw).strip().lower() in ("on", "true", "yes", "1")
                           if isinstance(raw, str) else bool(raw))
                break
        rows.append({
            "index": index,
            "link": str(link or "").strip().lower(),
            "speed_mbit": speed_mbit(attr.get("speed", 0)),
            "driver": str(attr.get("driver", "") or ""),
            "owner": owner_of(client, index, attr),
            "state": str(attr.get("state", attr.get("status", "")) or ""),
            "service": service,
        })
    return rows

def trex_cfg_facts():
    """Что демон знает о себе сам: сколько у него портов и какая линия.

    Номер порта у TRex - это индекс в его списке интерфейсов, а не имя карты:
    карты забрал DPDK и в /sys/class/net их нет. Скорость линии оттуда же -
    гадать по названию модели бессмысленно, а ошибка в ней тихо перекашивает
    пересчёт "процентов линии" в pps.

    Разбор грубый и намеренно такой: тащить YAML-парсер на машину, где его
    может не быть, ради двух чисел - плохая сделка. Берутся объявленные поля
    port_limit и port_bandwidth_gb, а список interfaces считается только если
    первого нет.
    """
    text = read("/etc/trex_cfg.yaml")
    if not text:
        return {"trex_ports": 0, "trex_link_mbit": 0}

    ports = 0
    mbit = 0
    for raw in text.splitlines():
        line = raw.strip().lstrip("- ").strip()
        if line.startswith("port_limit:"):
            ports = to_int(line.split(":", 1)[1])
        elif line.startswith("port_bandwidth_gb:"):
            gb = to_int(line.split(":", 1)[1])
            mbit = gb * 1000
    if not ports:
        ports = count_interfaces(text)
    return {"trex_ports": ports, "trex_link_mbit": mbit}

def count_interfaces(text):
    """Длина списка interfaces, с оглядкой на отступ.

    Без оглядки сюда попадают элементы соседних списков - у dual_if они тоже
    начинаются с дефиса, и порт-лишний берётся ровно так.
    """
    count = 0
    depth = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        indent = len(raw) - len(raw.lstrip())
        if depth is None:
            if stripped.startswith("interfaces"):
                depth = indent
            continue
        if indent <= depth:
            break
        if stripped.startswith("-"):
            count += 1
    return count

def to_int(text):
    digits = ""
    for ch in text.strip():
        if ch.isdigit():
            digits += ch
        elif digits:
            break
    return int(digits) if digits else 0

def answers(port):
    """Whether the daemon is listening - asked on the box itself, where the
    control port is not exposed to anyone else."""
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()

def can_sudo():
    """Whether a run could elevate here - tested with what a run would run.

    The obvious probe is `sudo -n true`, and it is wrong. The careful way to
    grant this is a rule scoped to the interpreter:

        someone ALL=(root) NOPASSWD: /usr/bin/python3

    which permits exactly what a run needs and nothing else - and fails
    `sudo -n true`. Reporting "нет sudo" there sends the operator to widen a
    permission that was deliberately narrow, to fix a problem that does not
    exist. So the interpreter is tried first, by name, the way the transport
    invokes it; `true` remains as the second chance for a blanket rule.
    """
    if os.geteuid() == 0:
        return True
    for probe in (["sudo", "-n", "python3", "-c", ""], ["sudo", "-n", "true"]):
        try:
            if subprocess.call(probe, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0:
                return True
        except OSError:
            return False
    return False

has, version = scapy()
has_ixnet, ixnet_version = ixnetwork()
info = {
    "ev": "host",
    "ok": True,
    "hostname": socket.gethostname(),
    "kernel": platform.release(),
    "python": platform.python_version(),
    "has_scapy": has,
    "scapy_version": version,
    "is_root": os.geteuid() == 0,
    "can_sudo": can_sudo(),
    "ifaces": ifaces(),
    "has_java": which("java"),
    "has_jmeter": which("jmeter"),
    "has_ixnetwork": has_ixnet,
    "ixnetwork_version": ixnet_version,
}
info.update(trex_facts())
print("@traphy " + json.dumps(info))
'''


def inspect(transport: Transport, timeout: int = 30,
            trex_dir: str = "") -> HostInfo:
    """Run the probe and turn its answer into a :class:`HostInfo`.

    ``trex_dir`` is where the target says its TRex lives; it is searched before
    the usual places, so a release unpacked somewhere unusual is still found.

    Never raises for an unhelpful target: a probe that fails comes back as an
    info object with ``ok`` False and a reason, because the setup screen wants
    to show that, not handle an exception.
    """
    from traphy.runner import parse_event

    payload: dict[str, Any] | None = None

    def take(line: str) -> None:
        nonlocal payload
        event = parse_event(line)
        if event and event.get("ev") == "host":
            payload = event

    try:
        completed = transport.run_stream(
            PROBE_SCRIPT, [trex_dir] if trex_dir else [], take, timeout=timeout)
    except TransportError as exc:
        return HostInfo(ok=False, error=str(exc))

    if payload is None:
        reason = (completed.stderr or completed.stdout).strip().splitlines()
        tail = reason[-1] if reason else f"код {completed.rc}"
        return HostInfo(ok=False, error=f"цель не ответила на опрос: {tail}")

    return HostInfo(
        ok=True,
        hostname=str(payload.get("hostname", "")),
        kernel=str(payload.get("kernel", "")),
        python=str(payload.get("python", "")),
        has_scapy=bool(payload.get("has_scapy")),
        scapy_version=str(payload.get("scapy_version", "")),
        is_root=bool(payload.get("is_root")),
        can_sudo=bool(payload.get("can_sudo")),
        ifaces=[_iface(d) for d in payload.get("ifaces", []) if isinstance(d, dict)],
        has_java=bool(payload.get("has_java")),
        has_jmeter=bool(payload.get("has_jmeter")),
        has_trex=bool(payload.get("has_trex")),
        trex_dir=str(payload.get("trex_dir", "")),
        trex_version=str(payload.get("trex_version", "")),
        has_trex_stl=bool(payload.get("has_trex_stl")),
        trex_daemon=bool(payload.get("trex_daemon")),
        trex_rpc=bool(payload.get("trex_rpc")),
        trex_rpc_error=str(payload.get("trex_rpc_error", "")),
        trex_rpc_ports=int(payload.get("trex_rpc_ports") or 0),
        trex_ports=int(payload.get("trex_ports") or 0),
        trex_link_mbit=int(payload.get("trex_link_mbit") or 0),
        trex_port_info=[_trex_port(d) for d in payload.get("trex_port_rows", [])
                        if isinstance(d, dict)],
        has_ixnetwork=bool(payload.get("has_ixnetwork")),
        ixnetwork_version=str(payload.get("ixnetwork_version", "")),
    )


def _trex_port(d: dict[str, Any]) -> TrexPort:
    service = d.get("service")
    return TrexPort(
        index=int(d.get("index", 0) or 0),
        link=str(d.get("link", "") or "").strip().lower(),
        speed_mbit=int(d.get("speed_mbit", 0) or 0),
        driver=str(d.get("driver", "") or ""),
        owner=str(d.get("owner", "") or ""),
        state=str(d.get("state", "") or ""),
        service=None if service is None else bool(service),
    )


def _iface(d: dict[str, Any]) -> Iface:
    return Iface(
        name=str(d.get("name", "")),
        mac=str(d.get("mac", "")),
        state=str(d.get("state", "unknown")),
        speed_mbit=int(d.get("speed_mbit", 0) or 0),
        mtu=int(d.get("mtu", 0) or 0),
        driver=str(d.get("driver", "")),
    )
