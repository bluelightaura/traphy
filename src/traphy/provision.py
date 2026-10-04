"""Подготовить генератор к работе с TRex - и показать, чем за это платят.

Разведка целей (``probe.py``) отвечает на вопрос «что на машине есть». Этот
модуль отвечает на следующий: «чего не хватает, чтобы TRex поднялся, и что
придётся сделать с машиной». Разница принципиальная. Привязка карты к DPDK
уводит её из ядра целиком: интерфейс исчезает из ``ip link``, маршруты через
него пропадают, а тот, кто ходил на стенд через эту карту, теряет связь и
узнаёт об этом последним.

Поэтому здесь два режима и они не смешиваются:

* **разведка** - ничего не меняет. Отвечает, что на генераторе уже есть, чего
  нет, и показывает готовые команды, если человек предпочитает руками;
* **подготовка** - показывает план целиком, ждёт явного согласия и только
  потом выполняет, по шагу за раз, останавливаясь на первом отказе.

Отдельно - то, чего инструмент не сделает ни в каком режиме: он не привяжет к
DPDK карту, через которую пришёл текущий сеанс. Это не осторожность, а
единственный способ не оставить человека без доступа к машине, которую он
только что настраивал.

Скрипты уезжают на цель так же, как разведочный: только стандартная
библиотека, построчный JSON обратно.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

from traphy.transport import Transport, TransportError

# Драйверы, под которыми карта принадлежит DPDK, а не ядру.
DPDK_DRIVERS = ("vfio-pci", "igb_uio", "uio_pci_generic")

# Как TRex получает карту. Разница не в скорости, а в том, чем платят:
# DPDK забирает карту у ядра целиком, AF_PACKET работает поверх ядра и не
# трогает ничего - но и потолок у него другой, и выдавать его цифры за
# проверку data plane на линейной скорости нельзя.
DPDK = "dpdk"
AF_PACKET = "af_packet"

MODES = {
    DPDK: ("DPDK", "карта уходит из ядра - линейная скорость"),
    AF_PACKET: ("AF_PACKET", "карта остаётся в ядре - около 1 Mpps"),
}

# Сколько гигабайт больших страниц просить. TRex сам рекомендует порядка этого
# на порт; меньше - он стартует и падает на выделении буферов, причём
# сообщением про mbuf, по которому причину не угадать.
HUGEPAGES_PER_PORT_MB = 1024


@dataclass
class Nic:
    """Сетевая карта глазами генератора, а не глазами коммутатора."""

    pci: str                       # 0000:3b:00.0 - то, чем её зовёт DPDK
    name: str = ""                 # eth1; пусто, когда карта уже отдана DPDK
    driver: str = ""               # драйвер в деле прямо сейчас
    kernel_driver: str = ""        # к какому вернётся, если отвязать
    mac: str = ""
    state: str = ""                # up | down | unknown
    speed_mbit: int = 0
    numa: int = -1
    model: str = ""
    carries_session: bool = False  # через неё пришёл наш SSH
    has_routes: bool = False       # через неё идут маршруты
    address: str = ""              # адрес, если он на ней есть

    @property
    def on_dpdk(self) -> bool:
        return self.driver in DPDK_DRIVERS

    @property
    def touchable(self) -> bool:
        """Можно ли её трогать, не оставшись без доступа к машине."""
        return not self.carries_session

    def describe(self) -> str:
        bits = [self.pci]
        if self.name:
            bits.append(self.name)
        bits.append(self.driver or "без драйвера")
        if self.on_dpdk:
            bits.append("под DPDK")
        elif self.state:
            bits.append(self.state)
        if self.speed_mbit:
            bits.append(f"{self.speed_mbit} Мбит/с")
        if self.numa >= 0:
            bits.append(f"NUMA {self.numa}")
        return " · ".join(bits)

    def warning(self) -> str:
        """Чем эта карта опасна. Пусто - значит ничем."""
        if self.carries_session:
            return "через неё идёт сеанс - связь оборвётся"
        if self.has_routes:
            return "через неё идут маршруты - пропадут"
        if self.address:
            return f"адрес {self.address} - исчезнет"
        return ""


@dataclass
class Generator:
    """Состояние генератора целиком: что есть, чего нет, чем это мешает."""

    ok: bool = False
    error: str = ""
    hostname: str = ""
    nics: list[Nic] = field(default_factory=list)

    # Большие страницы: без них TRex не стартует, и сообщение об этом невнятное.
    hugepages_total: int = 0
    hugepages_free: int = 0
    hugepage_kb: int = 0

    # IOMMU и vfio. vfio-pci без IOMMU работает только в режиме no-iommu, и
    # включать его надо явно - иначе привязка проходит, а TRex не видит порт.
    iommu: str = "unknown"              # on | off | unknown
    vfio_loaded: bool = False
    vfio_noiommu: bool = False
    modules: list[str] = field(default_factory=list)

    # Сам TRex.
    trex_dir: str = ""
    trex_version: str = ""
    has_trex_stl: bool = False
    devbind: str = ""                   # путь к dpdk-devbind.py внутри релиза
    daemon_running: bool = False
    daemon_pid: int = 0

    # Конфигурация.
    cfg_path: str = ""
    cfg_exists: bool = False
    cfg_ports: list[str] = field(default_factory=list)   # PCI в порядке файла

    is_root: bool = False
    can_sudo: bool = False

    def nic(self, pci: str) -> Nic | None:
        for card in self.nics:
            if card.pci == pci:
                return card
        return None

    @property
    def free_nics(self) -> list[Nic]:
        """Карты, которые можно отдать DPDK, не потеряв доступ к машине."""
        return [n for n in self.nics if n.touchable]

    @property
    def hugepages_mb(self) -> int:
        return self.hugepages_total * self.hugepage_kb // 1024

    def summary(self) -> list[str]:
        """Состояние генератора строками, в порядке, в котором это чинят."""
        if not self.ok:
            return [self.error or "генератор не ответил"]
        out = []
        if not self.trex_dir:
            out.append("релиза TRex на машине не видно")
        elif not self.has_trex_stl:
            out.append(f"в {self.trex_dir} нет control plane - это не релиз TRex")
        else:
            version = f" {self.trex_version}" if self.trex_version else ""
            out.append(f"TRex{version} в {self.trex_dir}")
        if self.hugepages_total:
            out.append(f"большие страницы: {self.hugepages_total} по "
                       f"{self.hugepage_kb} КБ ({self.hugepages_mb} МБ), "
                       f"свободно {self.hugepages_free}")
        else:
            out.append("большие страницы не выделены")
        out.append(f"IOMMU: {self.iommu}" + (", vfio-pci загружен"
                                             if self.vfio_loaded else
                                             ", vfio-pci не загружен"))
        on_dpdk = [n for n in self.nics if n.on_dpdk]
        out.append(f"под DPDK: {len(on_dpdk)} из {len(self.nics)} карт")
        out.append("демон отвечает" if self.daemon_running else "демон не поднят")
        return out


SURVEY_SCRIPT = r'''"""Разведка генератора. Ничего не меняет, root не нужен.

Отвечает на вопрос «что помешает TRex подняться». Поэтому смотрит не только на
карты, но и на то, чем они заняты: адрес, маршруты и - главное - не через эту
ли карту пришёл сеанс, из которого запущена разведка.
"""
import json
import os
import re
import socket
import subprocess
import sys

NET_CLASS = "0x02"           # класс PCI «сетевой контроллер»
DPDK_DRIVERS = ("vfio-pci", "igb_uio", "uio_pci_generic")
PCI_RE = r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}[.][0-9a-fA-F]"


def read(path, default=""):
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return default


def listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def shell(args):
    """Команда, вывод которой нужен целиком. Нет команды - пустая строка."""
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout if out.returncode == 0 else ""


def session_server_ip():
    """Адрес на этой машине, на который пришёл текущий сеанс.

    SSH_CONNECTION - «клиент порт сервер порт». Третье поле и есть адрес,
    через который нас видно, и карта с этим адресом неприкосновенна.
    """
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return parts[2] if len(parts) >= 4 else ""


def addresses():
    """Интерфейс -> список адресов на нём."""
    found = {}
    for line in shell(["ip", "-o", "-4", "addr", "show"]).splitlines():
        bits = line.split()
        if len(bits) >= 4 and bits[2] == "inet":
            found.setdefault(bits[1], []).append(bits[3].split("/")[0])
    return found


def routed():
    """Интерфейсы, через которые проложены маршруты."""
    out = set()
    for line in shell(["ip", "-o", "route", "show"]).splitlines():
        bits = line.split()
        if "dev" in bits:
            out.add(bits[bits.index("dev") + 1])
    return out


def pci_cards():
    """Сетевые устройства PCI - включая те, что уже забраны у ядра.

    Смотреть только /sys/class/net нельзя: карта под DPDK оттуда исчезает, и
    по такому списку выходило бы, что её вообще нет.
    """
    cards = []
    base = "/sys/bus/pci/devices"
    for slot in listdir(base):
        path = os.path.join(base, slot)
        if not read(os.path.join(path, "class")).startswith(NET_CLASS):
            continue
        driver = ""
        link = os.path.join(path, "driver")
        if os.path.islink(link):
            driver = os.path.basename(os.readlink(link))
        names = listdir(os.path.join(path, "net"))
        numa = read(os.path.join(path, "numa_node"), "-1")
        cards.append({
            "pci": slot,
            "name": names[0] if names else "",
            "driver": driver,
            "numa": int(numa) if numa.lstrip("-").isdigit() else -1,
        })
    return cards


def model_names():
    """PCI -> человеческое имя карты, если lspci есть."""
    names = {}
    for line in shell(["lspci", "-D", "-mm"]).splitlines():
        bits = line.split('"')
        if len(bits) >= 6 and " " in bits[0]:
            names[bits[0].split()[0]] = (bits[3] + " " + bits[5]).strip()
    return names


def speed_of(name):
    value = read("/sys/class/net/%s/speed" % name, "0")
    return int(value) if value.lstrip("-").isdigit() and int(value) > 0 else 0


def hugepages():
    """Сколько больших страниц есть и какого размера."""
    total = free = size = 0
    for line in read("/proc/meminfo").splitlines():
        if line.startswith("HugePages_Total:"):
            total = int(line.split()[1])
        elif line.startswith("HugePages_Free:"):
            free = int(line.split()[1])
        elif line.startswith("Hugepagesize:"):
            size = int(line.split()[1])
    return total, free, size


def iommu_state():
    """Включён ли IOMMU. Без него vfio-pci работает только в no-iommu."""
    if listdir("/sys/class/iommu"):
        return "on"
    cmdline = read("/proc/cmdline")
    for flag in ("iommu=pt", "intel_iommu=on", "amd_iommu=on"):
        if flag in cmdline:
            return "on"
    return "off"


def modules():
    return [line.split()[0] for line in read("/proc/modules").splitlines() if line]


def trex_release():
    """Каталог релиза TRex, его версия и наличие control plane."""
    candidates = [os.environ.get("TREX_DIR", "")] + sys.argv[1:]
    candidates += ["/opt/trex", "/opt/trex-core", os.path.expanduser("~/trex")]
    for base in ["/opt", os.path.expanduser("~")]:
        for entry in listdir(base):
            if entry.startswith(("trex", "v2.", "v3.")):
                candidates.append(os.path.join(base, entry))
    for path in candidates:
        if not path or not os.path.isdir(path):
            continue
        if not os.path.exists(os.path.join(path, "t-rex-64")):
            continue
        stl = os.path.isdir(os.path.join(path, "automation", "trex_control_plane"))
        found = re.search(r"v?(\d+[.]\d+)", os.path.basename(path))
        return path, found.group(1) if found else "", stl
    return "", "", False


def devbind(trex_dir):
    """Скрипт привязки карт внутри релиза. Имя менялось от версии к версии."""
    for name in ("dpdk-devbind.py", "dpdk_nic_bind.py", "dpdk_setup_ports.py"):
        path = os.path.join(trex_dir, name)
        if os.path.exists(path):
            return path
    return ""


def daemon():
    """Отвечает ли демон и чей это процесс."""
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect(("127.0.0.1", 4501))
        answers = True
    except OSError:
        answers = False
    finally:
        sock.close()
    pid = 0
    for entry in listdir("/proc"):
        if entry.isdigit() and "t-rex" in read("/proc/%s/comm" % entry):
            pid = int(entry)
            break
    return answers, pid


def config():
    """Где лежит trex_cfg.yaml и какие порты в нём перечислены по порядку."""
    for path in ("/etc/trex_cfg.yaml", "/etc/trex_cfg.yml"):
        text = read(path)
        if text:
            return path, True, re.findall(PCI_RE, text)
    return "/etc/trex_cfg.yaml", False, []


def can_sudo():
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


server_ip = session_server_ip()
addr = addresses()
with_routes = routed()
models = model_names()
cards = []
for card in pci_cards():
    name = card["name"]
    ips = addr.get(name, [])
    cards.append({
        "pci": card["pci"],
        "name": name,
        "driver": card["driver"],
        "kernel_driver": "" if card["driver"] in DPDK_DRIVERS else card["driver"],
        "mac": read("/sys/class/net/%s/address" % name) if name else "",
        "state": read("/sys/class/net/%s/operstate" % name, "unknown") if name else "",
        "speed_mbit": speed_of(name) if name else 0,
        "numa": card["numa"],
        "model": models.get(card["pci"], ""),
        "address": ips[0] if ips else "",
        "has_routes": name in with_routes,
        "carries_session": bool(server_ip) and server_ip in ips,
    })

total, free, size = hugepages()
trex_dir, trex_version, has_stl = trex_release()
answers, pid = daemon()
cfg_path, cfg_exists, cfg_ports = config()
loaded = modules()

print(json.dumps({
    "ev": "generator",
    "ok": True,
    "hostname": socket.gethostname(),
    "nics": cards,
    "hugepages_total": total,
    "hugepages_free": free,
    "hugepage_kb": size,
    "iommu": iommu_state(),
    "vfio_loaded": "vfio_pci" in loaded or "vfio" in loaded,
    "vfio_noiommu": read("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode") in ("Y", "1"),
    "modules": loaded,
    "trex_dir": trex_dir,
    "trex_version": trex_version,
    "has_trex_stl": has_stl,
    "devbind": devbind(trex_dir) if trex_dir else "",
    "daemon_running": answers,
    "daemon_pid": pid,
    "cfg_path": cfg_path,
    "cfg_exists": cfg_exists,
    "cfg_ports": cfg_ports,
    "is_root": os.geteuid() == 0,
    "can_sudo": can_sudo(),
}))
'''


def read_generator(payload: dict) -> Generator:
    """Ответ разведки - в состояние генератора."""
    gen = Generator(
        ok=bool(payload.get("ok")),
        error=str(payload.get("error", "")),
        hostname=str(payload.get("hostname", "")),
        hugepages_total=int(payload.get("hugepages_total", 0)),
        hugepages_free=int(payload.get("hugepages_free", 0)),
        hugepage_kb=int(payload.get("hugepage_kb", 0)),
        iommu=str(payload.get("iommu", "unknown")),
        vfio_loaded=bool(payload.get("vfio_loaded")),
        vfio_noiommu=bool(payload.get("vfio_noiommu")),
        modules=list(payload.get("modules") or []),
        trex_dir=str(payload.get("trex_dir", "")),
        trex_version=str(payload.get("trex_version", "")),
        has_trex_stl=bool(payload.get("has_trex_stl")),
        devbind=str(payload.get("devbind", "")),
        daemon_running=bool(payload.get("daemon_running")),
        daemon_pid=int(payload.get("daemon_pid", 0)),
        cfg_path=str(payload.get("cfg_path", "")),
        cfg_exists=bool(payload.get("cfg_exists")),
        cfg_ports=list(payload.get("cfg_ports") or []),
        is_root=bool(payload.get("is_root")),
        can_sudo=bool(payload.get("can_sudo")),
    )
    for row in payload.get("nics") or []:
        gen.nics.append(Nic(
            pci=str(row.get("pci", "")),
            name=str(row.get("name", "")),
            driver=str(row.get("driver", "")),
            kernel_driver=str(row.get("kernel_driver", "")),
            mac=str(row.get("mac", "")),
            state=str(row.get("state", "")),
            speed_mbit=int(row.get("speed_mbit", 0)),
            numa=int(row.get("numa", -1)),
            model=str(row.get("model", "")),
            address=str(row.get("address", "")),
            has_routes=bool(row.get("has_routes")),
            carries_session=bool(row.get("carries_session")),
        ))
    return gen


def survey(transport: Transport, trex_dir: str = "", timeout: int = 30) -> Generator:
    """Спросить генератор, в каком он состоянии. Ничего не меняет."""
    payload: dict = {}

    def take(line: str) -> None:
        try:
            event = json.loads(line)
        except ValueError:
            return
        if event.get("ev") == "generator":
            payload.update(event)

    try:
        done = transport.run_stream(
            SURVEY_SCRIPT, [trex_dir] if trex_dir else [], take, timeout=timeout)
    except TransportError as exc:
        return Generator(ok=False, error=str(exc))
    if not payload:
        tail = (done.stderr or "").strip().splitlines()
        return Generator(ok=False,
                         error=tail[-1] if tail else "разведка ничего не ответила")
    return read_generator(payload)


@dataclass
class Step:
    """Один шаг подготовки: что сделает, чем, и чем за это платят."""

    key: str
    title: str
    command: str
    needs_root: bool = True
    breaks: str = ""               # что перестанет работать после шага
    reversible: str = ""           # чем вернуть обратно
    why: str = ""                  # зачем он вообще нужен

    def describe(self) -> str:
        return f"{self.title}\n    {self.command}"


@dataclass
class Plan:
    """Что собираемся сделать с генератором - целиком, до единой команды.

    План существует отдельно от выполнения намеренно: в режиме разведки его
    показывают и не выполняют, а человек волен набрать команды руками. Это тот
    же приём, что в CLIRunner: сначала видно, что уйдёт, потом уходит.
    """

    steps: list[Step] = field(default_factory=list)
    refusals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    cfg_text: str = ""
    ports: list[str] = field(default_factory=list)

    @property
    def possible(self) -> bool:
        """Можно ли это вообще выполнять."""
        return not self.refusals and bool(self.steps)

    @property
    def nothing_to_do(self) -> bool:
        return not self.refusals and not self.steps

    def commands(self) -> list[str]:
        """Голые команды - для тех, кто предпочитает руками."""
        return [s.command for s in self.steps]

    def breakage(self) -> list[str]:
        """Всё, что сломается, одним списком. Это читают до согласия."""
        return [f"{s.title}: {s.breaks}" for s in self.steps if s.breaks]


def trex_cfg(gen: Generator, ports: list[str], cores: int = 4,
             mode: str = DPDK) -> str:
    """Текст trex_cfg.yaml для выбранных портов.

    ``dest_mac`` ставится адресом соседнего порта: это раскладка «порт в порт»,
    самая частая на стенде. Если между ними стоит коробка, адрес надо заменить
    на её - и об этом сказано прямо в файле, потому что молчаливо неверный
    dest_mac выглядит как стопроцентная потеря и ищется долго.
    """
    cards = [gen.nic(pci) for pci in ports]
    if mode == AF_PACKET:
        # Карты остаются в ядре, и TRex обращается к ним по имени интерфейса
        # через виртуальное устройство DPDK. Поэтому здесь имена, а не PCI.
        named = []
        for i, card in enumerate(cards):
            iface = card.name if card and card.name else ports[i]
            named.append(f"'--vdev=net_af_packet{i},iface={iface}'")
        devices = "[" + ", ".join(named) + "]"
        head = ["# Собрано TRaphy, режим AF_PACKET: карты остаются в ядре.",
                "# Потолок здесь около 1 Mpps - это проверка логики, а не",
                "# проверка data plane на линейной скорости."]
    else:
        devices = "[" + ", ".join(f'"{p}"' for p in ports) + "]"
        head = ["# Собрано TRaphy, режим DPDK: карты забраны у ядра."]

    lines = [
        *head,
        "# Порядок интерфейсов здесь задаёт номера портов: первый в списке -",
        "# порт 0, второй - порт 1. Именно эти номера спрашивает TRex, а не",
        "# те, что написаны на коммутаторе.",
        "- version: 2",
        f"  interfaces: {devices}",
        f"  port_limit: {len(ports)}",
        f"  c: {cores}",
        "  port_info:",
    ]
    for i, card in enumerate(cards):
        peer = cards[1 - i] if len(cards) == 2 else None
        own = (card.mac if card and card.mac else "00:00:00:00:00:00")
        dest = (peer.mac if peer and peer.mac else "00:00:00:00:00:01")
        lines += [
            f"      # порт {i}: {ports[i]}" + (f" ({card.name})" if card and card.name else ""),
            f"      - src_mac:  '{own}'",
            f"        dest_mac: '{dest}'"
            + ("   # сосед по кабелю; через коробку - заменить на её адрес"
               if peer else "   # поставить адрес того, кто на другом конце"),
        ]
    return "\n".join(lines) + "\n"


def build_plan(gen: Generator, ports: list[str], *,
               cores: int = 4, allow_noiommu: bool = False,
               hugepages_mb: int = 0, mode: str = DPDK) -> Plan:
    """Что нужно сделать, чтобы TRex поднялся на этих портах.

    План строится и тогда, когда выполнять его нельзя: отказы - это тоже
    ответ, и человеку надо показать их все сразу, а не по одному за попытку.
    """
    plan = Plan(ports=list(ports))

    if not gen.ok:
        plan.refusals.append(gen.error or "генератор не ответил")
        return plan
    if not gen.trex_dir:
        plan.refusals.append("на машине нет релиза TRex - настраивать нечего")
    elif not gen.has_trex_stl:
        plan.refusals.append(f"в {gen.trex_dir} нет control plane - это не релиз TRex")
    if mode == DPDK and not gen.devbind and gen.trex_dir:
        plan.refusals.append(f"в {gen.trex_dir} не найден скрипт привязки карт "
                             f"(dpdk-devbind.py) - без него порты не отдать DPDK")
    if not gen.is_root and not gen.can_sudo:
        plan.refusals.append("нет ни root, ни sudo без пароля - подготовка "
                             "состоит из привилегированных команд")
    if not ports:
        plan.refusals.append("не выбрано ни одного порта")

    for pci in ports:
        card = gen.nic(pci)
        if card is None:
            plan.refusals.append(f"карты {pci} на машине нет")
            continue
        if card.carries_session and mode == DPDK:
            # Единственный отказ, который нельзя снять галочкой: привязав эту
            # карту, человек потеряет доступ к машине ровно в тот момент, когда
            # она перестанет отвечать, и не узнает, почему.
            #
            # В AF_PACKET этого не происходит - карта остаётся в ядре. Там это
            # не отказ, а предупреждение: гнать нагрузку в собственный канал
            # управления можно, но связь с генератором при этом ляжет под
            # собственным трафиком, и выглядеть это будет как обрыв.
            plan.refusals.append(
                f"через {pci} ({card.name}) идёт текущий сеанс - привязка к "
                f"DPDK оборвёт связь с генератором; нужен другой порт или "
                f"отдельный канал управления")
        elif card.carries_session:
            plan.notes.append(
                f"Через {card.name or pci} идёт текущий сеанс. Карта останется "
                f"в ядре, но нагрузка пойдёт в тот же канал - связь с "
                f"генератором может лечь под собственным трафиком.")
    if plan.refusals:
        return plan

    if mode == AF_PACKET:
        taken = [gen.nic(p) for p in ports if (gen.nic(p) or Nic("")).on_dpdk]
        for card in taken:
            plan.refusals.append(
                f"{card.pci} отдана DPDK - в режиме AF_PACKET ядро её уже не "
                f"видит; верни её ядру или выбери режим DPDK")
        if plan.refusals:
            return plan

    need_mb = hugepages_mb or HUGEPAGES_PER_PORT_MB * max(len(ports), 1)
    if gen.hugepages_mb < need_mb:
        pages = need_mb * 1024 // max(gen.hugepage_kb or 2048, 1)
        plan.steps.append(Step(
            key="hugepages",
            title=f"Выделить большие страницы: {pages} по {gen.hugepage_kb or 2048} КБ",
            command=f"sysctl -w vm.nr_hugepages={pages}",
            why="без них TRex стартует и падает на выделении буферов, "
                "сообщением про mbuf, по которому причину не угадать",
            reversible=f"sysctl -w vm.nr_hugepages={gen.hugepages_total}",
        ))
        plan.notes.append("Выделение страниц не переживёт перезагрузку. "
                          "Чтобы пережило - vm.nr_hugepages в /etc/sysctl.d.")

    if mode == DPDK and not gen.vfio_loaded:
        plan.steps.append(Step(
            key="vfio",
            title="Загрузить модуль vfio-pci",
            command="modprobe vfio-pci",
            why="им карта и отдаётся из ядра в DPDK",
            reversible="modprobe -r vfio-pci",
        ))

    if mode == DPDK and gen.iommu != "on":
        if not allow_noiommu:
            plan.refusals.append(
                "IOMMU выключен. vfio-pci без него работает только в режиме "
                "no-iommu, а это снимает защиту памяти от карты - включать "
                "такое надо осознанно. Либо включить IOMMU в прошивке и "
                "параметрах ядра (intel_iommu=on / amd_iommu=on), либо "
                "разрешить no-iommu явно")
            return plan
        plan.steps.append(Step(
            key="noiommu",
            title="Разрешить vfio без IOMMU (небезопасный режим)",
            command="modprobe vfio enable_unsafe_noiommu_mode=1",
            why="IOMMU выключен, иначе карта не отдастся",
            breaks="карта получает прямой доступ к памяти без защиты IOMMU",
            reversible="перезагрузка машины",
        ))

    for pci in ports:
        card = gen.nic(pci)
        if card is None or card.on_dpdk or mode != DPDK:
            continue
        breaks = card.warning() or "интерфейс исчезнет из ip link"
        plan.steps.append(Step(
            key=f"bind:{pci}",
            title=f"Отдать {pci}" + (f" ({card.name})" if card.name else "") + " в DPDK",
            command=f"{gen.devbind} --bind=vfio-pci {pci}",
            why="без этого карта принадлежит ядру, и DPDK её не видит",
            breaks=breaks,
            reversible=f"{gen.devbind} --bind={card.kernel_driver or 'ice'} {pci}"
                       if card.kernel_driver else "",
        ))

    plan.cfg_text = trex_cfg(gen, ports, cores=cores, mode=mode)
    if not gen.cfg_exists or gen.cfg_ports != ports:
        plan.steps.append(Step(
            key="cfg",
            title=f"Записать {gen.cfg_path}",
            command=f"cat > {gen.cfg_path} <<'EOF' ... EOF",
            why="порядок интерфейсов в этом файле и задаёт номера портов TRex",
            breaks=("прежний файл будет сохранён рядом с суффиксом .bak"
                    if gen.cfg_exists else ""),
        ))
    if gen.cfg_exists and gen.cfg_ports and gen.cfg_ports != ports:
        plan.notes.append(f"В {gen.cfg_path} сейчас другие порты "
                          f"({', '.join(gen.cfg_ports)}) - номера сдвинутся.")

    if not gen.daemon_running:
        plan.steps.append(Step(
            key="daemon",
            title="Поднять демон TRex",
            command=f"cd {gen.trex_dir} && ./t-rex-64 -i"
                    + (" --software" if mode == AF_PACKET else "")
                    + f" --cfg {gen.cfg_path}",
            why="без него управляющий порт 4501 не отвечает",
            reversible="pkill -f t-rex-64",
        ))
    else:
        plan.notes.append(f"Демон уже поднят (pid {gen.daemon_pid}). Чтобы он "
                          f"прочитал новую конфигурацию, его надо перезапустить.")
    return plan


APPLY_SCRIPT = r'''"""Выполнить план подготовки. Шаг за шагом, до первого отказа.

План приходит целиком, уже составленный и уже показанный человеку: здесь ничего
не решается заново. Останавливаться на первом отказе обязательно - половина
подготовки хуже, чем её отсутствие, потому что выглядит как готовность.
"""
import json
import os
import socket
import subprocess
import sys
import time


def say(**event):
    print(json.dumps(event), flush=True)


def run(command, timeout=120):
    """Команда через оболочку: в плане есть перенаправления и cd."""
    try:
        done = subprocess.run(["sh", "-c", command], capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "", "команда не ответила за %d с" % timeout
    except OSError as exc:
        return 125, "", str(exc)
    return done.returncode, done.stdout.strip(), done.stderr.strip()


def write_config(path, text):
    """Записать конфигурацию, сохранив прежнюю рядом.

    Прежний файл уносит с собой порядок портов, по которому кто-то мог уже
    настроить прогоны. Затирать его молча нельзя.
    """
    if os.path.exists(path):
        backup = path + ".bak"
        try:
            with open(path) as src, open(backup, "w") as dst:
                dst.write(src.read())
        except OSError as exc:
            return 1, "", "прежний файл не сохранить: %s" % exc
    try:
        with open(path, "w") as handle:
            handle.write(text)
    except OSError as exc:
        return 1, "", str(exc)
    return 0, "записан %s" % path, ""


def daemon_answers(port=4501, wait=20):
    """Дождаться, пока управляющий порт начнёт отвечать."""
    deadline = time.time() + wait
    while time.time() < deadline:
        sock = socket.socket()
        sock.settimeout(0.5)
        try:
            sock.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.5)
        finally:
            sock.close()
    return False


def start_daemon(command):
    """Поднять демона и отпустить: он должен пережить наш выход.

    Без отвязки от сеанса демон уходит вместе со скриптом, и выглядит это как
    «поднялся и сразу упал» - причём в логе ничего нет.
    """
    log = "/tmp/traphy-trex.log"
    wrapped = "nohup sh -c %s > %s 2>&1 &" % (json.dumps(command), log)
    code, out, err = run(wrapped, timeout=20)
    if code != 0:
        return code, out, err
    if not daemon_answers():
        tail = ""
        try:
            with open(log) as handle:
                tail = handle.read()[-800:]
        except OSError:
            pass
        return 1, "", "демон не ответил на 4501 за 20 с. Журнал:\n" + tail
    return 0, "демон отвечает", ""


plan = json.loads(sys.argv[1])
steps = plan.get("steps") or []
say(ev="begin", total=len(steps))

failed = False
for step in steps:
    key = step.get("key", "")
    say(ev="step", key=key, title=step.get("title", ""), state="start")
    if key == "cfg":
        code, out, err = write_config(plan.get("cfg_path", "/etc/trex_cfg.yaml"),
                                      plan.get("cfg_text", ""))
    elif key == "daemon":
        code, out, err = start_daemon(step.get("command", ""))
    else:
        code, out, err = run(step.get("command", ""))
    if code == 0:
        say(ev="step", key=key, state="ok", output=out)
    else:
        say(ev="step", key=key, state="fail", code=code,
            output=out, error=err or "команда вернула %d" % code)
        failed = True
        break

say(ev="done", ok=not failed)
'''


def apply(transport: Transport, plan: Plan, cfg_path: str,
          on_event: Callable[[dict], None] | None = None,
          timeout: int = 300) -> tuple[bool, list[str]]:
    """Выполнить план на генераторе. Возвращает «получилось» и журнал.

    Вызывается только после явного согласия: сам по себе план ничего не
    выполняет и выполнить не может - это два разных действия нарочно.
    """
    if not plan.possible:
        return False, list(plan.refusals)

    payload = json.dumps({
        "cfg_path": cfg_path,
        "cfg_text": plan.cfg_text,
        "steps": [{"key": s.key, "title": s.title, "command": s.command}
                  for s in plan.steps],
    }, ensure_ascii=False)

    log: list[str] = []
    ok = False

    def take(line: str) -> None:
        nonlocal ok
        try:
            event = json.loads(line)
        except ValueError:
            log.append(line)
            return
        kind = event.get("ev")
        if kind == "step" and event.get("state") == "start":
            log.append(f"· {event.get('title', '')}")
        elif kind == "step" and event.get("state") == "ok":
            if event.get("output"):
                log.append(f"  {event['output']}")
        elif kind == "step" and event.get("state") == "fail":
            log.append(f"  отказ: {event.get('error', '')}")
        elif kind == "done":
            ok = bool(event.get("ok"))
        if on_event is not None:
            on_event(event)

    try:
        transport.run_stream(APPLY_SCRIPT, [payload], take,
                             sudo=True, timeout=timeout)
    except TransportError as exc:
        return False, [*log, str(exc)]
    return ok, log
