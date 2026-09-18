"""Turn a :class:`~traphy.models.Profile` into a control script for IxNetwork.

Third engine, third shape of run. Scapy is a script that sends frames itself.
TRex is a daemon on a host we reach over SSH. Ixia is a *chassis on the network*
driven through an API server, and the client that drives it runs here - so the
target stops being "a machine that executes something" and becomes an address
with cards and ports in it.

What that changes, and all of it is visible to the operator:

* **Ports are assigned, not discovered.** A port is a chassis address plus a
  card and a port number. There is no interface list to pick from and no
  ``/sys/class/net`` to read - :attr:`IxiaEngine.uses_ifaces` is False and the
  target form asks for ``карта/порт``.
* **Ports belong to someone.** A chassis is shared lab equipment and a port can
  already be owned by a colleague mid-test. Taking it is possible and is never
  the default: ``force_ownership`` is a deliberate setting, and without it a
  busy port is reported with who holds it rather than quietly seized.
* **Loss is counted by the chassis, per traffic item.** That is the same class
  of number as TRex's flow stats and it needs no caveat - provided tracking is
  on, which the script checks rather than assumes.
* **Frame size counts the CRC.** IxNetwork's frame size includes the four-byte
  FCS; TRaphy's model excludes it. The generated script adds the four back, so
  one profile puts the same bytes on the wire here as it does on the other two
  engines. TRaphy's 60-byte minimum lands exactly on IxNetwork's 64, which is
  the arithmetic agreeing with itself.
* **A field that is not there is a refusal, not a shrug.** Every packet field
  is addressed by its IxNetwork field id. If a release names one differently,
  the script stops and says which - sending traffic with a source MAC that
  silently stayed at its default is worse than sending nothing.

Progress comes back as the same ``@traphy {json}`` lines the other two engines
emit, so :mod:`traphy.runner` folds any of the three into a result without
knowing which produced it.
"""

from __future__ import annotations

import ipaddress

from traphy.models import (
    FieldTarget,
    L4Proto,
    Profile,
    RateType,
    Stream,
    TxMode,
    VMOp,
    range_size,
)

# IxNetwork's frame size includes the four-byte FCS; the TRaphy model's does
# not. Everything about the wire lines up once this is added back, including
# the minimum: TRaphy's 60 becomes IxNetwork's 64.
FCS_BYTES = 4

# The smallest frame IxNetwork will configure.
MIN_IXNET_FRAME = 64

# How a packet field is named to IxNetwork. These ids are the contract between
# this module and the chassis; when one does not resolve, the run stops and
# names it rather than sending a frame that is not the one that was composed.
FIELD_IDS = {
    "eth_dst": "ethernet.header.destinationAddress",
    "eth_src": "ethernet.header.sourceAddress",
    "vlan_id": "vlan.header.vlanTag.vlanID",
    "vlan_pcp": "vlan.header.vlanTag.priority",
    "ip_src": "ipv4.header.srcIp",
    "ip_dst": "ipv4.header.dstIp",
    "ttl": "ipv4.header.ttl",
    "udp_sport": "udp.header.srcPort",
    "udp_dport": "udp.header.dstPort",
    "tcp_sport": "tcp.header.srcPort",
    "tcp_dport": "tcp.header.dstPort",
}

# The protocol templates stacked onto a raw traffic item, in wire order.
STACK_IDS = {"eth": "ethernet", "vlan": "vlan", "ip": "ipv4",
             "udp": "udp", "tcp": "tcp"}


def generate(profile: Profile, tag: str = "") -> str:
    """The complete control script for ``profile`` as one string."""
    enabled = profile.enabled_streams
    skipped = [s.name for s in profile.streams if not s.enabled]

    parts = [_header(profile, skipped, tag, enabled), _HELPERS,
             _builder(enabled), _ENGINE]
    return "\n\n".join(parts) + "\n"


def frame_count(profile: Profile) -> int:
    """How many distinct frames the chassis will walk through.

    Uncapped, the same as the TRex engine and for the same reason: a range is
    a field increment on the card, not frames built in memory here.
    """
    return sum(_stream_frames(s) for s in profile.enabled_streams)


def _stream_frames(s: Stream) -> int:
    frames = 1
    for vf in s.vm_fields:
        frames *= max(1, range_size(vf))
    return frames


def script_name(profile: Profile) -> str:
    base = "".join(c if c.isalnum() or c in "-_" else "_" for c in profile.name)
    return f"{base or 'profile'}.py"


def warnings(profile: Profile) -> list[str]:
    """What this profile costs on Ixia, said before the run rather than after."""
    out: list[str] = []
    for s in profile.enabled_streams:
        wire = s.packet.frame_size + FCS_BYTES
        if wire < MIN_IXNET_FRAME:
            out.append(f"поток «{s.name}»: кадр {s.packet.frame_size} B + FCS - "
                       f"меньше {MIN_IXNET_FRAME} B, шасси поднимет до минимума")
        if any(vf.op is VMOp.RANDOM for vf in s.vm_fields):
            out.append(f"поток «{s.name}»: случайный перебор - шасси выдаёт "
                       f"свою последовательность, повторить её дословно нельзя")
        if s.tx_mode is TxMode.MULTI_BURST:
            out.append(f"поток «{s.name}»: много очередей - межочередной "
                       f"интервал задаётся шасси с его точностью, не нашей")
    return out


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
def _header(profile: Profile, skipped: list[str], tag: str,
            enabled: list[Stream]) -> str:
    desc = profile.description or "-"
    note = f"# Выключенные потоки не вошли: {', '.join(skipped)}\n" if skipped else ""
    run_tag = f"# Метка прогона: {tag}\n" if tag else ""
    walk = {s.name: _stream_frames(s) for s in enabled}
    said = warnings(profile)
    all_pps = all(s.rate_type is RateType.PPS for s in enabled)
    total_pps = profile.total_pps()
    return f'''\
#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Профиль: {profile.name}
# {desc}
{note}{run_tag}#
# Сгенерировано TRaphy. Это управляющий скрипт: трафик выдувает шасси Ixia,
# скрипт лишь настраивает его через IxNetwork и читает счётчики. Нужен
# Python 3 и ixnetwork-restpy; root не нужен, шасси тут вообще ни при чём.
#
#   ./{script_name(profile)} --api-host 10.0.0.1 --chassis 10.0.0.2 \\
#       --tx-port 1/1 --rx-port 1/2 --duration 10
#
# Порт шасси - общее имущество: без --force чужой занятый порт не отбирается,
# а называется вместе с тем, кто его держит.
#
# Потери считает само шасси по traffic item - это счётчик карты, а не
# сниффер. Без --rx-port приём не измеряется, и в отчёте написано это, а не
# ноль.
#
# Размер кадра: IxNetwork считает его вместе с FCS, модель TRaphy - без.
# Скрипт добавляет {FCS_BYTES} байта обратно, чтобы один профиль ложился в кабель
# одинаково на Scapy, TRex и здесь.
# ---------------------------------------------------------------------------
import argparse
import importlib
import json
import os
import sys
import time

FCS_BYTES = {FCS_BYTES}
MIN_IXNET_FRAME = {MIN_IXNET_FRAME}

# Сколько кадров обойдут инкременты полей по каждому потоку - посчитано при
# генерации; на карте это настройка, а не кадры в памяти.
VM_FRAMES = {walk!r}

# То, что этот профиль теряет именно на Ixia. Лежит прямо здесь, чтобы
# сохранённый скрипт говорил это сам, без TRaphy.
WARNINGS = {said!r}

# Суммарная заданная скорость и то, можно ли её вообще масштабировать одним
# числом: смесь процентов и битов общим pps не двигается, её пришлось бы
# выдумывать.
TOTAL_PPS = {total_pps!r}
ALL_PPS = {all_pps!r}'''


# --------------------------------------------------------------------------- #
# Fixed helpers, emitted verbatim
# --------------------------------------------------------------------------- #
_HELPERS = '''\
def emit(quiet, **event):
    """One machine-readable progress line, or nothing when muted."""
    if not quiet:
        sys.stdout.write("@traphy " + json.dumps(event) + "\\n")
        sys.stdout.flush()


class ApiMissing(Exception):
    """ixnetwork-restpy is not installed where this script is running."""

    def explain(self):
        return ("не найден ixnetwork-restpy - поставь его там, откуда "
                "запускается TRaphy: pip install ixnetwork-restpy")


class FieldMissing(Exception):
    """A packet field this release does not name the way we do.

    Raised rather than skipped on purpose. A frame whose source MAC quietly
    stayed at the chassis default looks like traffic, passes through the
    device and answers a question nobody asked.
    """

    def __init__(self, field_id):
        Exception.__init__(self, field_id)
        self.field_id = field_id

    def explain(self):
        return ("шасси не знает поля %s - похоже, версия IxNetwork называет "
                "его иначе; кадр собрался бы не тот, поэтому прогон "
                "остановлен" % self.field_id)


class PortBusy(Exception):
    """Somebody else is holding the port and we were not told to take it."""

    def __init__(self, detail):
        Exception.__init__(self, detail)
        self.detail = detail

    def explain(self):
        return ("порт занят: %s - договорись с владельцем или запусти с "
                "--force, чтобы отобрать" % self.detail)


def load_api():
    """Import ixnetwork-restpy, or say plainly that it is not here."""
    try:
        return importlib.import_module("ixnetwork_restpy")
    except ImportError:
        raise ApiMissing()


def split_port(text):
    """"1/2" into (card, port). The form a person says out loud."""
    parts = str(text).replace(":", "/").split("/")
    if len(parts) != 2:
        raise ValueError("порт задаётся как карта/порт, например 1/2")
    return int(parts[0]), int(parts[1])


def find_field(stack, field_id):
    """One packet field on the built stack, or a refusal naming it."""
    found = stack.Field.find(FieldTypeId=field_id)
    if len(found) == 0:
        raise FieldMissing(field_id)
    return found[0]


def set_field(stack, field_id, spec):
    """Give one packet field its value, fixed or walking.

    ``spec`` is what the generator decided: a single value, or an increment /
    decrement / random walk with its start, step and count. The chassis does
    the walking; nothing is expanded here.
    """
    field = find_field(stack, field_id)
    field.Auto = False
    kind = spec.get("type", "single")
    if kind == "single":
        field.ValueType = "singleValue"
        field.SingleValue = spec["value"]
        return
    if kind == "random":
        field.ValueType = "random"
        return
    field.ValueType = kind                      # increment | decrement
    field.StartValue = spec["start"]
    field.StepValue = spec["step"]
    field.CountValue = spec["count"]


def build_stack(ixnet, config_element, protocols):
    """Stack the protocol templates onto a raw traffic item, in wire order."""
    stack = config_element.Stack.find(StackTypeId="^ethernet$")
    for name in protocols:
        if name == "ethernet":
            continue
        template = ixnet.Traffic.ProtocolTemplate.find(
            StackTypeId="^%s$" % name)
        if len(template) == 0:
            raise FieldMissing("стек %s" % name)
        appended = stack.AppendProtocol(template[0])
        stack = config_element.Stack.read(appended)
    return config_element.Stack


def set_size(config_element, frame_size):
    """The frame as the chassis counts it: our bytes plus the FCS."""
    wire = max(MIN_IXNET_FRAME, frame_size + FCS_BYTES)
    config_element.FrameSize.update(Type="fixed", FixedSize=wire)
    return wire


def set_rate(config_element, kind, value):
    config_element.FrameRate.update(Type=kind, Rate=value)


def set_transmission(config_element, spec, duration):
    """How long and in what shape the stream goes out."""
    if spec["mode"] == "continuous":
        config_element.TransmissionControl.update(
            Type="fixedDuration", Duration=int(max(1, duration)))
        return
    if spec["mode"] == "single_burst":
        config_element.TransmissionControl.update(
            Type="fixedFrameCount", FrameCount=spec["burst"])
        return
    config_element.TransmissionControl.update(
        Type="custom", BurstPacketCount=spec["burst"],
        RepeatBurst=spec["bursts"], EnableInbetweenBurstGap=True,
        InbetweenBurstGap=spec["ibg"], InbetweenBurstGapUnits="microseconds")


def number(value):
    """A statistics cell as a number; views hand back strings and dashes."""
    try:
        return int(float(str(value).replace(",", "").strip() or 0))
    except ValueError:
        return 0'''


# --------------------------------------------------------------------------- #
# The generated builder
# --------------------------------------------------------------------------- #
def _builder(streams: list[Stream]) -> str:
    """Emit ``build_traffic()``: the profile in IxNetwork's own vocabulary."""
    body = [
        "def build_traffic(ixnet, tx_vport, rx_vport, duration):",
        '    """Потоки профиля как traffic items на шасси.',
        "",
        "    Возвращает (имена потоков, размеры кадров в кабеле). Каждое поле",
        "    ставится явно: то, что осталось бы по умолчанию шасси, - это не",
        "    тот кадр, который собрали в меню.",
        '    """',
        "    names = []",
        "    sizes = []",
    ]
    for s in streams:
        body.append("")
        body.extend(_stream_block(s))
    body.append("")
    body.append("    return names, sizes")
    return "\n".join(body)


def _stream_block(s: Stream) -> list[str]:
    p = s.packet
    out = [f"    # --- поток «{s.name}»: {_shape(s)}"]
    out.append(f"    item = ixnet.Traffic.TrafficItem.add(name={s.name!r}, "
               f'trafficType="raw", biDirectional=False)')
    out.append("    item.EndpointSet.add(Sources=[tx_vport.Protocols.add()],")
    out.append("                         Destinations=[rx_vport.Protocols.add()])")
    out.append("    element = item.ConfigElement.find()[0]")
    out.append(f"    stack = build_stack(ixnet, element, {_protocols(s)!r})")

    for field_id, spec in _fields(s):
        out.append(f"    set_field(stack, {field_id!r}, {spec!r})")

    out.append(f"    sizes.append(set_size(element, {p.frame_size}))")
    kind, value = _rate(s)
    out.append(f"    set_rate(element, {kind!r}, {value})")
    out.append(f"    set_transmission(element, {_transmission(s)!r}, duration)")
    # Per-item statistics only appear when the item is tracked; without this
    # the loss column has nothing behind it.
    out.append('    item.Tracking.find()[0].TrackBy = ["trackingenabled0"]')
    out.append(f"    names.append({s.name!r})")
    return out


def _protocols(s: Stream) -> list[str]:
    """The protocol stack this frame needs, in wire order."""
    out = [STACK_IDS["eth"]]
    if s.packet.has_vlan:
        out.append(STACK_IDS["vlan"])
    if s.packet.has_ip:
        out.append(STACK_IDS["ip"])
    if s.packet.has_l4:
        out.append(STACK_IDS["tcp"] if s.packet.l4_proto is L4Proto.TCP
                   else STACK_IDS["udp"])
    return out


def _fields(s: Stream) -> list[tuple[str, dict]]:
    """Every packet field to set, fixed values first, then the walking ones."""
    p = s.packet
    walking = {vf.target: vf for vf in s.vm_fields if _applies(s, vf)}
    l4 = "tcp" if p.l4_proto is L4Proto.TCP else "udp"

    out: list[tuple[str, dict]] = [
        (FIELD_IDS["eth_dst"], {"type": "single", "value": p.eth_dst}),
        (FIELD_IDS["eth_src"], {"type": "single", "value": p.eth_src}),
    ]
    if p.has_vlan:
        out.append((FIELD_IDS["vlan_id"], {"type": "single", "value": str(p.vlan)}))
        out.append((FIELD_IDS["vlan_pcp"],
                    {"type": "single", "value": str(p.vlan_pcp)}))
    if p.has_ip:
        out.append((FIELD_IDS["ip_src"],
                    _spec(walking.get(FieldTarget.IP_SRC), p.ip_src)))
        out.append((FIELD_IDS["ip_dst"],
                    _spec(walking.get(FieldTarget.IP_DST), p.ip_dst)))
        out.append((FIELD_IDS["ttl"], {"type": "single", "value": str(p.ttl)}))
    if p.has_l4:
        out.append((FIELD_IDS[f"{l4}_sport"],
                    _spec(walking.get(FieldTarget.SPORT), str(p.sport))))
        out.append((FIELD_IDS[f"{l4}_dport"],
                    _spec(walking.get(FieldTarget.DPORT), str(p.dport))))
    return out


def _applies(s: Stream, vf) -> bool:
    if vf.target.is_ip:
        return s.packet.has_ip
    return s.packet.has_l4


def _spec(vf, fixed: str) -> dict:
    """One field's value: the fixed one, or the walk that replaces it."""
    if vf is None:
        return {"type": "single", "value": fixed}
    if vf.op is VMOp.RANDOM:
        return {"type": "random"}
    start = vf.max_value if vf.op is VMOp.DEC else vf.min_value
    kind = "decrement" if vf.op is VMOp.DEC else "increment"
    return {"type": kind, "start": str(start), "step": _step(vf),
            "count": range_size(vf)}


def _step(vf) -> str:
    """The step as the field's own type: dotted for an address, plain for a
    port. IxNetwork wants the step in the units of the field it walks."""
    if vf.target.is_ip:
        return str(ipaddress.IPv4Address(vf.step))
    return str(vf.step)


def _rate(s: Stream) -> tuple[str, float]:
    if s.rate_type is RateType.PPS:
        return "framesPerSecond", s.rate_value
    if s.rate_type is RateType.BPS_L2:
        return "bitsPerSecond", s.rate_value
    return "percentLineRate", s.rate_value


def _transmission(s: Stream) -> dict:
    return {"mode": s.tx_mode.value, "burst": s.pkts_per_burst,
            "bursts": s.number_of_bursts, "ibg": s.ibg_usec}


def _shape(s: Stream) -> str:
    bits = [s.packet.describe(), s.rate_label()]
    if s.tx_mode is not TxMode.CONTINUOUS:
        bits.append(_MODE_WORDS[s.tx_mode])
    bits.extend(vf.describe() for vf in s.vm_fields)
    return ", ".join(bits)


_MODE_WORDS = {
    TxMode.CONTINUOUS: "непрерывно",
    TxMode.SINGLE_BURST: "одна очередь",
    TxMode.MULTI_BURST: "много очередей",
}


# --------------------------------------------------------------------------- #
# The engine, emitted verbatim
# --------------------------------------------------------------------------- #
_ENGINE = '''\
# Шасси заканчивает считать через мгновение после последнего кадра. Прочитать
# раньше - значит превратить хвост прогона в выдуманные потери. Отдельной
# константой, потому что подменённое шасси в тестах успокаивается мгновенно.
STATS_SETTLE = 2.0


class NoPassword(Exception):
    """An API server that wants a login, and no password anywhere to give it."""

    def explain(self):
        return ("API-сервер спрашивает логин, а пароля нет: положи его в "
                "TRAPHY_IXIA_PASSWORD - в файл цели пароли не пишутся и "
                "в командной строке их видно всей машине")


def connect(api, args):
    """Open a session on the API server and take the two ports.

    Ownership is the delicate part. A chassis port is shared equipment and may
    be held by somebody mid-test; taking it is possible and is never what
    happens by accident, so without --force a busy port comes back as a
    refusal that names who is on it.
    """
    password = os.environ.get("TRAPHY_IXIA_PASSWORD", "")
    if args.api_user and not password:
        raise NoPassword()

    assistant = api.SessionAssistant(
        IpAddress=args.api_host, RestPort=args.api_port,
        UserName=args.api_user or None, Password=password or None,
        LogLevel="info", ClearConfig=True)

    port_map = assistant.PortMapAssistant()
    tx_card, tx_port = split_port(args.tx_port)
    rx_card, rx_port = split_port(args.rx_port)
    port_map.Map(IpAddress=args.chassis, CardId=tx_card, PortId=tx_port,
                 Name="traphy-tx")
    port_map.Map(IpAddress=args.chassis, CardId=rx_card, PortId=rx_port,
                 Name="traphy-rx")
    try:
        port_map.Connect(ForceOwnership=args.force)
    except Exception as exc:
        detail = str(exc)
        if any(word in detail.lower()
               for word in ("owner", "ownership", "in use", "busy")):
            raise PortBusy(detail)
        raise
    return assistant


def vports(assistant):
    ixnet = assistant.Ixnetwork
    tx = ixnet.Vport.find(Name="traphy-tx")
    rx = ixnet.Vport.find(Name="traphy-rx")
    if len(tx) == 0 or len(rx) == 0:
        raise PortBusy("порты не поднялись на шасси")
    return tx[0], rx[0]


def scale_rates(ixnet, factor):
    """Move every stream's rate by the same factor.

    An aggregate override has to stay aggregate: scaling each stream keeps the
    mix between them, which is the only reading of "gnat at N pps in total"
    that does not quietly turn a profile into a different one.
    """
    for item in ixnet.Traffic.TrafficItem.find():
        for element in item.ConfigElement.find():
            element.FrameRate.update(Rate=element.FrameRate.Rate * factor)


def sample(view, names, sizes):
    """One reading of the chassis's own per-item counters."""
    tx = rx = tx_bytes = 0
    counted = 0
    for row in view.Rows:
        name = str(row["Traffic Item"])
        if name not in names:
            continue
        counted += 1
        seen = number(row["Tx Frames"])
        tx += seen
        rx += number(row["Rx Frames"])
        tx_bytes += seen * sizes.get(name, 0)
    return {"tx": tx, "rx": rx, "tx_bytes": tx_bytes, "counted": counted}


def run(assistant, args, names, sizes, quiet):
    """Apply the configuration, run it, and read the counters back."""
    ixnet = assistant.Ixnetwork
    if args.pps:
        ixnet.Traffic.Apply()
        scale_rates(ixnet, args.pps / TOTAL_PPS)
    ixnet.Traffic.Apply()

    view = assistant.StatViewAssistant("Traffic Item Statistics", Timeout=60)
    by_name = dict(zip(names, sizes))

    started = time.time()
    ixnet.Traffic.Start()
    deadline = started + max(args.duration, 0.0) + 60
    last = started
    while time.time() < deadline:
        time.sleep(0.5)
        now = time.time()
        if now - last >= 1.0:
            last = now
            snap = sample(view, names, by_name)
            elapsed = now - started
            emit(quiet, ev="tick", t=round(elapsed, 2), tx=snap["tx"],
                 rx=snap["rx"],
                 pps=round(snap["tx"] / elapsed, 1) if elapsed else 0.0)
        if str(ixnet.Traffic.State) in ("stopped", "unapplied", "error"):
            break

    if str(ixnet.Traffic.State) not in ("stopped", "unapplied"):
        ixnet.Traffic.Stop()
    seconds = time.time() - started
    time.sleep(STATS_SETTLE)
    final = sample(view, names, by_name)

    whole = final["counted"] == len(names) and final["counted"] > 0
    source = "traffic_item" if whole else "partial"
    note = "" if whole else (
        "счётчики пришли не по всем потокам (%d из %d) - потери посчитаны "
        "не по всему прогону" % (final["counted"], len(names)))
    return {
        "tx": final["tx"],
        "rx": final["rx"],
        "tx_bytes": final["tx_bytes"],
        "seconds": round(seconds, 3),
        "achieved_pps": round(final["tx"] / seconds, 1) if seconds else 0.0,
        "rx_source": source,
        "reliable": whole,
        "truncated": [],
        "note": note,
    }


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Профиль трафика для Ixia IxNetwork, собранный TRaphy")
    ap.add_argument("--api-host", required=True,
                    help="API-сервер IxNetwork (Windows GUI или Linux API)")
    ap.add_argument("--api-port", type=int, default=11009,
                    help="порт API: 11009 у Windows, 443 у Linux")
    ap.add_argument("--api-user", default="",
                    help="логин; пустой - сервер без авторизации")
    ap.add_argument("--chassis", required=True, help="адрес шасси")
    ap.add_argument("--tx-port", required=True, help="порт отправки, карта/порт")
    ap.add_argument("--rx-port", required=True, help="порт приёма, карта/порт")
    ap.add_argument("--duration", type=float, default=10.0, help="секунд")
    ap.add_argument("--pps", type=float, default=0.0,
                    help="общая цель по pps; масштабирует потоки пропорционально")
    ap.add_argument("--count", type=int, default=0,
                    help="не поддерживается: счёт кадров задаётся режимом потока")
    ap.add_argument("--force", action="store_true",
                    help="отобрать порт у владельца - по умолчанию не отбираем")
    ap.add_argument("--dry-run", action="store_true",
                    help="показать, что будет настроено, шасси не трогая")
    ap.add_argument("--quiet", action="store_true",
                    help="без машинных @traphy строк")
    return ap.parse_args(argv)


def refuse(quiet, message, code):
    emit(quiet, ev="error", msg=message)
    print(message, file=sys.stderr)
    return code


def main(argv=None):
    args = parse_args(argv)
    quiet = args.quiet

    if not VM_FRAMES:
        return refuse(quiet, "в профиле нет включённых потоков", 2)

    if args.count:
        return refuse(quiet,
                      "счёт кадров здесь задаётся режимом потока, а не общим "
                      "числом: поставь потоку очередь на нужное количество", 2)

    if args.pps and not ALL_PPS:
        return refuse(quiet,
                      "общий pps можно задать только профилю, у которого все "
                      "потоки заданы в pps - здесь есть проценты или биты, и "
                      "масштабировать их вместе значило бы выдумывать", 2)

    for line in WARNINGS:
        emit(quiet, ev="note", msg=line)
        print(line, file=sys.stderr)

    emit(quiet, ev="ready", frames=sum(VM_FRAMES.values()),
         iface="%s %s" % (args.chassis, args.tx_port),
         rx_iface="%s %s" % (args.chassis, args.rx_port),
         pps=args.pps or TOTAL_PPS, duration=args.duration, count=0,
         truncated=[])

    for name, frames in VM_FRAMES.items():
        emit(quiet, ev="stream", name=name, frames=frames)

    if args.dry_run:
        print("шасси %s, порты %s → %s, %.0f pps суммарно"
              % (args.chassis, args.tx_port, args.rx_port,
                 args.pps or TOTAL_PPS))
        for name, frames in VM_FRAMES.items():
            print("%s: обход %d кадров" % (name, frames))
        emit(quiet, ev="done", tx=0, rx=0, seconds=0.0, tx_bytes=0,
             achieved_pps=0.0, rx_source="none", reliable=False,
             note="сухой прогон - шасси не трогали")
        return 0

    try:
        api = load_api()
    except ApiMissing as exc:
        return refuse(quiet, exc.explain(), 3)

    assistant = None
    try:
        assistant = connect(api, args)
        tx_vport, rx_vport = vports(assistant)
        names, sizes = build_traffic(assistant.Ixnetwork, tx_vport, rx_vport,
                                     args.duration)
        result = run(assistant, args, names, sizes, quiet)
    except (NoPassword, FieldMissing, PortBusy) as exc:
        return refuse(quiet, exc.explain(), 4)
    except Exception as exc:
        # The restpy client raises its own types and we only have them after
        # the import above, so there is nothing narrower to catch here that
        # would not be a guess. The message is what the operator needs.
        return refuse(quiet, "IxNetwork на %s: %s" % (args.api_host, exc), 1)
    finally:
        if assistant is not None:
            try:
                assistant.Session.remove()
            except Exception:
                # Losing the session on the way out must not replace whatever
                # actually went wrong inside the run.
                pass

    emit(quiet, ev="done", **result)
    loss = max(0, result["tx"] - result["rx"])
    share = (loss / result["tx"] * 100.0) if result["tx"] else 0.0
    tail = ("принято %d, потеряно %d (%.2f%%)" % (result["rx"], loss, share)
            if result["reliable"] else result["note"])
    print("отправлено %d кадров за %.1f c (%.0f pps), %s"
          % (result["tx"], result["seconds"], result["achieved_pps"], tail))
    return 0


if __name__ == "__main__":
    sys.exit(main())'''
