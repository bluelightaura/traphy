"""Turn a :class:`~traphy.models.Profile` into a control script for TRex.

The Scapy engine ships a script that *is* the generator: it opens a raw socket
and paces frames itself. TRex does not work that way. The generator is a daemon
that already owns the NICs through DPDK, and a run means connecting to it,
handing it a profile, starting it, reading its counters and stopping. So what
this module emits is a *control* script - it talks to a server, it does not
send anything itself - and that difference shows up everywhere:

* **No root.** The daemon was started with root long ago; the script that
  drives it is an ordinary client. :meth:`TrexEngine.needs_root` says so.
* **Ranges are not expanded.** A /16 sweep is four bytes of field-engine
  configuration, not 65 536 frames in memory. The Scapy engine caps such a
  range and reports the truncation; here there is nothing to cap, which is one
  of the two reasons to reach for TRex at all.
* **Loss is counted in hardware.** Each stream carries a flow-stats group id,
  and the NIC counts frames of that group on the receiving port. That is a
  different number from "a sniffer matched a marker in the payload", and a far
  better one - so the script labels which of the two it used and refuses to
  dress one up as the other.
* **Frames are built by TRex's own Scapy.** The field engine writes at offsets
  resolved against the Scapy that ships inside the release. A frame crafted by
  some other Scapy can put a field at a different offset and the writes land in
  the wrong place - producing traffic that looks plausible and tests nothing.
  The script therefore puts the release's control plane on ``sys.path`` before
  importing anything and builds frames from what it finds there.

Progress comes back as the same ``@traphy {json}`` lines the Scapy script
emits, so :mod:`traphy.runner` folds either engine's run into a result without
knowing which one produced it.
"""

from __future__ import annotations

import hashlib
import ipaddress

from traphy import codegen_ship
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

# TRex writes a stream's flow-stats group id into the IPv4 identification field
# and keeps one hardware counter per id. Past this many the server refuses the
# stream, so the extra streams go out uncounted - and the script names them
# rather than letting the loss column quietly describe only part of the run.
MAX_PG_ID = 127

# Where a release keeps its control plane, relative to the install directory.
STL_PATHS = (
    "automation/trex_control_plane/interactive",
    "automation/trex_control_plane/stl",
)


def generate(profile: Profile, tag: str = "") -> str:
    """The complete control script for ``profile`` as one string."""
    enabled = profile.enabled_streams
    skipped = [s.name for s in profile.streams if not s.enabled]

    counted = len([s for s in enabled if s.packet.has_ip])
    parts = [_header(profile, skipped, tag, enabled), _HELPERS,
             codegen_ship.SHIP, _builder(enabled, _pg_base(tag, counted)),
             _ENGINE]
    return "\n\n".join(parts) + "\n"


def ordered_frames(profile: Profile) -> int:
    """How many frames this profile commits to sending, or 0 when it does not.

    Конечный план есть только у очередей: там число кадров названо заранее, и
    факт можно сверить с ним строго. У continuous плана нет по устройству
    режима - он льёт, пока его не остановят, - поэтому один такой поток делает
    бесплановым весь прогон. Врать тут нельзя в обе стороны: выдуманный план
    отменял бы годные замеры, отсутствие плана оставляет недоотправку
    незамеченной.
    """
    frames = 0
    for s in profile.enabled_streams:
        if s.tx_mode is TxMode.CONTINUOUS:
            return 0
        bursts = s.number_of_bursts if s.tx_mode is TxMode.MULTI_BURST else 1
        frames += max(0, s.pkts_per_burst) * max(1, bursts)
    return frames


def _pg_base(tag: str, counted: int) -> int:
    """Where this run's hardware counter groups start.

    The first group used to be zero every single run, and that is the one place
    repeatability does harm. A frame carries the group number and nothing about
    which run put it there, so a previous run's tail still circulating in the
    segment is counted by the current one as its own. On the bench that turned
    4001 sent frames into 142 250 747 "received" - and the run before it, with
    the groups blind, showed zero. Same cause, opposite symptom.

    Это не защита от чужого инструмента: он может взять ту же группу. От чужого
    защищает холостой замер перед стартом - см. ``idle_check``.
    """
    room = MAX_PG_ID - max(1, counted)
    if room <= 0 or not tag:
        return 0
    return int(hashlib.sha256(tag.encode("utf-8")).hexdigest()[:8], 16) % room


def frame_count(profile: Profile) -> int:
    """How many distinct frames the field engine will walk through.

    Deliberately uncapped, unlike the Scapy engine's count: nothing here is
    expanded into memory, so a quarter of a million frames is a number the
    operator should simply see rather than a warning about truncation.
    """
    return sum(_stream_frames(s) for s in profile.enabled_streams)


def _stream_frames(s: Stream) -> int:
    """The size of the space one stream's ranges walk, 1 when it has none."""
    frames = 1
    for vf in s.vm_fields:
        frames *= max(1, range_size(vf))
    return frames


def script_name(profile: Profile) -> str:
    base = "".join(c if c.isalnum() or c in "-_" else "_" for c in profile.name)
    return f"{base or 'profile'}.py"


def warnings(profile: Profile) -> list[str]:
    """What this profile loses on TRex, said before the run rather than after.

    Two things TRex cannot do quietly: count loss on a frame with no IP header,
    and keep a correct L4 checksum while the field engine walks the ports.
    Both are fine for a switch and both matter for anything that inspects
    further up, so they are named here and repeated by the running script.
    """
    out: list[str] = []
    for s in profile.enabled_streams:
        if not s.packet.has_ip:
            out.append(f"поток «{s.name}»: кадр без IP - потери по нему "
                       f"считаться не будут, TRex метит группы полем IP ID")
        if _walks_ports(s) and s.packet.l4_proto is L4Proto.TCP:
            out.append(f"поток «{s.name}»: перебираются порты TCP - "
                       f"контрольная сумма TCP пересчитываться не будет")
    counted = [s for s in profile.enabled_streams if s.packet.has_ip]
    if len(counted) > MAX_PG_ID:
        out.append(f"потоков с IP {len(counted)}, аппаратных счётчиков "
                   f"{MAX_PG_ID} - лишние уйдут без счёта приёма")
    return out


def _walks_ports(s: Stream) -> bool:
    return any(not vf.target.is_ip for vf in s.vm_fields)


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
def _header(profile: Profile, skipped: list[str], tag: str,
            enabled: list[Stream]) -> str:
    desc = profile.description or "-"
    note = f"# Выключенные потоки не вошли: {', '.join(skipped)}\n" if skipped else ""
    run_tag = f"# Метка прогона: {tag}\n" if tag else ""
    paths = ", ".join(repr(p) for p in STL_PATHS)
    walk = {s.name: _stream_frames(s) for s in enabled}
    said = warnings(profile)
    ordered = ordered_frames(profile)
    return f'''\
#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Профиль: {profile.name}
# {desc}
{note}{run_tag}#
# Сгенерировано TRaphy. Это управляющий скрипт: сам он ничего не шлёт, а
# говорит демону TRex, что слать. Нужен Python 3 и распакованный релиз TRex;
# root не нужен - демон подняли с ним задолго до нас.
#
#   ./{script_name(profile)} --trex-dir /opt/trex --tx-port 0 --rx-port 1 --duration 10
#
# Кадры собираются Scapy из самого релиза: field engine пишет по смещениям,
# посчитанным против него, и чужой Scapy положил бы их мимо. Поэтому control
# plane релиза встаёт в sys.path раньше всего остального.
#
# Потери считаются flow stats - счётчиками в железе по группе потока, а не
# сниффером по метке в теле кадра. Без --rx-port приём не измеряется, и в
# отчёте написано именно это, а не ноль.
# ---------------------------------------------------------------------------
import argparse
import base64
import importlib
import json
import os
import shutil
import sys
import tempfile
import time
import traceback

STL_PATHS = ({paths},)

# Сколько кадров обойдёт field engine по каждому потоку - посчитано при
# генерации, здесь просто чтобы отчёт назвал число, а не разворачивал его в
# память. В этом и разница с Scapy: там диапазон превращается в кадры, тут - в
# четыре байта настройки.
VM_FRAMES = {walk!r}

# То, что этот профиль теряет именно на TRex. Список собран при генерации и
# лежит прямо здесь, чтобы сохранённый скрипт говорил это сам, без TRaphy.
WARNINGS = {said!r}

# Сколько кадров профиль обещает послать: 0 - плана нет, прогон по времени.
ORDERED = {ordered}

# Метка прогона. Раньше жила только в комментарии выше - а она нужна коду: по
# ней след аренды опознаёт, чей это прогон.
RUN_TAG = {tag!r}'''


# --------------------------------------------------------------------------- #
# Fixed helpers, emitted verbatim
# --------------------------------------------------------------------------- #
_HELPERS = '''\
def emit(quiet, **event):
    """One machine-readable progress line, or nothing when muted."""
    if not quiet:
        sys.stdout.write("@traphy " + json.dumps(event) + "\\n")
        sys.stdout.flush()


def load_api(trex_dir):
    """Import TRex's stateless API from the release, not from site-packages.

    The order matters: the release's control plane goes on the path first so
    that the Scapy it bundles is the one the field-engine offsets were computed
    against. Both the modern layout and the older one are tried, because a
    bench running a 2.x release is a perfectly ordinary bench.
    """
    for relative in STL_PATHS:
        path = os.path.join(trex_dir, relative)
        if os.path.isdir(path) and path not in sys.path:
            sys.path.insert(0, path)
    problems = []
    for name in ("trex.stl.api", "trex_stl_lib.api"):
        try:
            return importlib.import_module(name)
        except ImportError as exc:
            problems.append("%s: %s" % (name, exc))
    raise ApiMissing(trex_dir, problems)


class ApiMissing(Exception):
    """The release is not where we were told it is, or is not a release."""

    def __init__(self, trex_dir, problems):
        Exception.__init__(self, trex_dir)
        self.trex_dir = trex_dir
        self.problems = problems

    def explain(self):
        return ("в %s не нашлось управляющей библиотеки TRex (%s) - "
                "проверь --trex-dir: там должен лежать automation/"
                "trex_control_plane" % (self.trex_dir, "; ".join(self.problems)))


def layers(api):
    """Ether/Dot1Q/IP/UDP/TCP as the release's own Scapy defines them."""
    names = ("Ether", "Dot1Q", "IP", "UDP", "TCP")
    found = {}
    missing = []
    for name in names:
        value = getattr(api, name, None)
        if value is None:
            missing.append(name)
        else:
            found[name] = value
    if missing:
        # The api module re-exports these in most releases; where it does not,
        # Scapy itself is already on the path because the api imported it.
        scapy = importlib.import_module("scapy.all")
        for name in missing:
            found[name] = getattr(scapy, name)
    return found


def pad(base, size):
    """Grow a frame to `size` bytes of L2, the FCS excluded.

    The same accounting the Scapy engine uses, deliberately: one profile has to
    put the same number of bytes on the wire whichever engine sends it, or the
    two are not comparable and the whole point of having both is gone. A frame
    already at or over the size is left alone rather than cut.
    """
    need = size - len(base)
    return base / ("x" * need) if need > 0 else base


def flow_stats(api, pg_id):
    """The hardware counter for one stream, or None when it cannot have one."""
    if pg_id is None:
        return None
    return api.STLFlowStats(pg_id=pg_id)


def port_stats(stats, port):
    """One port's counters, whichever way this release keys them.

    Worth a function because of what depends on it: the port counter is the
    only thing that can contradict a zero from the flow-stat groups. Miss the
    entry and the contradiction never happens - the safety net fails silently
    and a working link is reported as total loss with confidence on it.
    """
    if port < 0:
        return None
    entry = stats.get(port)
    if entry is None:
        entry = stats.get(str(port))
    return entry


def total(value):
    """Pull the aggregate out of a flow-stats entry, which is a per-port dict."""
    if isinstance(value, dict):
        return int(value.get("total", 0) or 0)
    return int(value or 0)


def per_port(value, port):
    """Группа считает по портам; нас интересует тот, который обязан принять.

    Возвращает (цифра по порту, есть ли вообще запись по нему).

    Агрегат ``total`` складывает все порты шасси. Кадр нашей группы, пришедший
    не на тот порт, где мы его ждём, в агрегате выглядит как наш принятый - а
    это вопрос к схеме стенда, не к устройству под нагрузкой. И отсутствие
    записи по нужному порту - это не ноль принятых: это «счётчика нет», и
    подменять его суммой по всем портам нельзя.
    """
    if not isinstance(value, dict) or port < 0:
        return 0, False
    for key in (port, str(port)):
        if key in value:
            return int(value[key] or 0), True
    return 0, False


def write_pcap(path, frames):
    """Write one sample frame per stream - what we built, before the engine.

    Deliberately not "the traffic": the field engine rewrites addresses and
    ports inside the server, and those frames never exist on this machine. A
    dump that implied otherwise would be worse than no dump.
    """
    scapy = importlib.import_module("scapy.all")
    scapy.wrpcap(path, frames)'''


# --------------------------------------------------------------------------- #
# The generated builder
# --------------------------------------------------------------------------- #
def _builder(streams: list[Stream], pg_base: int = 0) -> str:
    """Emit ``build_streams()``: the profile in TRex's own vocabulary."""
    body = [
        "def build_streams(api, L, want_flow_stats):",
        '    """Потоки профиля в форме TRex.',
        "",
        "    Возвращает (потоки, кадры-образцы, номера групп, потоки без",
        "    счётчика). Последнее - это те, чей приём померить нечем; отчёт",
        "    обязан их назвать, иначе колонка потерь описывает не весь прогон.",
        '    """',
        "    streams = []",
        "    frames = []",
        "    pg_ids = []",
        "    uncounted = []",
        f"    pg_next = {pg_base}",
    ]
    for s in streams:
        body.append("")
        body.extend(_stream_block(s))
    body.append("")
    body.append("    return streams, frames, pg_ids, uncounted")
    return "\n".join(body)


def _stream_block(s: Stream) -> list[str]:
    """One stream: the frame, the field engine over it, the rate it goes at."""
    p = s.packet
    out = [f"    # --- поток «{s.name}»: {_shape(s)}"]

    frame = [f'L["Ether"](src={p.eth_src!r}, dst={p.eth_dst!r})']
    if p.has_vlan:
        frame.append(f'L["Dot1Q"](vlan={p.vlan}, prio={p.vlan_pcp})')
    if p.has_ip:
        # Without a transport above it the frame still needs a protocol number
        # that exists; 61 is IANA's "any host internal protocol", which is what
        # a bare payload under IP actually is.
        proto = "" if p.has_l4 else ", proto=61"
        frame.append(f'L["IP"](src={p.ip_src!r}, dst={p.ip_dst!r}, '
                     f"ttl={p.ttl}{proto})")
    if p.has_l4:
        name = "TCP" if p.l4_proto is L4Proto.TCP else "UDP"
        # A UDP checksum of zero is the legal way to say "not computed", which
        # is the honest thing to send when the field engine is about to move
        # the ports underneath it. TCP has no such escape - see warnings().
        zero = ", chksum=0" if _walks_ports(s) and p.l4_proto is L4Proto.UDP else ""
        frame.append(f'L["{name}"](sport={p.sport}, dport={p.dport}{zero})')

    out.append("    base = " + " / ".join(frame))
    out.append(f"    base = pad(base, {p.frame_size})")
    out.append("    frames.append(base)")

    vm_lines = _vm_lines(s)
    if vm_lines:
        out.append("    vm = []")
        out.extend(vm_lines)
        out.append("    packet = api.STLPktBuilder(pkt=base, vm=api.STLScVmRaw(vm))")
    else:
        out.append("    packet = api.STLPktBuilder(pkt=base)")

    # Flow stats need an IPv4 header to carry the group id, so an L2 stream is
    # simply not countable and says so instead of reporting a zero.
    if p.has_ip:
        out.extend([
            f"    pg = pg_next if want_flow_stats and pg_next < {MAX_PG_ID} else None",
            "    if pg is None:",
            f"        uncounted.append({s.name!r})",
            "    else:",
            "        pg_ids.append(pg)",
            "        pg_next += 1",
        ])
    else:
        out.append("    pg = None")
        out.append(f"    uncounted.append({s.name!r})")

    out.append(f"    streams.append(api.STLStream(name={s.name!r}, packet=packet,")
    out.append(f"                                 mode={_mode_expr(s)},")
    out.append("                                 flow_stats=flow_stats(api, pg)))")
    return out


def _vm_lines(s: Stream) -> list[str]:
    """The field-engine program for one stream's ranges.

    Ranges that do not fit the frame's layers are dropped here rather than sent
    to the server, which would refuse them with a message about offsets that
    says nothing about the profile. :meth:`Profile.validate` catches the same
    thing earlier and in words; this is the belt to that's braces.
    """
    lines: list[str] = []
    touches_ip = False
    for i, vf in enumerate(s.vm_fields):
        if vf.target.is_ip and not s.packet.has_ip:
            continue
        if not vf.target.is_ip and not s.packet.has_l4:
            continue
        var = f"{vf.target.value}_{i}"
        lo, hi = _bounds(vf)
        size = 4 if vf.target.is_ip else 2
        step = f", step={vf.step}" if vf.op is not VMOp.RANDOM and vf.step != 1 else ""
        lines.append(f"    vm.append(api.STLVmFlowVar(name={var!r}, "
                     f"min_value={lo}, max_value={hi}, size={size}, "
                     f"op={vf.op.value!r}{step}))   # {vf.describe()}")
        lines.append(f"    vm.append(api.STLVmWrFlowVar(fv_name={var!r}, "
                     f"pkt_offset={_offset(s, vf.target)!r}))")
        touches_ip = touches_ip or vf.target.is_ip
    if touches_ip:
        # The header checksum has to be recomputed after the engine moves an
        # address, and it has to be the last thing the program does.
        lines.append('    vm.append(api.STLVmFixIpv4(offset="IP"))')
    return lines


def _bounds(vf) -> tuple[int, int]:
    """A range's ends as the integers TRex wants, in ascending order.

    Addresses are converted here rather than left as strings: some releases
    accept the dotted form and some do not, and a profile that works on the
    bench you have and not on the one you borrow is a bad trade for four
    characters of source.
    """
    if vf.target.is_ip:
        lo = int(ipaddress.IPv4Address(vf.min_value))
        hi = int(ipaddress.IPv4Address(vf.max_value))
    else:
        lo, hi = int(vf.min_value), int(vf.max_value)
    return (lo, hi) if lo <= hi else (hi, lo)


def _offset(s: Stream, target: FieldTarget) -> str:
    """Where in the frame the engine writes, named by layer as TRex expects."""
    if target is FieldTarget.IP_SRC:
        return "IP.src"
    if target is FieldTarget.IP_DST:
        return "IP.dst"
    layer = "TCP" if s.packet.l4_proto is L4Proto.TCP else "UDP"
    field = "sport" if target is FieldTarget.SPORT else "dport"
    return f"{layer}.{field}"


def _mode_expr(s: Stream) -> str:
    """The TX mode with its rate, as the call that builds it."""
    rate = _rate_kwarg(s)
    if s.tx_mode is TxMode.CONTINUOUS:
        return f"api.STLTXCont({rate})"
    if s.tx_mode is TxMode.SINGLE_BURST:
        return f"api.STLTXSingleBurst(total_pkts={s.pkts_per_burst}, {rate})"
    return (f"api.STLTXMultiBurst(pkts_per_burst={s.pkts_per_burst}, "
            f"count={s.number_of_bursts}, ibg={s.ibg_usec:g}, {rate})")


def _rate_kwarg(s: Stream) -> str:
    if s.rate_type is RateType.PPS:
        return f"pps={s.rate_value:g}"
    if s.rate_type is RateType.BPS_L2:
        return f"bps_L2={int(s.rate_value)}"
    return f"percentage={s.rate_value:g}"


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
# Что говорить про цифру приёма, смотря по тому, чем её померили. Молчать
# нельзя ни в одном случае: через неделю от прогона останется число, а не
# воспоминание о том, как оно получено, - поэтому источник едет вместе с ним.
SOURCE_NOTES = {
    "flow_stats": "",
    "mixed": "часть потоков без аппаратного счёта - потери посчитаны "
             "не по всему прогону",
    "port_counter": "приём считан счётчиком порта: туда легло всё, что в него "
                    "прилетело, а не только наши кадры",
    "flow_stats_blind": "группы потока на приёме не сосчитали НИЧЕГО, а порт "
                        "принял кадры - цифра взята со счётчика порта. "
                        "Так ведёт себя часть карт и драйверов: отправка "
                        "считается, приём нет",
    "flow_stats_unverified": "группы потока на приёме показали ноль, а "
                             "счётчик порта приёма не прочитался - сверить "
                             "было нечем, поэтому ноль подаётся как неточный",
    "flow_stats_foreign": "в нашу группу попали кадры, пришедшие не на тот "
                          "порт, который по схеме обязан принимать - цифра "
                          "приёма описывает не наш путь. Смотреть надо схему "
                          "стенда и изоляцию сегмента",
    "flow_stats_noport": "у группы нет разбивки по нашему порту приёма - "
                         "счётчика нет, и это не то же самое, что ноль "
                         "принятых; цифра взята по всем портам сразу",
    "flow_stats_tainted": "в наши группы на приёме уже шли кадры, когда мы "
                          "ещё ничего не отправляли, - значит в счёт попало не "
                          "только наше. Аппаратный счёт тут не считается "
                          "надёжным, сколько бы ровно он ни выглядел",
    "none": "приём не измерялся - без --rx-port считать нечем",
}


class Busy(Exception):
    """The ports belong to somebody else and we were not told to take them."""


class Dirty(Exception):
    """The ports are ours now, but somebody left them in a working state."""


def service_is_on(client, port):
    """Стоит ли порт в сервисном режиме. None - узнать не удалось.

    Разные релизы отдают атрибуты порта по-разному, а гадать тут нельзя в обе
    стороны: соврать «режим выключен» значит пропустить остаток, соврать
    «включён» значит отказать на чистой машине. Поэтому «не знаю» - отдельный
    ответ, и он никого ни в чём не обвиняет.
    """
    getter = getattr(client, "get_port_attr", None)
    if getter is None:
        return None
    try:
        attr = getter(port)
    except Exception:
        return None
    if not isinstance(attr, dict):
        return None
    for key in ("service", "service_mode", "is_service_mode"):
        if key in attr:
            value = attr[key]
            if isinstance(value, str):
                return value.strip().lower() in ("on", "true", "yes", "1")
            return bool(value)
    return None


def live_captures(client):
    """Сколько записей висит на демоне. None - узнать не удалось."""
    for name in ("get_capture_status", "capture_status"):
        getter = getattr(client, name, None)
        if getter is None:
            continue
        try:
            status = getter()
        except Exception:
            return None
        if isinstance(status, dict):
            return len(status)
        if isinstance(status, (list, tuple)):
            return len(status)
    return None


# Имена счётчиков ошибок приходят от драйвера, и одно и то же зовётся у разных
# карт по-разному. Поэтому разбор по подстрокам, а незнакомое имя называется
# незнакомым: приговор остаётся за человеком, программа говорит, что это и куда
# смотреть. Соврать здесь дороже, чем промолчать.
#
# Деление важнее самих имён. Счётчик генератора означает, что кадры потерялись
# НА НАШЕЙ стороне, не дойдя до устройства, - потери такого прогона считать
# нельзя вообще. Счётчик линка означает кабель, оптику или согласование, и это
# тоже не про устройство под нагрузкой.
ERR_GENERATOR = ("missed", "no_buffer", "nombuf", "mbuf", "alloc",
                 "out_of_buffer", "no_dma")
ERR_LINK = ("crc", "phy", "symbol", "illegal", "oversize", "undersize",
            "fragment", "jabber", "align")
ERR_MARKS = ERR_GENERATOR + ERR_LINK + ("err", "drop", "discard")


def error_kind(name):
    """generator | link | unknown - по имени счётчика, как его зовёт драйвер."""
    low = name.lower()
    for mark in ERR_GENERATOR:
        if mark in low:
            return "generator"
    for mark in ERR_LINK:
        if mark in low:
            return "link"
    return "unknown"


def read_xstats(client, ports):
    """Счётчики ошибок портов. Пусто, если релиз их не отдаёт.

    Берутся только те, в чьём имени есть признак ошибки: среди xstats полно
    обычных счётчиков кадров, и они растут на любом прогоне - мешать их с
    ошибками значит утопить находку в шуме.
    """
    getter = getattr(client, "get_xstats", None)
    if getter is None:
        return {}
    out = {}
    for port in ports:
        try:
            stats = getter(port)
        except Exception:
            continue
        if not isinstance(stats, dict):
            continue
        for name, value in stats.items():
            low = str(name).lower()
            if not any(mark in low for mark in ERR_MARKS):
                continue
            try:
                out["%d:%s" % (port, name)] = int(value)
            except (TypeError, ValueError):
                continue
    return out


def grown_errors(before, after):
    """Что выросло за прогон, с разбором по виду. Только прирост, не абсолют."""
    grew = {}
    kinds = {}
    for name, value in (after or {}).items():
        delta = value - (before or {}).get(name, 0)
        if delta > 0:
            grew[name] = delta
            kinds[name] = error_kind(name.split(":", 1)[-1])
    return grew, kinds


# --------------------------------------------------------------------------- #
# След аренды: чем прогон говорит следующему, что порты заняты им
# --------------------------------------------------------------------------- #
LEASE_DIR = "/tmp/traphy"


def lease_path(args, ports):
    """Один файл на набор портов - ресурс именно они, а не прогон.

    Каталог задаётся снаружи: на машине-генераторе он общий для всех, кто с неё
    работает, и подменить его нужно и в тестах, и там, где /tmp чистят по
    расписанию - след, исчезнувший сам, оставит порты без владельца.
    """
    return os.path.join(getattr(args, "lease_dir", "") or LEASE_DIR,
                        "lease-%s.json" % "-".join(str(p) for p in sorted(ports)))


def process_identity(pid=None):
    """Чем этот процесс отличается от другого с тем же номером.

    Номер pid переиспользуется, поэтому «процесс 1234 жив» само по себе не
    значит ничего: это может быть уже другой процесс. К номеру добавляются
    идентификатор загрузки системы и момент старта процесса в тиках - вместе они
    опознают именно тот процесс, который брал порты, и только его.
    """
    pid = os.getpid() if pid is None else pid
    boot = ""
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            boot = fh.read().strip()
    except OSError:
        pass
    started = ""
    try:
        with open("/proc/%d/stat" % pid) as fh:
            # Поле 22 - момент старта процесса. Имя процесса в скобках может
            # содержать пробелы, поэтому отсчёт идёт от закрывающей скобки.
            fields = fh.read().rsplit(") ", 1)[-1].split()
        started = fields[19]
    except (OSError, IndexError):
        pass
    return {"pid": pid, "boot": boot, "started": started}


def owner_alive(who):
    """Жив ли тот самый процесс, который взял порты. None - не определить."""
    now = process_identity(who.get("pid") or 0)
    if who.get("boot") and now["boot"] and who["boot"] != now["boot"]:
        return False                  # машина перезагружалась - процесса нет
    try:
        os.kill(int(who.get("pid") or 0), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                   # чужой процесс, но он есть
    except (OSError, ValueError):
        return None
    if who.get("started") and now["started"] and who["started"] != now["started"]:
        return False                  # номер переиспользован другим процессом
    return True


def write_lease(args, ports, pg_ids, quiet):
    """Оставить след: кто держит эти порты и чем его опознать.

    Нужен ровно для одного - чтобы за прогоном, убитым сигналом, можно было
    убрать. Его ``finally`` не исполняется вовсе, и без следа следующий человек
    видит порты, занятые неизвестно кем, и машину в состоянии, которого он не
    делал.
    """
    path = lease_path(args, ports)
    data = dict(process_identity(), ports=list(ports), pg_ids=list(pg_ids),
                tag=RUN_TAG, at=time.strftime("%Y-%m-%d %H:%M:%S"))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh)
        os.chmod(path, 0o600)
    except OSError as exc:
        emit(quiet, ev="note",
             msg="след аренды не записался (%s) - убрать за этим прогоном "
                 "автоматически будет нечем" % exc)
        return None
    return path


def update_lease(path, **fields):
    """Дописать в след то, что выяснилось позже: что мы переключили на портах.

    След пишется сразу после захвата, чтобы он существовал как можно раньше, -
    а сервисный режим и promiscuous меняются после. Без этого шага уборка знала
    бы, какие порты занять, но не знала бы, в какое состояние их вернуть.
    """
    if not path:
        return
    try:
        with open(path) as fh:
            data = json.load(fh)
        data.update(fields)
        with open(path, "w") as fh:
            json.dump(data, fh)
    except (OSError, ValueError):
        pass


def drop_lease(path):
    """Убрать след за собой. Молча: прогон уже кончился, добавить нечего."""
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


def port_flag(client, port, *names):
    """Значение флага порта по любому из его имён. None - не узнать."""
    getter = getattr(client, "get_port_attr", None)
    if getter is None:
        return None
    try:
        attr = getter(port)
    except Exception:
        return None
    if not isinstance(attr, dict):
        return None
    for name in names:
        if attr.get(name) is not None:
            value = attr[name]
            if isinstance(value, str):
                return value.strip().lower() in ("on", "true", "yes", "1")
            return bool(value)
    return None


def take_promiscuous(client, args, quiet):
    """Включить promiscuous на порту приёма, запомнив, как было.

    Карта с выключенным promiscuous отбрасывает кадры с чужим MAC, и приём
    читается нулём при исправном линке и идущем трафике. Пресеты шлют с
    выдуманными адресами - для коммутации это нормально и даже правильно, - но
    принимающий порт обязан их пропустить, иначе ноль в колонке приёма описывает
    фильтр карты, а выглядит как потери на устройстве.

    Возвращает (порт, как было) либо None, когда менять нечего. Включать молча
    нельзя: это изменение состояния чужой машины, и вернуть его обязаны мы.
    """
    if args.rx_port < 0 or not args.promiscuous:
        return None
    setter = getattr(client, "set_port_attr", None)
    if setter is None:
        return None
    was = port_flag(client, args.rx_port, "prom", "promiscuous")
    if was is True:
        return None                      # уже включён - трогать нечего
    try:
        setter(ports=[args.rx_port], promiscuous=True)
    except Exception as exc:
        emit(quiet, ev="note",
             msg="promiscuous на порту %d включить не удалось (%s) - если приём "
                 "окажется нулевым при идущем трафике, подозревать надо фильтр "
                 "карты, а не устройство" % (args.rx_port, exc))
        return None
    emit(quiet, ev="note",
         msg="promiscuous на порту %d включён на время прогона - кадры с "
             "выдуманными MAC иначе отбрасывает сама карта" % args.rx_port)
    return (args.rx_port, bool(was))


def link_is_down(client, ports):
    """Упал ли линк на наших портах. None - узнать не удалось.

    Линк, упавший ПОСРЕДИ прогона, не ловится больше ничем: до старта TRex сам
    откажется стартовать на упавшем порту, а дальше тишина в кабеле выглядит
    ровно как потери на устройстве. Поэтому его состояние спрашивается в каждом
    тике, и один упавший порт отменяет замер целиком.
    """
    getter = getattr(client, "get_port_attr", None)
    if getter is None:
        return None
    seen = False
    for port in ports:
        try:
            attr = getter(port)
        except Exception:
            continue
        if not isinstance(attr, dict) or attr.get("link") is None:
            continue
        seen = True
        if str(attr["link"]).strip().upper().startswith("DOWN"):
            return True
    return False if seen else None


def leftovers(client, ports):
    """What somebody left behind on ports that are now ours.

    Проверяется ПОСЛЕ захвата и ДО любого изменения состояния - это
    единственное место, где виден остаток прогона, убитого сигналом: его
    ``finally`` не исполнялся вовсе, поэтому на машине остаются идущий трафик,
    включённый сервисный режим и живая запись. Следующий человек получает
    отказ, к его работе отношения не имеющий, и связать его с записью,
    снятой часами раньше, не может никто.

    Отдельно важен идущий трафик: continuous-поток мёртвого владельца льёт
    кадры в порт приёма и попадает в наш групповой счёт - ровно это и дало на
    стенде 142 млн «принятых» при четырёх тысячах отправленных.
    """
    found = []
    try:
        if client.is_traffic_active(ports=ports):
            found.append("на портах идёт трафик - либо чужой, либо оставшийся "
                         "после прогона, который не убрал за собой")
    except Exception:
        pass
    for port in ports:
        if service_is_on(client, port) is True:
            found.append("порт %d стоит в сервисном режиме - его оставили "
                         "включённым, и потолок скорости на нём занижен"
                         % port)
    live = live_captures(client)
    if live:
        found.append("на демоне висит записей: %d - пока они живы, сервисный "
                     "режим не выключается" % live)
    return found


def clear_leftovers(client, ports, found, quiet):
    """Убрать остаток - только когда оператор сказал это вслух."""
    emit(quiet, ev="note",
         msg="--force: убираю остаток перед прогоном (%s)" % "; ".join(found))
    try:
        client.stop(ports=ports)
    except Exception:
        pass
    for name in ("remove_all_captures", "clear_captures"):
        killer = getattr(client, name, None)
        if killer is not None:
            try:
                killer()
            except Exception:
                pass
            break
    try:
        client.set_service_mode(ports=ports, enabled=False)
    except Exception:
        pass


def take_ports(client, args, ports, quiet):
    """Take the ports, or say who has them instead of taking them anyway.

    ``reset()`` is what the examples reach for and it would be one line - but
    it is documented as a FORCE acquire. On a generator shared with other
    people that stops a colleague mid-measurement, and they learn about it
    from their own numbers rather than from us. So ownership is asked for
    politely here, and --force is the operator saying out loud that the port
    is to be taken regardless.

    What follows the acquire is the rest of what ``reset()`` does - our own
    leftovers cleared and the counters zeroed - with nobody else's run touched.
    """
    try:
        client.acquire(ports=ports, force=args.force)
    except Exception as exc:
        raise Busy("порты %s не отдаются: %s. Генератор общий - выясни, чей "
                   "прогон идёт, либо задай --force, чтобы отобрать"
                   % (", ".join(str(p) for p in ports), exc))
    # Порты наши - и прежде чем что-либо на них менять, надо посмотреть, в
    # каком виде их оставили. Отказ здесь дешевле замера, который потом никто
    # не сможет объяснить.
    found = leftovers(client, ports)
    if found and not args.force:
        raise Dirty("порты %s захвачены, но на них остался чужой след: %s. "
                    "Разберись, чей это прогон, либо задай --force - тогда "
                    "остаток будет убран и об этом будет сказано"
                    % (", ".join(str(p) for p in ports), "; ".join(found)))
    if found:
        clear_leftovers(client, ports, found, quiet)
    client.remove_all_streams(ports=ports)
    client.clear_stats()


def absolutes(client, args, pg_ids):
    """Счётчики как есть, ничего не вычитая - сырьё и для базы, и для замера.

    Отдельно от sample() ровно потому, что одни и те же цифры нужны в двух
    качествах: как опорная точка перед стартом и как показания по ходу. Читать
    их двумя разными кусками кода - значит однажды сравнить несравнимое.
    """
    stats = client.get_stats()
    port = port_stats(stats, args.tx_port) or {}
    rx_entry = port_stats(stats, args.rx_port)
    groups = stats.get("flow_stats") or {}
    seen = [groups[pg] for pg in pg_ids if pg in groups]
    return {
        "tx": int(port.get("opackets", 0) or 0),
        "tx_bytes": int(port.get("obytes", 0) or 0),
        "tx_pps": float(port.get("tx_pps", 0.0) or 0.0),
        "rx_port": int((rx_entry or {}).get("ipackets", 0) or 0),
        "rx_port_seen": rx_entry is not None,
        "group_tx": sum(total(g.get("tx_pkts")) for g in seen),
        "group_rx": sum(total(g.get("rx_pkts")) for g in seen),
        "group_rx_port": sum(per_port(g.get("rx_pkts"), args.rx_port)[0]
                             for g in seen),
        # Есть ли разбивка по нужному порту хотя бы у одной группы. Нет - это
        # отдельный ответ, а не ноль принятых.
        "group_rx_port_seen": any(per_port(g.get("rx_pkts"), args.rx_port)[1]
                                  for g in seen),
        "groups": len(seen),
    }


def ZERO_BASE():
    """Опорная точка, когда её не брали: вычитать нечего."""
    return {"tx": 0, "tx_bytes": 0, "rx_port": 0, "group_tx": 0,
            "group_rx": 0, "group_rx_port": 0}


def sample(client, args, pg_ids, counted_all, base=None):
    """One reading of the counters, and where each number came from.

    Всё считается РАЗНИЦЕЙ к опорной точке, снятой перед стартом. Абсолютные
    значения тут не годятся: демон живёт неделями, группу с тем же номером мог
    использовать прошлый прогон, и обнуление счётчиков до регистрации наших
    потоков наших групп не касается вовсе. Прочитанный абсолют выглядит как
    показание прибора - на стенде это дало 142 млн «принятых» при четырёх
    тысячах отправленных.
    """
    base = base or ZERO_BASE()
    raw = absolutes(client, args, pg_ids)
    out = {
        "tx": max(0, raw["tx"] - base["tx"]),
        "tx_bytes": max(0, raw["tx_bytes"] - base["tx_bytes"]),
        "tx_pps": raw["tx_pps"],
        "rx": 0,
        "rx_port": 0,
        "rx_groups": 0,
        "rx_foreign": 0,
        "source": "none",
    }
    # The receiving port's own counter, read whether or not flow stats are in
    # play. It is the only thing that can contradict a zero from the groups,
    # and a zero that nothing can contradict is how a working link gets
    # reported as a dead one.
    rx_entry = raw["rx_port_seen"]
    port_rx = max(0, raw["rx_port"] - base["rx_port"])
    out["rx_port"] = port_rx

    if raw["groups"]:
        group_all = max(0, raw["group_rx"] - base["group_rx"])
        group_rx = max(0, raw["group_rx_port"] - base["group_rx_port"])
        if not raw["group_rx_port_seen"]:
            # Разбивки по нашему порту нет вовсе. Это не ноль - это отсутствие
            # счётчика, и единственный честный ход тут назвать его так.
            group_rx = group_all
        out["rx"] = group_rx
        out["rx_groups"] = group_rx
        out["rx_foreign"] = max(0, group_all - group_rx)
        if counted_all:
            # Per-group counters in hardware on both sides. This is the one
            # reading here that goes into a report without a caveat - but only
            # while it is not being contradicted.
            group_tx = max(0, raw["group_tx"] - base["group_tx"])
            out["tx"] = group_tx or out["tx"]
            out["source"] = "flow_stats"
            if not raw["group_rx_port_seen"]:
                out["source"] = "flow_stats_noport"
            elif out["rx_foreign"]:
                # Кадры с нашей меткой группы пришли не на тот порт, который по
                # схеме обязан принимать. Сложить их с нашими - значит выдать
                # чужой путь за наш; это вопрос к схеме стенда.
                out["source"] = "flow_stats_foreign"
        else:
            out["source"] = "mixed"
        # The contradiction that matters: the groups counted nothing on the
        # receive side while the port counted plenty. Some cards and drivers
        # count transmission per group and never the reception, and trusting
        # the group there turns "everything arrived" into "100% loss" with
        # reliable=True on it - a confident wrong answer, which is worse than
        # an unsure right one. The port counter wins, and says why.
        if group_rx == 0 and port_rx > 0:
            out["rx"] = port_rx
            out["source"] = "flow_stats_blind"
        elif group_rx == 0 and not rx_entry and args.rx_port >= 0:
            # A zero nothing was able to contradict. It may well be the truth,
            # but it is exactly the shape a blind driver produces, and the one
            # reading that would have told them apart is missing. Saying so
            # costs a caveat; not saying so costs somebody a day on a link that
            # was fine.
            out["source"] = "flow_stats_unverified"
    elif args.rx_port >= 0:
        out["rx"] = port_rx
        out["source"] = "port_counter"
    return out


def idle_check(client, args, pg_ids, base, quiet):
    """Read the receive side while this run is deliberately sending nothing.

    Счётчики только что обнулены, потоки ещё не стартовали. Всё, что прибавится
    за эту паузу, пришло не от нас - и узнать это ДО замера дороже, чем после:
    иначе грязный сегмент выглядит как показания прибора. На стенде именно это и
    случилось - в порт приёма шло 33 млн кадров в секунду, и аппаратный счёт
    отдал 142 млн при четырёх тысячах отправленных.

    Группы важнее порта. В порт может лететь что угодно, это нормально и лишь
    делает счётчик порта приблизительным. А вот кадры, попадающие в НАШУ группу,
    отравляют единственную цифру, которой инструмент верит без оговорок.
    """
    if args.idle_check <= 0 or args.rx_port < 0:
        return None
    time.sleep(args.idle_check)
    now = absolutes(client, args, pg_ids)
    port_rx = max(0, now["rx_port"] - base["rx_port"])
    group_rx = max(0, now["group_rx_port"] - base["group_rx_port"])
    if not now["group_rx_port_seen"]:
        group_rx = max(0, now["group_rx"] - base["group_rx"])
    emit(quiet, ev="idle", seconds=args.idle_check, rx_port=port_rx,
         rx_groups=group_rx, pg_ids=list(pg_ids))
    if group_rx:
        emit(quiet, ev="note",
             msg="до старта в наши группы приёма легло %d кадров за %.1f c - "
                 "сегмент занят чужим трафиком с той же меткой группы; "
                 "аппаратный счёт по этому прогону доверия не заслуживает"
                 % (group_rx, args.idle_check))
    elif port_rx:
        emit(quiet, ev="note",
             msg="до старта в порт приёма легло %d кадров за %.1f c - в "
                 "сегменте идёт посторонний трафик; счёт по счётчику порта "
                 "в этом прогоне ничего не измерит" % (port_rx, args.idle_check))
    return {"rx_port": port_rx, "rx_groups": group_rx}


def start_capture(client, args, quiet, service_ports):
    """Begin recording both directions. Returns the handles, or None.

    Automatic rather than asked for. A run whose frames were not kept can
    answer "сколько" and never "что именно" - and the second question is the
    one that comes up a week later, when the counters are all anyone has and
    nobody remembers what was actually on the wire.

    This is TRex's software capture: frames are copied up to the control
    plane, so it cannot follow a line-rate run. Hence the limit, and hence the
    limit being said out loud rather than a partial recording being presented
    as a whole one.
    """
    if not args.capture:
        return None
    handles = {}
    ports = sorted({args.tx_port} | ({args.rx_port} if args.rx_port >= 0
                                     else set()))
    try:
        # TRex records nothing at all unless the port is in service mode: the
        # frames have to come up through the software path to be copied, and
        # in the fast path they never do. It costs rate, which is why the
        # result says the run was recorded instead of leaving the operator to
        # discover the ceiling and blame the device for it.
        client.set_service_mode(ports=ports, enabled=True)
        service_ports.extend(ports)
        for kind, port in (("tx", args.tx_port), ("rx", args.rx_port)):
            if port < 0:
                continue
            spec = {"limit": args.capture_limit, "mode": "fixed"}
            spec["tx_ports" if kind == "tx" else "rx_ports"] = [port]
            handles[kind] = client.start_capture(**spec)["id"]
    except Exception as exc:
        emit(quiet, ev="note",
             msg="захват не начался (%s) - прогон идёт без записи кадров" % exc)
        try:
            client.set_service_mode(ports=ports, enabled=False)
            while service_ports:
                service_ports.pop()
        except Exception:
            pass
        return None
    emit(quiet, ev="note",
         msg="идёт запись кадров, до %d на сторону; порты в сервисном режиме, "
             "потолок скорости в этом прогоне ниже обычного"
             % args.capture_limit)
    return handles


def stop_capture(client, args, handles, quiet):
    """Write each direction out and ship it back inside the event stream.

    The pcap is written on the machine that did the sending and has to reach
    the machine that will open it. It travels as base64 in the events rather
    than being left behind for somebody to collect: the generator is shared,
    and a tool that scatters files across a shared box is a tool people stop
    running.
    """
    if not handles:
        return
    folder = tempfile.mkdtemp(prefix="traphy-cap-")
    try:
        for kind, handle in sorted(handles.items()):
            path = os.path.join(folder, "%s.pcap" % kind)
            try:
                client.stop_capture(handle, output=path)
            except Exception as exc:
                emit(quiet, ev="note",
                     msg="запись %s не сохранилась: %s" % (kind, exc))
                continue
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
            except OSError as exc:
                emit(quiet, ev="note", msg="запись %s не прочиталась: %s"
                     % (kind, exc))
                continue
            ship_pcap(kind, raw, quiet, args.capture_limit)
            if kind == "tx" and raw:
                # Запись отправки снимается до выгрузки на карту, поэтому
                # контрольные суммы в ней могут быть не посчитаны. Кадр от
                # этого не испорчен - испорчен вывод, если проверять
                # целостность по этой стороне.
                emit(quiet, ev="note",
                     msg="в записи отправки контрольные суммы могут быть "
                         "не посчитаны - захват идёт до выгрузки на карту; "
                         "целостность кадра проверяй по записи приёма")
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def recover(api, args, quiet):
    """Убрать за прогоном, который не убрал за собой.

    Это НЕ силовой захват вслепую. Силовой захват здесь всё равно происходит -
    ключей владения, выданных демоном, у нас нет и достать их из клиента нечем, -
    но он разрешён только после того, как по следу аренды доказано, что процесс
    владельца мёртв. Живой прогон не трогается: отобрать у живого - это --force,
    и это другое решение, которое принимает человек.

    И главное, что говорится в конце: освобождены ресурсы, а измерение НЕ
    восстановлено. Прогон, который тут убирали, не состоялся.
    """
    ports = [args.tx_port]
    if args.rx_port >= 0 and args.rx_port != args.tx_port:
        ports.append(args.rx_port)
    path = lease_path(args, ports)
    try:
        with open(path) as fh:
            lease = json.load(fh)
    except (OSError, ValueError) as exc:
        msg = ("следа аренды на портах %s нет (%s) - убирать нечего. Либо за "
               "этими портами никто не падал, либо прогон шёл с другими "
               "портами или с другой машины"
               % (", ".join(str(p) for p in ports), exc))
        emit(quiet, ev="error", msg=msg)
        print(msg, file=sys.stderr)
        return 2

    alive = owner_alive(lease)
    if alive is not False:
        why = ("ещё жив" if alive else "жив он или нет - определить не удалось")
        msg = ("прогон с меткой %s (pid %s) %s - уборка отменена. Дождись его "
               "или останови сам; отобрать у живого прогона - это --force, и "
               "это другое решение"
               % (lease.get("tag", "?"), lease.get("pid"), why))
        emit(quiet, ev="error", msg=msg)
        print(msg, file=sys.stderr)
        return 4

    emit(quiet, ev="note",
         msg="след аренды от %s (метка %s, pid %s): процесс мёртв, убираю"
             % (lease.get("at", "?"), lease.get("tag", "?"), lease.get("pid")))
    client = api.STLClient(server=args.server, sync_port=args.sync_port)
    client.connect()
    cleaned = []
    try:
        client.acquire(ports=ports, force=True)
        cleaned.append("порты захвачены")
        try:
            if client.is_traffic_active(ports=ports):
                client.stop(ports=ports)
                cleaned.append("трафик остановлен")
        except Exception:
            pass
        for name in ("remove_all_captures", "clear_captures"):
            killer = getattr(client, name, None)
            if killer is not None:
                try:
                    killer()
                    cleaned.append("записи сняты")
                except Exception:
                    pass
                break
        service = lease.get("service_ports") or ports
        try:
            client.set_service_mode(ports=service, enabled=False)
            cleaned.append("сервисный режим выключен")
        except Exception as exc:
            emit(quiet, ev="note",
                 msg="сервисный режим снять не удалось: %s" % exc)
        was = lease.get("promiscuous")
        if was:
            try:
                client.set_port_attr(ports=[was[0]], promiscuous=bool(was[1]))
                cleaned.append("promiscuous возвращён")
            except Exception as exc:
                emit(quiet, ev="note",
                     msg="promiscuous вернуть не удалось: %s" % exc)
        try:
            client.release(ports=ports)
            cleaned.append("порты отданы")
        except Exception:
            pass
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
    drop_lease(path)

    said = "убрано: " + ", ".join(cleaned) if cleaned else "убирать было нечего"
    emit(quiet, ev="note", msg=said)
    print(said)
    last = ("ИЗМЕРЕНИЕ НЕ ВОССТАНОВЛЕНО - освобождены только ресурсы. Прогон, "
            "за которым убирали, не состоялся, и его цифры брать нельзя")
    emit(quiet, ev="note", msg=last)
    print(last)
    return 0


def run(api, args, streams, pg_ids, uncounted, quiet):
    """Drive the server through one run. Returns the result dict."""
    counted_all = bool(pg_ids) and not uncounted
    ports = [args.tx_port]
    if args.rx_port >= 0 and args.rx_port != args.tx_port:
        ports.append(args.rx_port)

    client = api.STLClient(server=args.server, sync_port=args.sync_port)
    client.connect()
    # Оба до try: в finally они читаются, а дотуда можно долететь и с отказа на
    # самом захвате портов, когда ни то, ни другое ещё не заводилось.
    # Именно те порты, которые переключили МЫ, и только они возвращаются обратно.
    # Флаг «да/нет» этого не различал, а возвращать чужое переключение так же
    # неправильно, как не вернуть своё.
    service_ports = []
    promisc = None
    handles = None
    idle = None
    base = ZERO_BASE()
    link_down = False
    errors_before = {}
    errors = {}
    error_kinds = {}
    lease = None
    # Захватили ли мы порты на самом деле. Если нет - в finally нельзя трогать
    # НИЧЕГО: и release, и disconnect с умолчаниями (stop_traffic=True,
    # release_ports=True) бьют по портам, которые держит чужой прогон. Отказ
    # «порт занят» обязан быть безвредным для того, кто его занял.
    owned = False
    try:
        take_ports(client, args, ports, quiet)
        owned = True
        lease = write_lease(args, ports, pg_ids, quiet)
        client.add_streams(streams, ports=[args.tx_port])
        promisc = take_promiscuous(client, args, quiet)
        handles = start_capture(client, args, quiet, service_ports)
        update_lease(lease, service_ports=sorted(set(service_ports)),
                     promiscuous=list(promisc) if promisc else None)
        # Обнуление ВТОРОЙ раз, и только теперь оно что-то значит: в take_ports
        # наших групп на сервере ещё не существовало, так что их счётчиков то
        # обнуление не касалось. А номер группы могли занимать до нас.
        try:
            client.clear_stats()
        except Exception as exc:
            emit(quiet, ev="note",
                 msg="счётчики не обнулились перед замером (%s) - цифры пойдут "
                     "разницей к тому, что было" % exc)
        base = absolutes(client, args, pg_ids)
        if base["group_rx"] or base["group_tx"] or base["rx_port"]:
            # Обнулили - а там не ноль. Значит либо релиз не чистит группы,
            # зарегистрированные после очистки, либо в сегмент уже что-то идёт.
            # В обоих случаях абсолютная цифра не годится, и вычитание базы -
            # единственное, что делает замер замером.
            emit(quiet, ev="note",
                 msg="счётчики после обнуления не нулевые (группы %d/%d, порт "
                     "приёма %d) - дальше всё считается разницей к этому"
                     % (base["group_tx"], base["group_rx"], base["rx_port"]))
        emit(quiet, ev="base", group_tx=base["group_tx"],
             group_rx=base["group_rx"], rx_port=base["rx_port"])
        errors_before = read_xstats(client, ports)
        # Холостой замер стоит ЗДЕСЬ, а не раньше, и это не косметика. Групп на
        # сервере не существует, пока потоки не добавлены, а на части карт
        # групповой счётчик приёма вообще не растёт вне сервисного режима -
        # именно это и наблюдалось на стенде. Замер до этих двух шагов показывал
        # бы чистый ноль на грязном сегменте, то есть врал бы ровно там, где его
        # и завели.
        idle = idle_check(client, args, pg_ids, base, quiet)

        started = time.time()
        # force здесь - НЕ про отъём чужого: порты уже наши, а отобрать их
        # мог только acquire выше, и он вежливый. Продавливать приходится две
        # свои же вещи, и обе законные:
        #
        #   - собственный сервисный режим: запись кадров без него невозможна,
        #     а стартовать на порту в этом режиме TRex без force отказывается.
        #     Не форсировать тут значит сломать запись целиком;
        #   - явное --force оператора.
        #
        # Без записи и без --force старт остаётся неформированным нарочно:
        # тогда TRex откажется стартовать на порту с упавшим линком, и это
        # правильный ответ - иначе весь прогон вернётся как «потери 100%».
        client.start(ports=[args.tx_port], duration=args.duration,
                     mult=args.mult, force=bool(args.force or handles))
        # A hard stop past the asked-for duration: a profile made only of
        # bursts finishes early, and a server that never reports the traffic as
        # stopped must not hold the run open for ever.
        deadline = started + max(args.duration, 0.0) + 30
        last = started
        while time.time() < deadline:
            time.sleep(0.25)
            now = time.time()
            if now - last >= 1.0:
                last = now
                snap = sample(client, args, pg_ids, counted_all, base)
                # Счётчик порта приёма едет в каждом тике рядом с групповой
                # цифрой. Раньше sample() его читал и выбрасывал, если группа
                # была ненулевой, - и по архиву прогона было уже не понять,
                # сошлись они или разошлись.
                if link_is_down(client, ports) is True and not link_down:
                    link_down = True
                    emit(quiet, ev="note",
                         msg="линк на наших портах упал по ходу прогона - "
                             "дальше тишина в кабеле выглядит как потери на "
                             "устройстве, но описывает обрыв")
                emit(quiet, ev="tick", t=round(now - started, 2),
                     tx=snap["tx"], rx=snap["rx"],
                     rx_port=snap["rx_port"], rx_groups=snap["rx_groups"],
                     link_down=link_down, pps=round(snap["tx_pps"], 1))
            if not client.is_traffic_active(ports=[args.tx_port]):
                break

        if client.is_traffic_active(ports=[args.tx_port]):
            client.stop(ports=[args.tx_port])
        else:
            client.wait_on_traffic(ports=[args.tx_port], timeout=30)
        seconds = time.time() - started
        # Frames still in flight when the last one left have to land before the
        # receiving counter is read, or the tail of the run reads as loss.
        # Полсекунды тут было взято на глаз; счётчики на разных сборках
        # устаканиваются дольше, поэтому это параметр, а не константа.
        time.sleep(max(0.0, args.settle))
        final = sample(client, args, pg_ids, counted_all, base)
        errors, error_kinds = grown_errors(errors_before,
                                           read_xstats(client, ports))
        for name in sorted(errors):
            kind = error_kinds[name]
            if kind == "generator":
                said = ("счётчик генератора - кадры терялись на нашей стороне, "
                        "не дойдя до устройства; потери этого прогона считать "
                        "нельзя")
            elif kind == "link":
                said = "счётчик линка - смотреть кабель, оптику, согласование"
            else:
                said = ("незнакомый счётчик - имя приходит от драйвера, "
                        "разбирать человеку")
            emit(quiet, ev="note",
                 msg="ошибки порта: %s вырос на %d - %s"
                     % (name, errors[name], said))
        if errors:
            emit(quiet, ev="xstats", grew=errors, kinds=error_kinds)
        stop_capture(client, args, handles, quiet)
        handles = None            # забрали, дальше снимать нечего
    finally:
        # Обратно в быстрый тракт - ЧТО БЫ НИ СЛУЧИЛОСЬ. Раньше это снималось
        # в stop_capture, до которого при отказе посреди прогона дело не
        # доходило: порты оставались в сервисном режиме навсегда, а следующий
        # прогон без записи отказывался стартовать вовсе. На общей машине это
        # отравляет стенд всем, и связать это с записью, снятой часами раньше,
        # не сможет никто.
        # Сначала снять записи, и только потом режим: пока запись жива, TRex
        # отказывается выключать сервисный режим - "unable to disable service
        # mode - an active capture exists". Прогон, умерший между стартом
        # записи и её снятием, оставлял на машине и то, и другое.
        if handles:
            for handle in handles.values():
                try:
                    client.stop_capture(handle)
                except Exception:
                    pass
        if service_ports:
            try:
                client.set_service_mode(ports=sorted(set(service_ports)),
                                        enabled=False)
            except Exception as exc:
                # Молчащий отказ возврата - это отравленный стенд без следа:
                # машина остаётся в режиме, в котором не пускает трафик вообще,
                # а следующий человек видит отказ, к его работе отношения не
                # имеющий. Сказать вслух - единственное, что здесь можно.
                emit(quiet, ev="note",
                     msg="СЕРВИСНЫЙ РЕЖИМ ВЕРНУТЬ НЕ УДАЛОСЬ (%s) на портах "
                         "%s - следующий прогон на этой машине может не "
                         "стартовать вовсе; снимать руками"
                         % (exc, sorted(set(service_ports))))
        if promisc is not None:
            port, was = promisc
            try:
                client.set_port_attr(ports=[port], promiscuous=was)
            except Exception as exc:
                emit(quiet, ev="note",
                     msg="promiscuous на порту %d вернуть не удалось (%s) - "
                         "порт остался в состоянии, которого не просили"
                         % (port, exc))
        # Handed back explicitly rather than left to the disconnect: a release
        # that happens only as a side effect of closing the socket does not
        # happen when the socket is already gone, and the next person finds
        # the ports owned by a run that ended.
        if owned:
            try:
                client.release(ports=ports)
            except Exception:
                pass
        try:
            if owned:
                client.disconnect()
            else:
                # Ничего не наше - и уходим, ничего не тронув. Умолчания
                # disconnect() остановили бы чужой трафик и отдали бы чужие
                # порты, то есть отказ «порт занят» испортил бы ровно тот
                # прогон, которого он не хотел касаться.
                client.disconnect(stop_traffic=False, release_ports=False)
        except TypeError:
            # Релиз, не знающий этих параметров: лучше не отключаться вовсе,
            # чем отключиться с умолчаниями. Сокет закроется с процессом.
            pass
        except Exception:
            # Losing the connection on the way out must not replace whatever
            # actually went wrong inside the run.
            pass
        drop_lease(lease)

    source = final["source"]
    if idle and idle["rx_groups"] > 0 and source in (
            "flow_stats", "mixed", "flow_stats_foreign", "flow_stats_noport"):
        # Ровная цифра из отравленной группы опаснее кривой: она выглядит как
        # измерение. Переименовать источник - единственный способ, которым это
        # доезжает до отчёта, до JSON и до истории, а не только до текста ноты.
        source = "flow_stats_tainted"
    note = SOURCE_NOTES.get(source, "")
    if source == "flow_stats" and final["rx"] > final["tx"]:
        note = ("аппаратный счёт дал больше, чем отправлено (%d против %d) - "
                "в группу попало не только наше; цифра приёма по этому прогону "
                "ничего не измеряет" % (final["rx"], final["tx"]))
    if uncounted and source == "mixed":
        # Worth naming only when the rest of the run *was* counted in hardware.
        # When nothing was, "these streams had no counter" lists every stream
        # there is and says less than the sentence already above it.
        note = "без аппаратного счёта: " + ", ".join(uncounted) + " · " + note
    return {
        "tx": final["tx"],
        "rx": final["rx"],
        "tx_bytes": final["tx_bytes"],
        "seconds": round(seconds, 3),
        "achieved_pps": round(final["tx"] / seconds, 1) if seconds else 0.0,
        "rx_source": source,
        # Структурно, а не по тексту ноты: по архиву прогона должно быть видно,
        # шёл ли он в сервисном режиме (потолок скорости ниже) и что показывал
        # приём, пока мы молчали. Без этих полей различие двух прогонов
        # приходилось доставать диффом сгенерированных скриптов.
        "service_mode": bool(service_ports),
        "idle_rx": (idle or {}).get("rx_port", 0),
        "idle_rx_groups": (idle or {}).get("rx_groups", 0),
        # Сколько кадров нашей группы пришло мимо нашего порта приёма.
        "rx_foreign": final.get("rx_foreign", 0),
        # Чем гейт достоверности на принимающей стороне судит о годности замера.
        "ordered": ORDERED,
        "link_down": bool(link_down),
        "port_errors": errors,
        "generator_errors": sorted(n for n in errors
                                   if error_kinds.get(n) == "generator"),
        # Только НЕОПРОВЕРГНУТЫЙ аппаратный счёт годится как есть. Принято
        # больше, чем послано, - это и есть опровержение: столько наших кадров
        # вернуться не могло, значит в счёт попало чужое. Найдено на стенде
        # 2026-09-30: группа насчитала 46 млн при 20 тысячах отправленных, и
        # прогон уходил с пометкой «надёжно».
        "reliable": source == "flow_stats" and final["rx"] <= final["tx"],
        "truncated": [],
        "note": note,
    }


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Профиль трафика для TRex, собранный TRaphy")
    ap.add_argument("--trex-dir", default="/opt/trex",
                    help="распакованный релиз TRex на этой машине")
    ap.add_argument("--server", default="127.0.0.1",
                    help="адрес демона TRex - обычно он тут же")
    ap.add_argument("--sync-port", type=int, default=4501,
                    help="порт управления демона")
    ap.add_argument("--tx-port", type=int, default=0,
                    help="порт TRex, с которого шлём (индекс, не имя NIC)")
    ap.add_argument("--rx-port", type=int, default=-1,
                    help="порт приёма; без него потери не измеряются")
    ap.add_argument("--duration", type=float, default=10.0, help="секунд")
    ap.add_argument("--mult", default="1",
                    help="множитель скорости: 1, 50%%, 100kpps, 1gbps")
    ap.add_argument("--count", type=int, default=0,
                    help="не поддерживается: TRex шлёт по времени")
    ap.add_argument("--capture", action="store_true",
                    help="записывать отправленные и принятые кадры "
                         "и вернуть их вместе с результатом")
    ap.add_argument("--capture-limit", type=int, default=1000,
                    help="сколько кадров сохранять на сторону")
    ap.add_argument("--pcap", default="",
                    help="куда записать образцы кадров (по одному на поток) - "
                         "путь на ЭТОЙ машине, для запуска скрипта руками")
    ap.add_argument("--ship-frames", action="store_true",
                    help="вернуть образцы кадров вызывающему внутри потока "
                         "событий, ничего здесь не оставляя")
    ap.add_argument("--lease-dir", default=LEASE_DIR,
                    help="где держать след аренды портов на этой машине")
    ap.add_argument("--recover-only", action="store_true",
                    help="не слать ничего: убрать за прогоном, который не убрал "
                         "за собой, если по следу аренды его процесс мёртв")
    ap.add_argument("--no-promiscuous", dest="promiscuous",
                    action="store_false",
                    help="не включать promiscuous на порту приёма; с ним карта "
                         "иначе отбрасывает кадры с чужим MAC и приём читается "
                         "нулём")
    ap.add_argument("--settle", type=float, default=2.0,
                    help="сколько ждать дослёта кадров перед снятием "
                         "счётчиков приёма")
    ap.add_argument("--idle-check", type=float, default=1.0,
                    help="сколько секунд слушать приём до старта, чтобы "
                         "поймать чужой трафик в сегменте; 0 - не слушать")
    ap.add_argument("--force", action="store_true",
                    help="отобрать порты, даже если их держит чужой прогон")
    ap.add_argument("--dry-run", action="store_true",
                    help="собрать профиль и показать, демону ничего не отдавая")
    ap.add_argument("--quiet", action="store_true",
                    help="без машинных @traphy строк")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    quiet = args.quiet

    if args.count:
        # Refused rather than approximated. "Duration that works out to about
        # N frames" is not N frames, and a tool that quietly substitutes one
        # for the other is the reason nobody trusts the other numbers either.
        msg = ("TRex шлёт по времени, а не по счёту кадров: чтобы послать "
               "ровно столько - задай потоку режим очереди на нужное число")
        emit(quiet, ev="error", msg=msg)
        print(msg, file=sys.stderr)
        return 2

    try:
        api = load_api(args.trex_dir)
    except ApiMissing as exc:
        emit(quiet, ev="error", msg=exc.explain())
        print(exc.explain(), file=sys.stderr)
        return 3

    if args.recover_only:
        # Профиль тут ни при чём: убирают за чужим прогоном, а не шлют свой.
        try:
            return recover(api, args, quiet)
        except Exception as exc:
            msg = "уборка не удалась: %s" % exc
            emit(quiet, ev="error", msg=msg)
            print(msg, file=sys.stderr)
            traceback.print_exc()
            return 1

    L = layers(api)
    want_flow_stats = args.rx_port >= 0
    streams, frames, pg_ids, uncounted = build_streams(api, L, want_flow_stats)

    if not streams:
        emit(quiet, ev="error", msg="в профиле нет включённых потоков")
        print("нет потоков - слать нечего", file=sys.stderr)
        return 2

    for stream, frame in zip(streams, frames):
        name = getattr(stream, "name", "?")
        emit(quiet, ev="stream", name=name,
             frames=VM_FRAMES.get(name, 1), bytes=len(frame))

    for line in WARNINGS:
        emit(quiet, ev="note", msg=line)
        print(line, file=sys.stderr)

    emit(quiet, ev="ready", frames=sum(VM_FRAMES.values()) or len(streams),
         iface="порт %d" % args.tx_port,
         rx_iface=("порт %d" % args.rx_port) if want_flow_stats else "",
         pps=0.0, duration=args.duration, count=0, truncated=[])

    if args.pcap:
        write_pcap(args.pcap, frames)
        emit(quiet, ev="note",
             msg="в %s записаны образцы кадров - по одному на поток, такими, "
                 "какими их собрали до field engine" % args.pcap)

    if args.ship_frames:
        # Домой внутри потока событий, как и записанные кадры, и по той же
        # причине: скрипт исполняется на машине-генераторе, а каталог прогона
        # живёт на машине, которая его запустила. Путь оттуда сюда не годится -
        # его тут просто нет, и запись по нему роняет прогон до первого кадра.
        folder = tempfile.mkdtemp(prefix="traphy-frames-")
        try:
            path = os.path.join(folder, "streams.pcap")
            write_pcap(path, frames)
            with open(path, "rb") as fh:
                ship_pcap("streams", fh.read(), quiet)
        except Exception as exc:
            emit(quiet, ev="note",
                 msg="образцы кадров не отправились: %s" % exc)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    if args.dry_run:
        for stream, frame in zip(streams, frames):
            name = getattr(stream, "name", "?")
            print("%s: кадр %d B, обход %d кадров"
                  % (name, len(frame), VM_FRAMES.get(name, 1)))
            print("   " + frame.summary())
        emit(quiet, ev="done", tx=0, rx=0, seconds=0.0, tx_bytes=0,
             achieved_pps=0.0, rx_source="none", reliable=False,
             note="сухой прогон - демону ничего не отдавали")
        return 0

    try:
        result = run(api, args, streams, pg_ids, uncounted, quiet)
    except Busy as exc:
        # Its own exit code: "somebody else is on the generator" is a thing to
        # wait out, not a fault to go and debug.
        emit(quiet, ev="error", msg=str(exc))
        print(str(exc), file=sys.stderr)
        return 4
    except Dirty as exc:
        # И свой код: порт достался нам, но в состоянии, в котором мерить
        # нельзя. Это не занятый порт (4) и не поломка (1) - это остаток,
        # который надо либо разобрать руками, либо убрать явным --force.
        emit(quiet, ev="error", msg=str(exc))
        print(str(exc), file=sys.stderr)
        return 5
    except Exception as exc:
        # The release defines its own exception types and we only have them
        # after the import above, so there is nothing narrower to catch here
        # that would not also be a guess. The message is what matters.
        msg = "TRex на %s:%d - %s" % (args.server, args.sync_port, exc)
        emit(quiet, ev="error", msg=msg)
        print(msg, file=sys.stderr)
        # И стек следом. Сообщение говорит ЧТО, стек говорит ГДЕ, и без второго
        # отказ вроде "Failed to send message to server" не сужается ничем:
        # он одинаково выглядит и на подключении, и на запуске. Архив прогона
        # затем и ведётся, чтобы через неделю не переигрывать отказ заново.
        traceback.print_exc()
        return 1

    emit(quiet, ev="done", **result)
    if result["reliable"]:
        loss = max(0, result["tx"] - result["rx"])
        share = (loss / result["tx"] * 100.0) if result["tx"] else 0.0
        tail = "принято %d, потеряно %d (%.2f%%)" % (result["rx"], loss, share)
    else:
        tail = result["note"] or "приём не измерялся"
    print("отправлено %d кадров за %.1f c (%.0f pps), %s"
          % (result["tx"], result["seconds"], result["achieved_pps"], tail))
    return 0


if __name__ == "__main__":
    sys.exit(main())'''
