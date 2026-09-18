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

    parts = [_header(profile, skipped, tag, enabled), _HELPERS,
             _builder(enabled), _ENGINE]
    return "\n\n".join(parts) + "\n"


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
import importlib
import json
import os
import sys
import time

STL_PATHS = ({paths},)

# Сколько кадров обойдёт field engine по каждому потоку - посчитано при
# генерации, здесь просто чтобы отчёт назвал число, а не разворачивал его в
# память. В этом и разница с Scapy: там диапазон превращается в кадры, тут - в
# четыре байта настройки.
VM_FRAMES = {walk!r}

# То, что этот профиль теряет именно на TRex. Список собран при генерации и
# лежит прямо здесь, чтобы сохранённый скрипт говорил это сам, без TRaphy.
WARNINGS = {said!r}'''


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


def total(value):
    """Pull the aggregate out of a flow-stats entry, which is a per-port dict."""
    if isinstance(value, dict):
        return int(value.get("total", 0) or 0)
    return int(value or 0)


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
def _builder(streams: list[Stream]) -> str:
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
        "    pg_next = 0",
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
    "none": "приём не измерялся - без --rx-port считать нечем",
}


def sample(client, args, pg_ids, counted_all):
    """One reading of the counters, and where each number came from."""
    stats = client.get_stats()
    port = stats.get(args.tx_port) or {}
    out = {
        "tx": int(port.get("opackets", 0) or 0),
        "tx_bytes": int(port.get("obytes", 0) or 0),
        "tx_pps": float(port.get("tx_pps", 0.0) or 0.0),
        "rx": 0,
        "source": "none",
    }
    groups = stats.get("flow_stats") or {}
    seen = [groups[pg] for pg in pg_ids if pg in groups]
    if seen:
        out["rx"] = sum(total(g.get("rx_pkts")) for g in seen)
        if counted_all:
            # Per-group counters in hardware on both sides. This is the one
            # reading here that goes into a report without a caveat.
            out["tx"] = sum(total(g.get("tx_pkts")) for g in seen) or out["tx"]
            out["source"] = "flow_stats"
        else:
            out["source"] = "mixed"
    elif args.rx_port >= 0:
        rx_port = stats.get(args.rx_port) or {}
        out["rx"] = int(rx_port.get("ipackets", 0) or 0)
        out["source"] = "port_counter"
    return out


def run(api, args, streams, pg_ids, uncounted, quiet):
    """Drive the server through one run. Returns the result dict."""
    counted_all = bool(pg_ids) and not uncounted
    ports = [args.tx_port]
    if args.rx_port >= 0 and args.rx_port != args.tx_port:
        ports.append(args.rx_port)

    client = api.STLClient(server=args.server, sync_port=args.sync_port)
    client.connect()
    try:
        client.reset(ports=ports)
        client.add_streams(streams, ports=[args.tx_port])
        client.clear_stats()

        started = time.time()
        client.start(ports=[args.tx_port], duration=args.duration,
                     mult=args.mult, force=True)
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
                snap = sample(client, args, pg_ids, counted_all)
                emit(quiet, ev="tick", t=round(now - started, 2),
                     tx=snap["tx"], rx=snap["rx"],
                     pps=round(snap["tx_pps"], 1))
            if not client.is_traffic_active(ports=[args.tx_port]):
                break

        if client.is_traffic_active(ports=[args.tx_port]):
            client.stop(ports=[args.tx_port])
        else:
            client.wait_on_traffic(ports=[args.tx_port], timeout=30)
        seconds = time.time() - started
        # Frames still in flight when the last one left have to land before the
        # receiving counter is read, or the tail of the run reads as loss.
        time.sleep(0.5)
        final = sample(client, args, pg_ids, counted_all)
    finally:
        try:
            client.disconnect()
        except Exception:
            # Losing the connection on the way out must not replace whatever
            # actually went wrong inside the run.
            pass

    source = final["source"]
    note = SOURCE_NOTES.get(source, "")
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
        "reliable": source == "flow_stats",
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
    ap.add_argument("--pcap", default="",
                    help="куда записать образцы кадров (по одному на поток)")
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
    except Exception as exc:
        # The release defines its own exception types and we only have them
        # after the import above, so there is nothing narrower to catch here
        # that would not also be a guess. The message is what matters.
        msg = "TRex на %s:%d - %s" % (args.server, args.sync_port, exc)
        emit(quiet, ev="error", msg=msg)
        print(msg, file=sys.stderr)
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
