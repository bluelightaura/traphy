"""Turn a :class:`~traphy.models.Profile` into a stand-alone Scapy script.

This is the whole point of the tool. The operator composes traffic in the menu;
what comes out is an ordinary Python file that runs anywhere Scapy and root are
available, with no TRaphy installed on the far side. The runner ships exactly
this file over SSH - so what you preview on the "Скрипт" screen is byte-for-byte
what executes on the wire, and a saved script keeps working after the menu that
made it is gone.

Three things about the generated script are worth knowing:

* **inc / dec ranges are expanded** into concrete frames at build time, capped
  at :data:`EXPAND_CAP`, and the script says so when it truncates. **random
  ranges** are drawn once into a pool of :data:`RANDOM_POOL` frames rather than
  left volatile, so the byte counts it reports are exact rather than estimated.
* **Rate is paced, not guaranteed.** Scapy on a normal kernel path is not a
  line-rate engine. The script sends in short slices and reports the pps it
  actually achieved, which is the honest number; if the achieved rate is well
  under the requested one, that is the tool telling you it ran out of road.
* **Loss is only measured when there is a receive interface.** Otherwise the
  script counts what it sent and reports the receive side as unmeasured, rather
  than reporting zero and letting it read as zero loss.

Progress is emitted as ``@traphy {json}`` lines on stdout, which the runner
parses. They are suppressible with ``--quiet`` so a saved script used by hand
prints only human text.
"""

from __future__ import annotations

from traphy.models import FieldTarget, L4Proto, Profile, Stream, TxMode, VMOp

# How many frames a single inc/dec range may expand to. A /16 sweep is 65k
# frames and several hundred megabytes once serialised; the cap turns that into
# a truncation the script reports rather than a machine that starts swapping.
EXPAND_CAP = 1024

# How many frames a random range is drawn into. Enough spread that a device
# cannot cache its way out, small enough to build instantly.
RANDOM_POOL = 256

# Marker carried in the payload so a sniffer on the receive side counts our
# frames and not whatever else the network is doing. The runner replaces the
# suffix per run, so a second run never counts the first one's stragglers.
DEFAULT_TAG = "TRAPHY0"


def generate(profile: Profile, tag: str = DEFAULT_TAG) -> str:
    """The complete script for ``profile`` as one string."""
    enabled = profile.enabled_streams
    skipped = [s.name for s in profile.streams if not s.enabled]

    parts = [_header(profile, skipped, tag), _HELPERS]
    for i, s in enumerate(enabled):
        parts.append(_builder(s, i))
    parts.append(_stream_table(enabled))
    parts.append(_ENGINE)
    return "\n\n".join(parts) + "\n"


def frame_count(profile: Profile) -> int:
    """How many distinct frames the generated script will build.

    Each walking field multiplies the set, capped the same way the script caps
    it, so the number the builder screen shows is the number that will actually
    exist in memory on the target rather than an optimistic product.
    """
    from traphy.models import range_size

    total = 0
    for s in profile.enabled_streams:
        frames = 1
        for vf in s.vm_fields:
            span = RANDOM_POOL if vf.op is VMOp.RANDOM else min(range_size(vf) or 1,
                                                                EXPAND_CAP)
            frames *= max(1, span)
        total += frames
    return total


def script_name(profile: Profile) -> str:
    """A filename for a saved script, derived from the profile name."""
    base = "".join(c if c.isalnum() or c in "-_" else "_" for c in profile.name)
    return f"{base or 'profile'}.py"


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
def _header(profile: Profile, skipped: list[str], tag: str) -> str:
    desc = profile.description or "-"
    note = ""
    if skipped:
        note = f"# Выключенные потоки не вошли: {', '.join(skipped)}\n"
    return f'''\
#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Профиль: {profile.name}
# {desc}
{note}#
# Сгенерировано TRaphy. Файл самодостаточный: нужен Python 3, Scapy и root.
#
#   sudo ./{script_name(profile)} --iface eth0 --duration 10
#
# Scapy не line-rate: --pps это цель, а не гарантия. Скрипт печатает ту
# скорость, которую реально выдал. Потери считаются только если задан
# --rx-iface; без него приём не измеряется и в отчёте так и написано.
# ---------------------------------------------------------------------------
import argparse
import ipaddress
import json
import random
import sys
import time

from scapy.all import AsyncSniffer, Dot1Q, Ether, IP, TCP, UDP, conf, wrpcap

TAG = {tag!r}.encode()
EXPAND_CAP = {EXPAND_CAP}
RANDOM_POOL = {RANDOM_POOL}

# Ширина отрезка, которым скрипт нарезает отправку. Спать после каждого
# пакета на высоком pps нельзя - планировщик не даст такой точности; поэтому
# шлём пачку на отрезок и досыпаем остаток.
SLICE = 0.01

_TRUNCATED = []'''


# --------------------------------------------------------------------------- #
# Fixed helpers, emitted verbatim
# --------------------------------------------------------------------------- #
_HELPERS = '''\
def emit(quiet, **event):
    """One machine-readable progress line, or nothing when muted."""
    if not quiet:
        sys.stdout.write("@traphy " + json.dumps(event) + "\\n")
        sys.stdout.flush()


def ip_range(name, lo, hi, step):
    """Concrete addresses from lo..hi, capped; records what it cut."""
    a, b = int(ipaddress.IPv4Address(lo)), int(ipaddress.IPv4Address(hi))
    out, value = [], a
    while value <= b and len(out) < EXPAND_CAP:
        out.append(str(ipaddress.IPv4Address(value)))
        value += step
    total = (b - a) // step + 1 if b >= a else 0
    if total > len(out):
        _TRUNCATED.append("%s: %d из %d значений" % (name, len(out), total))
    return out or [lo]


def num_range(name, lo, hi, step, down=False):
    """Concrete integers, capped, in the direction asked for."""
    lo, hi = int(lo), int(hi)
    seq = range(hi, lo - 1, -step) if down else range(lo, hi + 1, step)
    out = list(seq)[:EXPAND_CAP]
    if len(seq) > len(out):
        _TRUNCATED.append("%s: %d из %d значений" % (name, len(out), len(seq)))
    return out or [lo]


def rand_ips(lo, hi, n=RANDOM_POOL):
    """A fixed pool of random addresses, drawn once so byte counts stay exact."""
    a, b = int(ipaddress.IPv4Address(lo)), int(ipaddress.IPv4Address(hi))
    if b < a:
        a, b = b, a
    return [str(ipaddress.IPv4Address(random.randint(a, b))) for _ in range(n)]


def rand_ports(lo, hi, n=RANDOM_POOL):
    lo, hi = int(lo), int(hi)
    if hi < lo:
        lo, hi = hi, lo
    return [random.randint(lo, hi) for _ in range(n)]


def pad_to(pkt, size):
    """Grow a frame to `size` bytes, marker first so the sniffer can match it.

    `size` counts the L2 frame without the 4-byte FCS the NIC appends. A frame
    already at or over the target is returned untouched rather than truncated:
    silently cutting a header would produce garbage that still looks like a
    packet.
    """
    need = size - len(bytes(pkt))
    if need <= 0:
        return pkt
    filler = (TAG + b"x" * need)[:need]
    return pkt / filler'''


# --------------------------------------------------------------------------- #
# Per-stream builders
# --------------------------------------------------------------------------- #
def _builder(s: Stream, index: int) -> str:
    """Emit ``build_<n>()`` returning the concrete frames for one stream.

    Ranges become nested loops around the frame expression; a stream with no
    ranges builds exactly one frame and the loops collapse away.
    """
    p = s.packet
    values = {
        FieldTarget.IP_SRC: repr(p.ip_src),
        FieldTarget.IP_DST: repr(p.ip_dst),
        FieldTarget.SPORT: str(p.sport),
        FieldTarget.DPORT: str(p.dport),
    }
    loops: list[str] = []
    pools: list[str] = []

    for vf in s.vm_fields:
        var = f"v_{vf.target.value}"
        label = f"{s.name}/{vf.target.value}"
        if vf.op is VMOp.RANDOM:
            fn = "rand_ips" if vf.target.is_ip else "rand_ports"
            pools.append(f"    pool_{vf.target.value} = "
                         f"{fn}({vf.min_value!r}, {vf.max_value!r})")
            loops.append(f"for {var} in pool_{vf.target.value}:")
        elif vf.target.is_ip:
            loops.append(f"for {var} in ip_range({label!r}, {vf.min_value!r}, "
                         f"{vf.max_value!r}, {vf.step}):")
        else:
            down = vf.op is VMOp.DEC
            loops.append(f"for {var} in num_range({label!r}, {vf.min_value}, "
                         f"{vf.max_value}, {vf.step}, down={down}):")
        values[vf.target] = var

    layers = [f"Ether(src={p.eth_src!r}, dst={p.eth_dst!r})"]
    if p.has_vlan:
        layers.append(f"Dot1Q(vlan={p.vlan}, prio={p.vlan_pcp})")
    if p.has_ip:
        # An L3-only frame carries raw payload under no transport at all. Left
        # to itself Scapy stamps proto 0, which is not a thing on the wire and
        # makes a capture read as malformed; 61 is IANA's "any host internal
        # protocol", which is exactly what this is.
        proto = "" if p.has_l4 else ", proto=61"
        layers.append(f"IP(src={values[FieldTarget.IP_SRC]}, "
                      f"dst={values[FieldTarget.IP_DST]}, ttl={p.ttl}{proto})")
    if p.has_l4:
        proto = "TCP" if p.l4_proto is L4Proto.TCP else "UDP"
        layers.append(f"{proto}(sport={values[FieldTarget.SPORT]}, "
                      f"dport={values[FieldTarget.DPORT]})")
    frame = " / ".join(layers)

    body = [f"def build_{index}():", f'    """Кадры потока «{s.name}»: {_shape(s)}."""',
            "    frames = []"]
    body.extend(pools)
    indent = "    "
    for loop in loops:
        body.append(indent + loop)
        indent += "    "
    body.append(f"{indent}frames.append(pad_to({frame}, {p.frame_size}))")
    body.append("    return frames")
    return "\n".join(body)


def _shape(s: Stream) -> str:
    """A short "what this stream is" for the builder's docstring."""
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


def _stream_table(streams: list[Stream]) -> str:
    """The table the engine walks: one row per stream, rate and mode alongside
    the builder that makes its frames."""
    rows = []
    for i, s in enumerate(streams):
        rows.append(
            "    {"
            f"'name': {s.name!r}, 'build': build_{i}, "
            f"'pps': {s.pps():.6g}, 'mode': {s.tx_mode.value!r}, "
            f"'burst': {s.pkts_per_burst}, 'bursts': {s.number_of_bursts}, "
            f"'ibg': {s.ibg_usec:.6g}"
            "},"
        )
    body = "\n".join(rows) or "    # профиль пуст"
    return "STREAMS = [\n" + body + "\n]"


# --------------------------------------------------------------------------- #
# The engine, emitted verbatim
# --------------------------------------------------------------------------- #
_ENGINE = '''\
class Pacer:
    """Decides how many frames a stream owes on each time slice.

    Continuous streams owe `pps * SLICE` frames, carrying the fraction over so
    a rate that is not a whole number per slice still averages out. Burst modes
    owe a whole burst at once and then nothing until the gap has passed, which
    is what makes a burst a burst rather than a briefly higher rate.
    """

    def __init__(self, spec, count):
        self.name = spec["name"]
        self.pps = max(0.0, float(spec["pps"]))
        self.mode = spec["mode"]
        self.burst = max(1, int(spec["burst"]))
        self.bursts_left = max(1, int(spec["bursts"]))
        self.ibg = max(0.0, float(spec["ibg"])) / 1e6
        self.count = count
        self.owed = 0.0
        self.sent = 0
        self.next_burst_at = 0.0
        self.done = False

    def due(self, now):
        """Frames this stream should send right now."""
        if self.done:
            return 0
        if self.mode == "continuous":
            self.owed += self.pps * SLICE
        else:
            if now < self.next_burst_at:
                return 0
            self.owed += self.burst
            self.bursts_left -= 1
            if self.mode == "single_burst" or self.bursts_left <= 0:
                self.next_burst_at = float("inf")
            else:
                # The gap is measured from the moment the burst is handed over,
                # which is close enough: a burst drains in well under the gap.
                self.next_burst_at = now + self.ibg + self.burst / max(self.pps, 1.0)
        take = int(self.owed)
        self.owed -= take
        if self.count:
            take = min(take, max(0, self.count - self.sent))
            if self.sent + take >= self.count:
                self.done = True
        return take

    def finished(self):
        """True when this stream has nothing left to do, ever."""
        if self.mode == "continuous":
            return self.count and self.sent >= self.count
        return self.next_burst_at == float("inf") and self.owed < 1


def build_all(quiet):
    """Every stream's frames, pre-serialised to bytes for the send loop."""
    built = []
    for spec in STREAMS:
        frames = spec["build"]()
        raws = [bytes(f) for f in frames]
        built.append((spec, frames, raws))
        emit(quiet, ev="stream", name=spec["name"], frames=len(raws),
             bytes=sum(len(r) for r in raws), pps=spec["pps"], mode=spec["mode"])
    return built


def run(args, built, quiet):
    """Send until the duration or the count runs out. Returns a result dict."""
    total_pps = sum(s["pps"] for s, _, _ in built) or 1.0
    scale = (args.pps / total_pps) if args.pps else 1.0

    pacers = []
    for spec, _frames, raws in built:
        scaled = dict(spec, pps=spec["pps"] * scale)
        share = int(args.count * spec["pps"] / total_pps) if args.count else 0
        pacers.append((Pacer(scaled, share), raws))

    sniffer = None
    if args.rx_iface:
        sniffer = AsyncSniffer(iface=args.rx_iface, store=bool(args.rx_pcap),
                               lfilter=lambda p: TAG in bytes(p))
        sniffer.start()
        # Give the sniffer a moment to attach; frames sent into a socket that
        # is not listening yet would read as loss that never happened.
        time.sleep(0.3)

    sock = conf.L2socket(iface=args.iface)
    started = time.perf_counter()
    deadline = started + args.duration if not args.count else float("inf")
    tx = tx_bytes = 0
    cursors = [0] * len(pacers)
    last_tick = started

    try:
        while True:
            now = time.perf_counter()
            if now >= deadline or all(p.finished() for p, _ in pacers):
                break
            slice_start = now
            for index, (pacer, raws) in enumerate(pacers):
                for _ in range(pacer.due(now)):
                    raw = raws[cursors[index] % len(raws)]
                    sock.send(raw)
                    cursors[index] += 1
                    pacer.sent += 1
                    tx += 1
                    tx_bytes += len(raw)
            rest = SLICE - (time.perf_counter() - slice_start)
            if rest > 0:
                time.sleep(rest)
            if now - last_tick >= 1.0:
                elapsed = now - started
                emit(quiet, ev="tick", t=round(elapsed, 2), tx=tx,
                     rx=sniff_count(sniffer),
                     pps=round(tx / elapsed, 1) if elapsed else 0.0)
                last_tick = now
    except KeyboardInterrupt:
        emit(quiet, ev="note", msg="прервано с клавиатуры")
    finally:
        sock.close()

    seconds = time.perf_counter() - started
    rx, rx_frames = stop_sniffer(sniffer)
    if args.rx_pcap and rx_frames:
        wrpcap(args.rx_pcap, rx_frames)

    return {
        "tx": tx, "tx_bytes": tx_bytes, "rx": rx,
        "seconds": round(seconds, 3),
        "achieved_pps": round(tx / seconds, 1) if seconds else 0.0,
        "rx_source": "marker" if sniffer is not None else "none",
        "reliable": sniffer is not None,
        "truncated": list(_TRUNCATED),
    }


def sniff_count(sniffer):
    """How many of ours the receive side has seen so far (0 if not sniffing)."""
    if sniffer is None:
        return 0
    try:
        return len(sniffer.results or [])
    except Exception:
        return 0


def stop_sniffer(sniffer):
    """Stop and drain the sniffer. Returns (count, frames)."""
    if sniffer is None:
        return 0, []
    # Frames in flight when the last one is sent still have to arrive.
    time.sleep(0.5)
    try:
        caught = sniffer.stop() or []
    except Exception:
        caught = list(sniffer.results or [])
    return len(caught), list(caught)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Профиль трафика, собранный TRaphy")
    ap.add_argument("--iface", required=True, help="интерфейс отправки")
    ap.add_argument("--rx-iface", default="",
                    help="интерфейс приёма; без него потери не измеряются")
    ap.add_argument("--duration", type=float, default=10.0, help="секунд")
    ap.add_argument("--count", type=int, default=0,
                    help="всего пакетов; отменяет --duration")
    ap.add_argument("--pps", type=float, default=0.0,
                    help="общая цель по pps; масштабирует потоки пропорционально")
    ap.add_argument("--pcap", default="", help="куда записать отправляемые кадры")
    ap.add_argument("--rx-pcap", default="", help="куда записать принятые кадры")
    ap.add_argument("--dry-run", action="store_true",
                    help="собрать и показать кадры, ничего не отправляя")
    ap.add_argument("--quiet", action="store_true",
                    help="без машинных @traphy строк")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    quiet = args.quiet

    if not STREAMS:
        emit(quiet, ev="error", msg="в профиле нет включённых потоков")
        print("нет потоков - слать нечего", file=sys.stderr)
        return 2

    built = build_all(quiet)
    frames = sum(len(r) for _, _, r in built)
    total_pps = sum(s["pps"] for s, _, _ in built)
    emit(quiet, ev="ready", frames=frames, iface=args.iface,
         rx_iface=args.rx_iface, pps=args.pps or total_pps,
         duration=args.duration, count=args.count,
         truncated=list(_TRUNCATED))

    for line in _TRUNCATED:
        print("диапазон урезан - " + line, file=sys.stderr)

    if args.pcap:
        wrpcap(args.pcap, [f for _, fs, _ in built for f in fs])

    if args.dry_run:
        for spec, fs, raws in built:
            print("%s: %d кадров, %d B" % (spec["name"], len(raws),
                                           sum(len(r) for r in raws)))
            print("   " + fs[0].summary())
        emit(quiet, ev="done", tx=0, rx=0, seconds=0.0, tx_bytes=0,
             achieved_pps=0.0, rx_source="none", reliable=False,
             note="сухой прогон - в кабель ничего не ушло")
        return 0

    try:
        result = run(args, built, quiet)
    except PermissionError:
        emit(quiet, ev="error", msg="нет прав на сырой сокет - нужен root")
        print("нужен root: sudo " + " ".join(sys.argv), file=sys.stderr)
        return 13
    except OSError as exc:
        emit(quiet, ev="error", msg="интерфейс %s: %s" % (args.iface, exc))
        print("интерфейс %s: %s" % (args.iface, exc), file=sys.stderr)
        return 1

    emit(quiet, ev="done", **result)
    loss = result["tx"] - result["rx"]
    if result["reliable"]:
        share = (loss / result["tx"] * 100.0) if result["tx"] else 0.0
        tail = "принято %d, потеряно %d (%.2f%%)" % (result["rx"], loss, share)
    else:
        tail = "приём не измерялся - задай --rx-iface"
    print("отправлено %d кадров за %.1f c (%.0f pps), %s"
          % (result["tx"], result["seconds"], result["achieved_pps"], tail))
    return 0


if __name__ == "__main__":
    sys.exit(main())'''
