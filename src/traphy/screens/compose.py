"""Composing the traffic by hand: layer, fields, ranges, rate.

This is the part the tool exists for. Nothing here writes a packet - it edits
:mod:`traphy.models` dataclasses, and the code generator turns those into the
script. That separation is what lets the "Показать скрипт" screen be truthful:
it is not a rendering of the form, it is the actual artefact.

The guided path asks one thing per screen, in the order the answers depend on
each other: what layer, then the fields that layer has, then what should walk,
then how fast. A preset skips straight to the end with all four already
answered, and the stream editor reopens any of them afterwards.
"""

from __future__ import annotations

import copy

from traphy import presets, ui
from traphy.forms import (
    FORM_EXIT,
    Field,
    as_float,
    as_int,
    as_ip,
    as_mac,
    edit_form,
)
from traphy.codegen import frame_count
from traphy.models import (
    FieldTarget,
    L4Proto,
    Packet,
    Profile,
    RateType,
    Stream,
    TxMode,
    VMField,
    VMOp,
    range_size,
)
from traphy.session import Session
from traphy.strings import t

_LAYERS = [
    ("l2", "w_l2", "w_l2_hint"),
    ("l3", "w_l3", "w_l3_hint"),
    ("l4", "w_l4", "w_l4_hint"),
]

_RATE_UNITS = [
    (RateType.PPS.value, "u_pps"),
    (RateType.BPS_L2.value, "u_bps"),
    (RateType.PERCENT.value, "u_pct"),
]

_TX_MODES = [
    (TxMode.CONTINUOUS.value, "m_continuous"),
    (TxMode.SINGLE_BURST.value, "m_single"),
    (TxMode.MULTI_BURST.value, "m_multi"),
]


def compose_screen(session: Session) -> Profile | None:
    """Where a new profile comes from. Returns it, or None if backed out of."""
    options = [
        (t("from_preset"), t("from_preset_hint")),
        (t("by_hand"), t("by_hand_hint")),
        (t("load_saved"), t("load_saved_hint")),
    ]
    picked = ui.choose(t("compose_pick"), options, keys_hint=t("keys_pick"),
                       width=ui.WIDE)
    if picked is None:
        return None
    if picked == 0:
        return preset_screen()
    if picked == 1:
        return wizard(session)
    return load_screen(session)


def preset_screen() -> Profile | None:
    """Pick a ready-made profile."""
    keys = presets.keys()
    options = [(presets.PRESETS[k][0], presets.PRESETS[k][1]) for k in keys]
    picked = ui.choose(t("pick_preset"), options, keys_hint=t("keys_pick"),
                       width=ui.WIDE)
    return presets.build(keys[picked]) if picked is not None else None


def load_screen(session: Session) -> Profile | None:
    """Open a profile saved earlier."""
    directory = session.profile_dir
    paths = sorted(directory.glob("*.json")) if directory.exists() else []
    if not paths:
        ui.notice([ui.c(f"  В {directory}/ нет сохранённых профилей", "warn"), "",
                   ui.c("  " + t("keys_any"), "dim")], ui.WIDE)
        return None
    options = [(p.stem, _peek(p)) for p in paths]
    picked = ui.choose(t("load_saved"), options, keys_hint=t("keys_pick"),
                       width=ui.WIDE)
    if picked is None:
        return None
    try:
        return Profile.load(paths[picked])
    except (OSError, ValueError) as exc:
        ui.notice([ui.c(f"  Не читается: {exc}", "bad"), "",
                   ui.c("  " + t("keys_any"), "dim")], ui.WIDE)
        return None


def _peek(path) -> str:
    """A one-line description of a saved profile without fully trusting it."""
    try:
        profile = Profile.load(path)
    except (OSError, ValueError):
        return "не читается"
    return profile.description or f"{len(profile.streams)} потоков"


# --------------------------------------------------------------------------- #
# The guided build
# --------------------------------------------------------------------------- #
def wizard(session: Session) -> Profile | None:
    """Four questions, in dependency order. None if backed out at any step."""
    del session
    layer = _ask_layer()
    if layer is None:
        return None

    stream = Stream(name="s1", packet=Packet(layer=layer))
    _default_for(stream, layer)

    if not _ask_fields(stream, step=2):
        return None
    if not _ask_ranges(stream, step=3):
        return None
    if not _ask_rate(stream, step=4):
        return None

    name = _profile_name(layer, stream)
    return Profile(name=name, description=_describe(stream), streams=[stream])


def _ask_layer() -> str | None:
    options = [(t(label), t(hint)) for _key, label, hint in _LAYERS]
    title = f"{t('w_layer')}   —   {t('step', n=1, total=4)}"
    picked = ui.choose(title, options, cursor=2, keys_hint=t("keys_pick"),
                       width=ui.WIDE)
    return _LAYERS[picked][0] if picked is not None else None


def _default_for(stream: Stream, layer: str) -> None:
    """Sensible starting values so the fields screen is never blank.

    The sizes differ per layer on purpose: 64 bytes is the interesting case for
    switching, while an L3 or L4 test usually wants something that is not all
    padding.
    """
    stream.packet.frame_size = {"l2": 64, "l3": 128, "l4": 128}[layer]
    stream.name = {"l2": "eth", "l3": "ip", "l4": "udp"}[layer]


def _ask_fields(stream: Stream, step: int) -> bool:
    """The frame's own fields, filtered to the layer that has them."""
    title = f"{t('w_fields')}   —   {t('step', n=step, total=4)}"
    done = {"ok": False}

    def finish() -> str:
        done["ok"] = True
        return ""

    edit_form(title, packet_fields(stream), width=ui.WIDE,
              keys_hint="↑/↓ поле   ↵ править   n дальше   q отмена",
              header=[ui.c("  " + _preview(stream), "dim")],
              extra_keys={"n": lambda: _finish_if_valid(stream, done)})
    return done["ok"]


def _finish_if_valid(stream: Stream, done: dict[str, bool]) -> str:
    """The wizard's "дальше" key: refuse to advance over a broken stream.

    Catching it here rather than at the end means the operator fixes the field
    they are looking at, instead of being told three screens later that the
    frame was too small for its own headers.
    """
    problems = Profile(streams=[stream]).validate()
    if problems:
        return "! " + problems[0]
    done["ok"] = True
    return FORM_EXIT


def _ask_ranges(stream: Stream, step: int) -> bool:
    title = f"{t('w_ranges')}   —   {t('step', n=step, total=4)}"
    ranges_screen(stream, title=title)
    return True


def _ask_rate(stream: Stream, step: int) -> bool:
    title = f"{t('w_rate')}   —   {t('step', n=step, total=4)}"
    done = {"ok": False}
    edit_form(title, rate_fields(stream), width=ui.WIDE,
              keys_hint="↑/↓ поле   ↵ править   n готово   q отмена",
              header=[ui.c("  " + _preview(stream), "dim")],
              extra_keys={"n": lambda: _finish_if_valid(stream, done)})
    return done["ok"]


def _profile_name(layer: str, stream: Stream) -> str:
    walked = "_sweep" if stream.vm_fields else ""
    tag = "vlan" if stream.packet.has_vlan else layer
    return f"{tag}{walked}"


def _describe(stream: Stream) -> str:
    bits = [stream.packet.describe(), stream.rate_label()]
    bits.extend(vf.describe() for vf in stream.vm_fields)
    return ", ".join(bits)


def _preview(stream: Stream) -> str:
    """The one-line "what this is" shown above every builder screen."""
    return f"{stream.name}: {_describe(stream)}"


# --------------------------------------------------------------------------- #
# Field sets, shared by the wizard and the stream editor
# --------------------------------------------------------------------------- #
def packet_fields(stream: Stream) -> list[Field]:
    p = stream.packet
    has_ip = lambda: p.has_ip
    has_l4 = lambda: p.has_l4

    def set_vlan(v: str) -> str:
        text = v.strip().lower()
        if text in ("", "-", "нет", "no", "none"):
            p.vlan = None
            return ""
        n, err = as_int(text, 0, 4095, t("p_vlan"))
        if err:
            return err
        p.vlan = n
        return ""

    def set_size(v: str) -> str:
        n, err = as_int(v, 60, 9000, t("p_size"))
        if err:
            return err
        p.frame_size = n
        return _size_note(p)

    def set_port(attr: str, label: str):
        def setter(v: str) -> str:
            n, err = as_int(v, 0, 65535, label)
            if err:
                return err
            setattr(p, attr, n)
            return ""
        return setter

    def set_mac(attr: str, label: str):
        def setter(v: str) -> str:
            mac, err = as_mac(v, label)
            if err:
                return err
            setattr(p, attr, mac)
            return ""
        return setter

    def set_ip(attr: str, label: str):
        def setter(v: str) -> str:
            ip, err = as_ip(v, label)
            if err:
                return err
            setattr(p, attr, ip)
            return ""
        return setter

    def set_ttl(v: str) -> str:
        n, err = as_int(v, 1, 255, t("p_ttl"))
        if err:
            return err
        p.ttl = n
        return ""

    def set_proto(v: str) -> str:
        p.l4_proto = L4Proto(v)
        return ""

    return [
        Field("name", t("p_name"), lambda: stream.name,
              lambda v: (setattr(stream, "name", v.strip() or stream.name), "")[1]),
        Field("eth_src", t("p_eth_src"), lambda: p.eth_src,
              set_mac("eth_src", t("p_eth_src"))),
        Field("eth_dst", t("p_eth_dst"), lambda: p.eth_dst,
              set_mac("eth_dst", t("p_eth_dst"))),
        Field("vlan", t("p_vlan"), lambda: str(p.vlan) if p.has_vlan else t("no"),
              set_vlan, hint="тег добавит 4 байта к кадру"),
        Field("ip_src", t("p_ip_src"), lambda: p.ip_src,
              set_ip("ip_src", t("p_ip_src")), visible=has_ip),
        Field("ip_dst", t("p_ip_dst"), lambda: p.ip_dst,
              set_ip("ip_dst", t("p_ip_dst")), visible=has_ip),
        Field("ttl", t("p_ttl"), lambda: str(p.ttl), set_ttl, visible=has_ip),
        Field("proto", t("p_proto"), lambda: p.l4_proto.value, set_proto,
              kind="pick", visible=has_l4,
              options=[("UDP", "UDP", "без сессии"), ("TCP", "TCP", "таблицы сессий")]),
        Field("sport", t("p_sport"), lambda: str(p.sport),
              set_port("sport", t("p_sport")), visible=has_l4),
        Field("dport", t("p_dport"), lambda: str(p.dport),
              set_port("dport", t("p_dport")), visible=has_l4),
        Field("size", t("p_size"), lambda: str(p.frame_size), set_size,
              hint="без FCS; на проводе будет на 4 байта больше"),
    ]


def _size_note(p: Packet) -> str:
    """Warn when the requested size cannot hold the headers it was given."""
    floor = {"l2": 14, "l3": 34, "l4": 54}[p.layer] + (4 if p.has_vlan else 0)
    if p.frame_size < floor:
        return (f"! {p.frame_size} B мало для этих заголовков — "
                f"кадр выйдет {floor} B")
    return ""


def rate_fields(stream: Stream) -> list[Field]:
    burst = lambda: stream.tx_mode is not TxMode.CONTINUOUS
    multi = lambda: stream.tx_mode is TxMode.MULTI_BURST

    def set_unit(v: str) -> str:
        stream.rate_type = RateType(v)
        return ""

    def set_rate(v: str) -> str:
        x, err = as_float(v, t("p_rate"))
        if err:
            return err
        if stream.rate_type is RateType.PERCENT and x > 100:
            return f"! {t('p_rate')}: больше 100% линии не бывает"
        stream.rate_value = x
        return _rate_note(stream)

    def set_mode(v: str) -> str:
        stream.tx_mode = TxMode(v)
        return ""

    def set_burst(v: str) -> str:
        n, err = as_int(v, 1, 10_000_000, t("p_burst"))
        if err:
            return err
        stream.pkts_per_burst = n
        return ""

    def set_bursts(v: str) -> str:
        n, err = as_int(v, 1, 100_000, t("p_bursts"))
        if err:
            return err
        stream.number_of_bursts = n
        return ""

    def set_ibg(v: str) -> str:
        x, err = as_float(v, t("p_ibg"))
        if err:
            return err
        stream.ibg_usec = x
        return ""

    return [
        Field("unit", t("p_rate_type"), lambda: stream.rate_type.value, set_unit,
              kind="pick",
              options=[(value, t(label), "") for value, label in _RATE_UNITS]),
        Field("rate", t("p_rate"), lambda: f"{stream.rate_value:g}", set_rate,
              hint="Scapy это цель, а не гарантия"),
        Field("mode", t("p_mode"), lambda: stream.tx_mode.value, set_mode,
              kind="pick",
              options=[(value, t(label), "") for value, label in _TX_MODES]),
        Field("burst", t("p_burst"), lambda: str(stream.pkts_per_burst),
              set_burst, visible=burst),
        Field("bursts", t("p_bursts"), lambda: str(stream.number_of_bursts),
              set_bursts, visible=multi),
        Field("ibg", t("p_ibg"), lambda: f"{stream.ibg_usec:g}", set_ibg,
              visible=multi, hint="пауза между очередями"),
    ]


def _rate_note(stream: Stream) -> str:
    """Say out loud when a rate is beyond what this path can carry.

    Scapy through a kernel socket tops out well below a NIC. Somewhere around
    a hundred thousand frames a second the loop stops keeping up, and a run
    that quietly delivers a third of what was asked reads as a device problem
    when it is a tool problem.
    """
    pps = stream.pps()
    if pps > 200_000:
        return f"! ~{pps:,.0f} pps — Scapy столько не выдаст, возьми меньше"
    if pps > 50_000:
        return f"~{pps:,.0f} pps — на грани того, что Scapy тянет"
    return ""


# --------------------------------------------------------------------------- #
# Ranges
# --------------------------------------------------------------------------- #
def ranges_screen(stream: Stream, title: str = "") -> None:
    """Add, edit and remove the fields that walk instead of holding still."""
    if not ui.interactive():
        return
    cursor = 0
    status = ""
    while True:
        rows = list(stream.vm_fields)
        total = len(rows) + 1                       # the trailing "add" row
        cursor = max(0, min(cursor, total - 1))
        ui.draw(_render_ranges(stream, cursor, status, title))
        status = ""
        key = ui.read_key()

        if key in ("q", "esc", "quit"):
            return
        if key == "up":
            cursor = (cursor - 1) % total
        elif key == "down":
            cursor = (cursor + 1) % total
        elif key == "enter":
            if cursor == len(rows):
                status = _add_range(stream)
            else:
                status = _edit_range(stream, rows[cursor])
        elif key == "d" and cursor < len(rows):
            stream.vm_fields.remove(rows[cursor])
            status = "диапазон убран"


def _render_ranges(stream: Stream, cursor: int, status: str, title: str) -> str:
    lines: list[str] = [ui.c(title or t("w_ranges"), "title"),
                        ui.c("  " + _preview(stream), "dim"), None]  # type: ignore[list-item]
    if not stream.vm_fields:
        lines.append(ui.c("  " + t("w_no_range"), "dim"))
    for i, vf in enumerate(stream.vm_fields):
        size = range_size(vf)
        text = f" {'▸' if i == cursor else ' '} {ui.pad(vf.describe(), 44)} {size} знач."
        lines.append(ui.selected_row(text, ui.WIDE) if i == cursor
                     else ui.pad(text, ui.WIDE))
    add = f" {'▸' if cursor == len(stream.vm_fields) else ' '} + добавить диапазон"
    lines.append(ui.selected_row(add, ui.WIDE)
                 if cursor == len(stream.vm_fields) else ui.pad(add, ui.WIDE))
    lines.append("")
    if status:
        lines.append(ui.c("  " + status.lstrip("! "),
                          "bad" if status.startswith("!") else "ok"))
    lines.append(ui.c("  ↑/↓ выбор   ↵ править   d убрать   q дальше", "dim"))
    return ui.panel(lines, ui.WIDE)


def _add_range(stream: Stream) -> str:
    """Offer only the fields this frame actually has, then edit the new one."""
    available = _range_targets(stream)
    if not available:
        return "! в этом кадре нечего перебирать — добавь IP или L4"
    options = [(target.label, _range_hint(target)) for target in available]
    picked = ui.choose(t("w_ranges"), options, keys_hint=t("keys_pick"),
                       width=ui.WIDE)
    if picked is None:
        return ""
    target = available[picked]
    vf = VMField(target=target, **_range_defaults(target, stream))
    stream.vm_fields.append(vf)
    return _edit_range(stream, vf)


def _range_targets(stream: Stream) -> list[FieldTarget]:
    used = {vf.target for vf in stream.vm_fields}
    out: list[FieldTarget] = []
    if stream.packet.has_ip:
        out += [FieldTarget.IP_SRC, FieldTarget.IP_DST]
    if stream.packet.has_l4:
        out += [FieldTarget.SPORT, FieldTarget.DPORT]
    return [target for target in out if target not in used]


def _range_hint(target: FieldTarget) -> str:
    return {
        FieldTarget.IP_SRC: "нагрузка на таблицу источников",
        FieldTarget.IP_DST: "перебор маршрутов, FIB",
        FieldTarget.SPORT: "разные сессии от одного узла",
        FieldTarget.DPORT: "сессии, ACL, NAT",
    }[target]


def _range_defaults(target: FieldTarget, stream: Stream) -> dict[str, object]:
    p = stream.packet
    if target is FieldTarget.IP_SRC:
        return {"op": VMOp.INC, "min_value": p.ip_src, "max_value": _bump(p.ip_src)}
    if target is FieldTarget.IP_DST:
        return {"op": VMOp.INC, "min_value": p.ip_dst, "max_value": _bump(p.ip_dst)}
    return {"op": VMOp.INC, "min_value": "1", "max_value": "1024"}


def _bump(ip: str) -> str:
    """The top of a default /24-ish range starting at ``ip``."""
    import ipaddress
    try:
        base = int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return ip
    return str(ipaddress.IPv4Address(min(base + 253, 2 ** 32 - 1)))


def _edit_range(stream: Stream, vf: VMField) -> str:
    """The three questions a range has: how it walks, from where, to where."""
    is_ip = vf.target.is_ip

    def set_op(v: str) -> str:
        vf.op = VMOp(v)
        return ""

    def set_end(attr: str) -> object:
        def setter(v: str) -> str:
            if is_ip:
                ip, err = as_ip(v, vf.target.label)
                if err:
                    return err
                setattr(vf, attr, ip)
            else:
                n, err = as_int(v, 0, 65535, vf.target.label)
                if err:
                    return err
                setattr(vf, attr, str(n))
            return _range_note(vf)
        return setter

    def set_step(v: str) -> str:
        n, err = as_int(v, 1, 65535, "шаг")
        if err:
            return err
        vf.step = n
        return _range_note(vf)

    fields = [
        Field("op", "как перебирать", lambda: vf.op.value, set_op, kind="pick",
              options=[(VMOp.INC.value, "по возрастанию", "1, 2, 3…"),
                       (VMOp.DEC.value, "по убыванию", "…3, 2, 1"),
                       (VMOp.RANDOM.value, "случайно", "пул из 256 значений")]),
        Field("min", "от", lambda: vf.min_value, set_end("min_value")),
        Field("max", "до", lambda: vf.max_value, set_end("max_value")),
        Field("step", "шаг", lambda: str(vf.step), set_step,
              visible=lambda: vf.op is not VMOp.RANDOM),
    ]
    edit_form(f"Диапазон — {vf.target.label}", fields, width=ui.WIDE,
              keys_hint="↑/↓ поле   ↵ править   q готово",
              header=[ui.c("  " + _preview(stream), "dim")])
    return _range_note(vf) or "диапазон обновлён"


def _range_note(vf: VMField) -> str:
    """Flag a range that will be truncated before the run finds out for us."""
    from traphy.codegen import EXPAND_CAP

    size = range_size(vf)
    if size == 0:
        return "! концы диапазона не разбираются или стоят задом наперёд"
    if vf.op is not VMOp.RANDOM and size > EXPAND_CAP:
        return (f"! {size} значений — будет урезано до {EXPAND_CAP}; "
                f"возьми шаг больше или диапазон уже")
    return ""


# --------------------------------------------------------------------------- #
# The stream list
# --------------------------------------------------------------------------- #
def streams_screen(session: Session) -> None:
    """Every stream in the profile: edit, toggle, delete, add."""
    if not (ui.interactive() and session.profile):
        return
    profile = session.profile
    cursor = 0
    status = ""
    while True:
        total = len(profile.streams) + 1
        cursor = max(0, min(cursor, total - 1))
        ui.draw(_render_streams(session, profile, cursor, status))
        status = ""
        key = ui.read_key()

        if key in ("q", "esc", "quit"):
            session.remember_profile(profile)
            return
        if key == "up":
            cursor = (cursor - 1) % total
        elif key == "down":
            cursor = (cursor + 1) % total
        elif key == "enter":
            if cursor == len(profile.streams):
                profile.streams.append(_new_stream(profile))
                status = "поток добавлен"
            else:
                stream_editor(profile.streams[cursor])
        elif key == " " and cursor < len(profile.streams):
            s = profile.streams[cursor]
            s.enabled = not s.enabled
            status = f"{s.name}: {'включён' if s.enabled else 'выключен'}"
        elif key == "d" and cursor < len(profile.streams):
            status = _delete_stream(profile, cursor)


def _render_streams(session: Session, profile: Profile, cursor: int,
                    status: str) -> str:
    lines: list[str] = [ui.c(t("streams_head", name=profile.name), "title")]
    frames = frame_count(profile)
    pps = f"{profile.total_pps(session.target.link_mbit):,.0f}".replace(",", " ")
    lines.append(ui.c("  " + t("total_rate", pps=pps, frames=frames), "dim"))
    lines.append(None)  # type: ignore[arg-type]

    for i, s in enumerate(profile.streams):
        mark = "●" if s.enabled else "○"
        tail = "" if s.enabled else f"  ({t('stream_off')})"
        text = (f" {'▸' if i == cursor else ' '} {mark} {ui.pad(s.name, 12)}"
                f" {ui.pad(s.packet.describe(), 20)} {s.rate_label()}{tail}")
        if i == cursor:
            lines.append(ui.selected_row(text, ui.WIDE))
        elif not s.enabled:
            lines.append(ui.dim_row(text, ui.WIDE))
        else:
            lines.append(ui.pad(ui.trim(text, ui.WIDE), ui.WIDE))
        for vf in s.vm_fields:
            lines.append(ui.c(f"        ↳ {vf.describe()}", "accent"))

    add = f" {'▸' if cursor == len(profile.streams) else ' '} {t('add_stream')}"
    lines.append(ui.selected_row(add, ui.WIDE)
                 if cursor == len(profile.streams) else ui.pad(add, ui.WIDE))

    lines.append("")
    if status:
        lines.append(ui.c("  " + status.lstrip("! "),
                          "bad" if status.startswith("!") else "ok"))
    for problem in profile.validate():
        lines.append(ui.c(f"  • {problem}", "warn"))
    lines.append(ui.c("  " + t("keys_streams"), "dim"))
    return ui.panel(lines, ui.WIDE)


def _new_stream(profile: Profile) -> Stream:
    """A copy of the last stream rather than a blank one.

    Adding a second stream almost always means "the same thing but a different
    size or port", so copying saves re-entering the MACs and addresses that
    were just typed. The name is made unique so validation stays quiet.
    """
    base = copy.deepcopy(profile.streams[-1]) if profile.streams else Stream()
    used = {s.name for s in profile.streams}
    n = 2
    stem = base.name.rstrip("0123456789") or "s"
    while f"{stem}{n}" in used:
        n += 1
    base.name = f"{stem}{n}"
    base.enabled = True
    return base


def _delete_stream(profile: Profile, index: int) -> str:
    if len(profile.streams) <= 1:
        return "! " + t("last_stream")
    doomed = profile.streams[index]
    answer = ui.notice([ui.c("  " + t("confirm_delete", name=doomed.name), "warn")],
                       ui.WIDE)
    if answer in ("y", "д", "enter"):
        profile.streams.pop(index)
        return f"поток «{doomed.name}» удалён"
    return ""


def stream_editor(stream: Stream) -> None:
    """One stream, all of it: fields, rate, and the ranges behind one key."""
    fields = packet_fields(stream) + rate_fields(stream)
    edit_form(f"Поток — {stream.name}", fields, width=ui.WIDE,
              keys_hint="↑/↓ поле   ↵ править   r диапазоны   q назад",
              header=[ui.c("  " + _preview(stream), "dim")],
              extra_keys={"r": lambda: _open_ranges(stream)})


def _open_ranges(stream: Stream) -> str:
    ranges_screen(stream)
    return ""
