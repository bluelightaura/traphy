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
from pathlib import Path

from traphy import engines, presets, ui
from traphy.forms import (
    FORM_EXIT,
    Field,
    as_float,
    as_int,
    as_ip,
    as_mac,
    edit_form,
)
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
        profile = preset_screen()
    elif picked == 1:
        profile = wizard(session)
    else:
        profile = load_screen(session)
    if profile is None:
        return None
    # Сторож стоит здесь, а не на сохранении: сохраняет вызывающий, сразу же
    # после возврата, и к тому моменту спрашивать уже не у кого.
    return _unless_it_overwrites(session, profile)


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
# Чужая работа под тем же именем
# --------------------------------------------------------------------------- #
def _unless_it_overwrites(session: Session, profile: Profile) -> Profile | None:
    """The composed profile, once it is clear it lands on nobody else's file.

    What the caller does with what this screen returns is save it, under a name
    computed from the profile - fixed for a preset, deterministic for the
    wizard - so the names collide as a matter of course. A second look at a
    preset used to overwrite a profile tuned by hand before the stream screen
    was even drawn, with neither a question nor the file name anywhere on the
    screen. It is asked here because this is the last moment there is anyone to
    ask: one return later the file is already written.
    """
    while True:
        path = session.profile_path(profile.name)
        if not _would_overwrite(path, profile):
            return profile
        answer = ui.notice(_overwrite_panel(path, profile), ui.WIDE)
        if answer in ("y", "д"):
            return profile
        if answer not in ("n", "н"):
            # Любая другая клавиша - отмена, и отмена здесь значит «ничего не
            # сохранено»: на экране стоял вопрос про чужой файл.
            return None
        renamed = ui.ask_line("новое имя профиля (Enter - отмена): ").strip()
        if not renamed:
            return None
        profile.name = renamed


def _overwrite_panel(path: Path, profile: Profile) -> list[str]:
    """Что именно потеряется, с именем файла - его и не хватало."""
    room = ui.WIDE - 16
    return [
        ui.c(f"  Профиль «{profile.name}» уже сохранён", "warn"),
        ui.c(f"  файл: {_where(path)}", "dim"),
        None,  # type: ignore[list-item]
        ui.c(f"  там сейчас: {ui.trim(_disk_line(path), room)}", "dim"),
        ui.c(f"  станет:     {ui.trim(_streams_line(profile), room)}", "dim"),
        "",
        ui.c("  y перезаписать   n другое имя   "
             "любая другая клавиша - отмена", "dim"),
    ]


def _streams_line(profile: Profile) -> str:
    """Чем профиль является - по самим потокам, а не по подписи.

    Подпись у пресета стоит фиксированная («L3 IPv4 - маршрутизация») и правку
    размера со скоростью не описывает - то есть ровно то, что здесь надо
    сравнить, в ней и не видно.
    """
    return ", ".join(_describe(s) for s in profile.streams[:2]) or "нет потоков"


def _disk_line(path: Path) -> str:
    """То же про профиль, который уже лежит в файле."""
    try:
        return _streams_line(Profile.load(path))
    except (OSError, ValueError):
        return "не читается"


def _would_overwrite(path: Path, profile: Profile) -> bool:
    """Whether saving this profile would change what that file already holds."""
    return path.exists() and not _same_on_disk(path, profile)


def _same_on_disk(path: Path, profile: Profile) -> bool:
    """Whether that file holds exactly this profile - by content, not by bytes.

    Сравнивать текстом нельзя: ``rate_value`` 7000 после загрузки становится
    7000.0, и профиль, только что открытый из своего же файла, выглядел бы
    изменённым. Сторож спрашивал бы на каждом открытии, а вопрос, который
    задают там, где терять нечего, перестают читать.

    Нечитаемый файл - это «не то же самое»: сказать, что в нём, мы не можем.
    """
    try:
        return Profile.load(path).to_dict() == profile.to_dict()
    except (OSError, ValueError):
        return False


def _where(path: Path, room: int = 44) -> str:
    """Путь, из которого видно файл: режется голова, а не имя.

    Каталог профилей бывает длинным (во временном каталоге теста - очень), а
    узнать из строки надо ровно одно - какой файл.
    """
    text = str(path)
    if ui.width_of(text) <= room:
        return text
    return "…/" + "/".join(path.parts[-2:])


# --------------------------------------------------------------------------- #
# Сохранён ли он на самом деле
# --------------------------------------------------------------------------- #
def saved_state(session: Session,
                profile: Profile | None = None) -> tuple[bool, str]:
    """Whether what is in hand is also on disk, and the line that says which.

    ``Session.remember_profile`` swallows the ``OSError`` and quietly empties
    the remembered path, so on a profile directory nobody can write to, the
    stream screen showed the edit, the disk held nothing, and the next sitting
    opened with "трафик не собран". The screen that showed the edit is the one
    that has to admit it did not survive.
    """
    profile = profile or session.profile
    if profile is None:
        return True, ""
    path = session.profile_path(profile.name)
    shown = _where(path)
    if not path.exists():
        return False, f"не сохранён: файла {shown} нет"
    if not _same_on_disk(path, profile):
        return False, f"правки не сохранены: в {shown} другая версия"
    return True, f"сохранён: {shown}"


def unsaved_note(session: Session) -> str:
    """«не сохранён» для сводки профиля на главном экране, иначе пустая строка.

    Что считать сохранённым, решается в одном месте и живёт здесь; строку
    рисует launcher, и ему нужно из этого решения только одно слово.
    """
    saved, _line = saved_state(session)
    return "" if saved else "не сохранён"


def destination(profile: Profile) -> str:
    """Куда уйдёт трафик - одной строкой, для сводки и для экрана потоков.

    Сводка профиля называла имя, число потоков и скорость, то есть всё, кроме
    единственного, что делает прогон правильным или бессмысленным: адреса
    назначения. Считается здесь, печатается тем, кто сводку рисует.
    """
    streams = profile.enabled_streams or profile.streams
    if not streams:
        return ""
    seen = [stream_destination(s) for s in streams]
    extra = len(set(seen)) - 1
    return seen[0] + (f"  +{extra}" if extra > 0 else "")


def stream_destination(stream: Stream) -> str:
    """Адрес назначения одного потока, с диапазоном, если он перебирается."""
    p = stream.packet
    if not p.has_ip:
        return p.eth_dst
    where = _walked(stream, FieldTarget.IP_DST) or p.ip_dst
    if not p.has_l4:
        return where
    port = _walked(stream, FieldTarget.DPORT) or str(p.dport)
    return f"{where}:{port}"


def _walked(stream: Stream, target: FieldTarget) -> str:
    """Диапазон по этому полю, если поле перебирается, иначе пустая строка."""
    for vf in stream.vm_fields:
        if vf.target is target:
            return f"{vf.min_value}..{vf.max_value}"
    return ""


# --------------------------------------------------------------------------- #
# The guided build
# --------------------------------------------------------------------------- #
def wizard(session: Session) -> Profile | None:
    """Four questions, in dependency order. None if backed out at any step."""
    layer = _ask_layer()
    if layer is None:
        return None

    # Движок и скорость линии нужны уже здесь: подсказка под скоростью и
    # заметка на принятое значение - его политика, а «% от линии» считается от
    # этой цели. Раньше сеанс здесь выбрасывался, и оба брались из умолчания.
    engine = engines.get(session.target.engine)
    link_mbit = session.target.link_mbit

    stream = Stream(name="s1", packet=Packet(layer=layer))
    _default_for(stream, layer)

    if not _ask_fields(stream, step=2):
        return None
    if not _ask_ranges(stream, engine, step=3):
        return None
    if not _ask_rate(stream, engine, link_mbit, step=4):
        return None

    name = _profile_name(layer, stream)
    return Profile(name=name, description=_describe(stream), streams=[stream])


def _ask_layer() -> str | None:
    options = [(t(label), t(hint)) for _key, label, hint in _LAYERS]
    title = f"{t('w_layer')}   -   {t('step', n=1, total=4)}"
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
    title = f"{t('w_fields')}   -   {t('step', n=step, total=4)}"
    done = {"ok": False}
    while True:
        done["ok"] = False
        # Функцией, а не списком: поля этого экрана меняют тот же поток, который
        # шапка описывает, и посчитанная один раз она расходится с ними сразу -
        # размер поставлен 60, а в шапке до выхода с экрана держится прежний.
        edit_form(title, packet_fields(stream), width=ui.WIDE,
                  keys_hint="↑/↓ поле   ↵ править   n дальше   "
                            "q бросить сборку",
                  header=lambda: [ui.c("  " + _preview(stream), "dim")],
                  extra_keys={"n": lambda: _finish_if_valid(stream, done)})
        if done["ok"]:
            return True
        if _abandon(step):
            return False


def _abandon(step: int) -> bool:
    """Confirm dropping the whole wizard, because one key should not do it.

    Step 3 taught the hand that ``q`` means "дальше" - the ranges screen had it
    in the footer - and the same key on step 4 threw away four screens of work
    without asking. The keys say the same thing everywhere now; this is the
    second half of that, for the hand that already learned the old meaning.

    Without a terminal there is nobody to ask and nothing was entered, so the
    wizard is dropped - which is also what it did before.
    """
    if not ui.interactive():
        return True
    answer = ui.notice([
        ui.c("  Бросить сборку?", "warn"),
        ui.c(f"  Собранное на шагах 1-{step} из 4 потеряется.", "dim"),
        "",
        ui.c("  y бросить   любая другая клавиша - вернуться к сборке", "dim"),
    ], ui.WIDE)
    return answer in ("y", "д")


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


def _ask_ranges(stream: Stream, engine: engines.Engine, step: int) -> bool:
    title = f"{t('w_ranges')}   -   {t('step', n=step, total=4)}"
    return ranges_screen(stream, engine, title=title, wizard=True)


def _ask_rate(stream: Stream, engine: engines.Engine, link_mbit: int,
              step: int) -> bool:
    title = f"{t('w_rate')}   -   {t('step', n=step, total=4)}"
    done = {"ok": False}
    while True:
        done["ok"] = False
        edit_form(title, rate_fields(stream, engine, link_mbit), width=ui.WIDE,
                  keys_hint="↑/↓ поле   ↵ править   n готово   "
                            "q бросить сборку",
                  header=lambda: [ui.c("  " + _preview(stream), "dim")],
                  extra_keys={"n": lambda: _finish_if_valid(stream, done)})
        if done["ok"]:
            return True
        if _abandon(step):
            return False


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
        # Самая дорогая ловушка этого экрана, и стоит она ровно тут. Для
        # коммутации выдуманный MAC нормален - коробка его выучит. Для
        # маршрутизации нет: кадр с чужим MAC не поднимется на третий уровень,
        # приём честно покажет ноль, и это выглядит поломкой инструмента.
        Field("eth_dst", t("p_eth_dst"), lambda: p.eth_dst,
              set_mac("eth_dst", t("p_eth_dst")),
              hint=lambda: ("маршрутизация: нужен MAC интерфейса роутера - "
                            "с выдуманным кадр не дойдёт до L3 и приём будет "
                            "нулевой"
                            if p.has_ip else
                            "коммутация: выдуманный годится, коробка его "
                            "выучит")),
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
        return (f"! {p.frame_size} B мало для этих заголовков - "
                f"кадр выйдет {floor} B")
    return ""


def rate_fields(stream: Stream, engine: engines.Engine,
                link_mbit: int) -> list[Field]:
    """The rate questions, priced against the engine and the line that will
    carry them.

    Neither argument has a default on purpose: the defect this signature fixes
    was exactly a default. ``_rate_note`` used to call ``stream.pps()`` with no
    link, so on a 25G target a stream set to "50% of the line" was announced as
    ~411 184 pps when it was ten million, and the standing hint said "Scapy"
    whatever was selected.
    """
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
        return engine.rate_note(stream, link_mbit)

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
              hint=lambda: engine.rate_hint),
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


# --------------------------------------------------------------------------- #
# Ranges
# --------------------------------------------------------------------------- #
def ranges_screen(stream: Stream, engine: engines.Engine,
                  title: str = "", wizard: bool = False) -> bool:
    """Add, edit and remove the fields that walk instead of holding still.

    ``wizard`` is what makes ``q`` mean one thing across the whole guided path.
    As a wizard step this screen goes forward on ``n`` like the two around it,
    and ``q`` asks before dropping the build; opened from the stream editor it
    is just a screen to come back from. Returns whether the caller should carry
    on - always true outside the wizard.
    """
    if not ui.interactive():
        # Экран не открылся, значит ничего и не подтверждали: для шага визарда
        # это «дальше нельзя», для стороннего вызова - просто нечего делать.
        return not wizard
    cursor = 0
    status = ""
    while True:
        rows = list(stream.vm_fields)
        total = len(rows) + 1                       # the trailing "add" row
        cursor = max(0, min(cursor, total - 1))
        ui.draw(_render_ranges(stream, cursor, status, title, wizard))
        status = ""
        key = ui.read_key()

        if key in ("q", "esc", "quit"):
            if not wizard:
                return True
            if _abandon(3):
                return False
            continue
        if wizard and key == "n":
            return True
        if key == "up":
            cursor = (cursor - 1) % total
        elif key == "down":
            cursor = (cursor + 1) % total
        elif key == "enter":
            if cursor == len(rows):
                status = _add_range(stream, engine)
            else:
                status = _edit_range(stream, rows[cursor], engine)
        elif key == "d" and cursor < len(rows):
            stream.vm_fields.remove(rows[cursor])
            status = "диапазон убран"


def _render_ranges(stream: Stream, cursor: int, status: str, title: str,
                   wizard: bool = False) -> str:
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
    keys = ("↑/↓ выбор   ↵ править   d убрать   n дальше   q бросить сборку"
            if wizard else "↑/↓ выбор   ↵ править   d убрать   q назад")
    lines.append(ui.c("  " + keys, "dim"))
    return ui.panel(lines, ui.WIDE)


def _add_range(stream: Stream, engine: engines.Engine) -> str:
    """Offer only the fields this frame actually has, then edit the new one."""
    available = _range_targets(stream)
    if not available:
        return "! в этом кадре нечего перебирать - добавь IP или L4"
    options = [(target.label, _range_hint(target)) for target in available]
    picked = ui.choose(t("w_ranges"), options, keys_hint=t("keys_pick"),
                       width=ui.WIDE)
    if picked is None:
        return ""
    target = available[picked]
    vf = VMField(target=target, **_range_defaults(target, stream))
    stream.vm_fields.append(vf)
    return _edit_range(stream, vf, engine)


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


def _edit_range(stream: Stream, vf: VMField, engine: engines.Engine) -> str:
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
            return _range_note(vf, engine)
        return setter

    def set_step(v: str) -> str:
        n, err = as_int(v, 1, 65535, "шаг")
        if err:
            return err
        vf.step = n
        return _range_note(vf, engine)

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
    edit_form(f"Диапазон - {vf.target.label}", fields, width=ui.WIDE,
              keys_hint="↑/↓ поле   ↵ править   q готово",
              header=lambda: [ui.c("  " + _preview(stream), "dim")])
    return _range_note(vf, engine) or "диапазон обновлён"


def _range_note(vf: VMField, engine: engines.Engine) -> str:
    """What is wrong with this range, then what this engine will do to it.

    The first check is the model's and holds whoever sends: ends that do not
    parse, or that run backwards, describe no range at all. Whether a range
    that *is* a range gets walked in full is the engine's business - Scapy
    expands it into frames and caps the result, TRex and Ixia hand it to
    hardware that counts through all of it - so that half is asked, not guessed.
    """
    if range_size(vf) == 0:
        return "! концы диапазона не разбираются или стоят задом наперёд"
    return engine.range_note(vf)


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
            _save_on_exit(session, profile)
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
                stream_editor(profile.streams[cursor],
                              engines.get(session.target.engine),
                              session.target.link_mbit)
        elif key == " " and cursor < len(profile.streams):
            s = profile.streams[cursor]
            s.enabled = not s.enabled
            status = f"{s.name}: {'включён' if s.enabled else 'выключен'}"
        elif key == "d" and cursor < len(profile.streams):
            status = _delete_stream(profile, cursor)


def _save_on_exit(session: Session, profile: Profile) -> None:
    """Save on the way out, and say it out loud when the disk did not take it.

    The save itself swallows its ``OSError``, so "сохранено" was the only thing
    this screen could ever report. A run of the tool that ends believing a
    profile exists is worse than one that ends knowing it does not: the next
    sitting opens with nothing composed and no idea why.
    """
    session.remember_profile(profile)
    saved, line = saved_state(session, profile)
    if saved:
        return
    ui.notice([
        ui.c("  Правка НЕ сохранена", "bad"),
        ui.c("  " + line, "warn"),
        "",
        ui.c("  Собранное живёт только в этом сеансе - следующий запуск "
             "откроется без него.", "dim"),
        ui.c("  Обычно это права на каталог профилей.", "dim"),
        "",
        ui.c("  " + t("keys_any"), "dim"),
    ], ui.WIDE)


def _render_streams(session: Session, profile: Profile, cursor: int,
                    status: str) -> str:
    lines: list[str] = [ui.c(t("streams_head", name=profile.name), "title")]
    # Asked of the engine, not of the Scapy generator: the same /16 sweep is
    # 1024 frames there and 65 536 here, and the number on the screen has to
    # be the one this target will actually build.
    engine = engines.get(session.target.engine)
    frames = engine.frame_count(profile)
    pps = f"{profile.total_pps(session.target.link_mbit):,.0f}".replace(",", " ")
    lines.append(ui.c("  " + t("total_rate", pps=pps, frames=frames), "dim"))
    # Куда шлём - на экране, а не только в скрипте: убедиться, что трафик пойдёт
    # по адресу, иначе можно было только открыв profile.json руками.
    lines.append(ui.c(f"  куда: {destination(profile)}", "dim"))
    # И сохранён ли он. Правка, которую диск не взял, выглядела здесь ровно так
    # же, как взятая, - экран показывал её из памяти.
    saved, where = saved_state(session, profile)
    lines.append(ui.c("  " + where, "dim" if saved else "warn"))
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
    # Рядом с проблемами профиля, а не вместо них: это не «нельзя запускать», а
    # «запустится, но вот это не измерится». Читал их один CLI, и пресет L2 на
    # TRex уходил из меню молча - человек видел rx=0 и шёл проверять коробку.
    for warning in engine.warnings(profile):
        lines.append(ui.c(f"  • {warning}", "warn"))
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
    # Через общий `ui.confirm`, а не «любая клавиша»: на каждой другой панели
    # инструмента Enter значит «закрыть», и только здесь он значил «удалить».
    # Рука, привыкшая закрывать панели Enter'ом, стирала поток.
    if ui.confirm([ui.c("  " + t("confirm_delete", name=doomed.name), "warn")],
                  ui.WIDE):
        profile.streams.pop(index)
        return f"поток «{doomed.name}» удалён"
    return ""


def stream_editor(stream: Stream, engine: engines.Engine,
                  link_mbit: int) -> None:
    """One stream, all of it: fields, rate, and the ranges behind one key."""
    fields = packet_fields(stream) + rate_fields(stream, engine, link_mbit)
    edit_form(f"Поток - {stream.name}", fields, width=ui.WIDE,
              keys_hint="↑/↓ поле   ↵ править   r диапазоны   q назад",
              header=lambda: [ui.c("  " + _preview(stream), "dim")],
              extra_keys={"r": lambda: _open_ranges(stream, engine)})


def _open_ranges(stream: Stream, engine: engines.Engine) -> str:
    ranges_screen(stream, engine)
    return ""
