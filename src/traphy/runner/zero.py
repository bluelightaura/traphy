"""Why nothing came back - facts first, suspicions second, and labelled as such.

"Потери 100%" is the most expensive answer this tool can print. Acting on it
means someone walks to a rack, and walking to the wrong rack costs a morning.
So a zero is never returned bare: it comes with what is *established* about the
run and, separately, what is worth checking - and the two are never mixed,
because a guess dressed as a fact is what sends people to the wrong rack.

The order matters and it goes outward from us: did anything leave at all, was
anybody counting, could the frame have been dropped at ingress by its own
shape, and only then the device. Blaming the box first is the habit this module
exists to break.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for types only
    from traphy.models import Profile
    from traphy.runner.result import RunResult
    from traphy.target import Target

# A frame whose size sits on the classic boundary is worth one line of its own:
# traphy sizes frames without FCS, so the textbook "64-byte test" is 60 here,
# and a run set up from a TRex example that already subtracted four will be
# four bytes short of what the operator thinks they asked for.
FCS_BYTES = 4
CLASSIC_SIZES = (60, 64)


def is_zero(result: RunResult) -> bool:
    """Frames left, nothing came back, and somebody was actually counting."""
    return result.tx_pkts > 0 and result.rx_pkts == 0 and result.rx_source != "none"


# Кто именно считал приём. Счёт по метке точен, но делает его сниффер, а не
# железо: назвать его аппаратным - ровно та подмена, от которой отчёт этого
# инструмента и отказывается везде в другом месте.
HOW_COUNTED = {
    "marker": "сниффером по метке в теле кадра",
    "flow_stats": "аппаратными счётчиками группы",
    "traffic_item": "счётчиками traffic item на шасси",
}


def iface_tag(name: str) -> int | None:
    """Тег, который навесит ядро на этом интерфейсе, если он VLAN-подинтерфейс.

    Профиль может не содержать ни одного тега, а кадры всё равно уйдут
    тегированными: тег добавляет интерфейс. Совет «кадры уходят без тега»
    в таком прогоне отправляет искать несуществующую причину.
    """
    for part in (name.rsplit(".", 1)[-1] if "." in name else "",
                 name[4:] if name.lower().startswith("vlan") else ""):
        if part.isdigit() and 1 <= int(part) <= 4094:
            return int(part)
    return None


def established(result: RunResult) -> list[str]:
    """What this run proves on its own, without looking at the device."""
    out: list[str] = []
    if result.tx_pkts == 0:
        out.append("из генератора не вышло ни единого кадра - "
                   "устройство здесь ни при чём, разбираться надо с прогоном")
        return out
    out.append(f"генератор отправил {result.tx_pkts} кадров "
               f"с {result.tx_iface or 'порта отправки'}")
    if result.rx_source == "none":
        out.append("приёмная сторона не считалась вообще - это не «ноль "
                   "принято», это «никто не считал»")
    elif result.reliable:
        out.append(f"приём считан {HOW_COUNTED.get(result.rx_source, result.rx_source)}"
                   f" - ноль здесь означает именно ноль")
    else:
        out.append(f"приём считан как {result.rx_source} - ноль по нему "
                   f"надёжен меньше, чем аппаратный счёт")
    return out


def worth_checking(result: RunResult, profile: Profile,
                   target: Target) -> list[str]:
    """Things that produce this exact picture. Suspicions, and they say so."""
    out: list[str] = []
    if result.rx_source == "none":
        where = ("порт приёма" if result.engine in ("trex", "ixia")
                 else "интерфейс приёма")
        out.append(f"в цели не задан {where} - пока он пуст, ни один прогон "
                   f"не сможет ответить, дошло ли что-нибудь")
        return out

    if result.tx_iface and result.tx_iface == result.rx_iface:
        out.append("отправка и приём указаны на одном порту - счётчик ловит "
                   "собственную отправку, а не то, что вернулось через коробку")

    # Первым, потому что это причина номер один и проверяется за минуту.
    # Счётчик входящих на ближнем порту при этом считает исправно, так что
    # «коробка кадры видит» ничего не опровергает: выйти им может быть некуда.
    out.append("линк на дальнем плече - на самой коробке оба порта должны "
               "быть up; порт без линка считает входящие на соседнем плече "
               "и не выпускает ничего")

    packets = [s.packet for s in profile.streams if s.enabled]
    tagged = [p for p in packets if p.vlan is not None]
    if tagged:
        tags = sorted({p.vlan for p in tagged if p.vlan is not None})
        out.append(f"кадры уходят с тегом {tags} - оба порта должны пропускать "
                   f"этот VLAN; на access-порту чужого тега трафик умрёт на входе")
    elif packets:
        tag = iface_tag(result.tx_iface)
        if tag is not None:
            out.append(f"в профиле тега нет, но отправка идёт с "
                       f"{result.tx_iface} - тег {tag} навешивает ядро, и "
                       f"пропускать оба порта должны именно его")
        else:
            out.append("кадры уходят без тега - если порты в trunk без native "
                       "VLAN, нетегированный кадр отбрасывается на входе")

    dsts = {p.eth_dst.lower() for p in packets}
    unicast = {d for d in dsts if d and not _is_group(d)}
    if unicast:
        out.append("назначение юникастовое - коробка не знает этот адрес, "
                   "пока он не побывал источником; проверь, что она его "
                   "флудит, а не гасит")

    sizes = {p.frame_size for p in packets}
    classic = sizes & set(CLASSIC_SIZES)
    if classic:
        out.append(f"размер кадра {sorted(classic)} - в traphy он считается "
                   f"без FCS, классический «64-байтный» прогон задаётся как 60")

    if result.engine == "trex" and result.rx_source == "port_counter":
        out.append("TRex не отдал flow stats и скатился на счётчик порта - "
                   "на virtio это обычное дело, на живой карте стоит смотреть, "
                   "почему группа потока не считается")

    return out


def _is_group(mac: str) -> bool:
    """True for broadcast and multicast - the low bit of the first octet."""
    head = mac.split(":")[0]
    try:
        return bool(int(head, 16) & 1)
    except ValueError:
        return False


def explain(result: RunResult, profile: Profile, target: Target) -> list[str]:
    """The whole answer, facts then suspicions, ready to print in order."""
    if result.dry_run:
        # Не отправить ни кадра - это и есть смысл холостого прогона, а не
        # находка. Советовать тут «задай интерфейс приёма», который задан,
        # значит научить человека пролистывать предупреждения не читая.
        return []
    if result.tx_pkts > 0 and result.rx_pkts > 0:
        return []
    out = [f"· {line}" for line in established(result)]
    checks = worth_checking(result, profile, target)
    if checks:
        out.append("проверить, в этом порядке:")
        out.extend(f"  - {line}" for line in checks)
    return out
