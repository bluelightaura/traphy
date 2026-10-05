#!/usr/bin/env python3
"""Перерисовать середину баннера: кадр и три способа положить его в провод.

Раньше там был радар - красиво, но ни о чём: он ничего не говорил про то, чем
инструмент стал. Теперь в середине то, что и отличает TRaphy от «скрипта со
Scapy»: кадр собирается один, а уехать в провод может тремя разными путями, и
плотность точек на проводах показывает, чем за это платят.

Остальной баннер не трогается - заголовок, подпись, левый блок и список
пресетов остаются как были. Скрипт идемпотентный: гоняется поверх исходника.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
BANNER = ROOT / "assets" / "traphy-banner.png"

BG = (0, 0, 0)
BLUE = (46, 139, 255)
LIGHT = (230, 230, 230)
DIM = (114, 114, 114)
DEEP = (14, 46, 88)

# Та часть холста, где был круг с выносками. Границы сняты с исходника.
AREA = (230, 420, 695, 815)

MONO = "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf"
MONO_BOLD = "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Bold.ttf"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(MONO_BOLD if bold else MONO, size)


def draw_frame(d: ImageDraw.ImageDraw, x: int, y: int) -> int:
    """Кадр как он собирается: заголовки слоями, слева направо."""
    parts = [("ETH", 62), ("VLAN", 66), ("IP", 48), ("UDP", 58), ("payload", 104)]
    d.text((x, y - 26), "frame", font=font(19), fill=DIM)
    cursor = x
    for i, (name, width) in enumerate(parts):
        filled = i < 4                       # заголовки ярче полезной нагрузки
        d.rectangle([cursor, y, cursor + width, y + 34],
                    outline=BLUE if filled else DIM, width=2,
                    fill=DEEP if filled else None)
        text = font(16, bold=filled)
        tw = d.textlength(name, font=text)
        d.text((cursor + (width - tw) / 2, y + 9), name, font=text,
               fill=LIGHT if filled else DIM)
        cursor += width + 4
    return cursor


def draw_wire(d: ImageDraw.ImageDraw, x: int, y: int, width: int,
              label: str, note: str, step: int, bright: bool) -> None:
    """Провод с кадрами. Чем плотнее точки, тем выше скорость."""
    colour = BLUE if bright else DIM
    d.line([x, y, x + width, y], fill=DEEP if not bright else colour, width=1)
    for pos in range(x + 6, x + width - 4, step):
        d.rectangle([pos, y - 4, pos + 5, y + 4], fill=colour)
    d.text((x, y - 30), label, font=font(17, bold=bright), fill=colour)
    d.text((x + width + 12, y - 9), note, font=font(15), fill=DIM)


def main() -> int:
    if not BANNER.exists():
        print(f"нет файла {BANNER}", file=sys.stderr)
        return 1
    im = Image.open(BANNER).convert("RGB")
    d = ImageDraw.Draw(im)

    # Снести прежнюю середину вместе с выносками.
    d.rectangle(list(AREA), fill=BG)

    left, top = AREA[0] + 18, AREA[1] + 6
    end = draw_frame(d, left, top + 34)

    # Стрелка от кадра вниз, к проводам: один кадр - три пути.
    mid = (left + end) // 2
    d.line([mid, top + 76, mid, top + 104], fill=BLUE, width=2)
    d.polygon([(mid - 6, top + 102), (mid + 6, top + 102), (mid, top + 114)],
              fill=BLUE)

    d.text((left, top + 126), "engines:", font=font(19), fill=BLUE)

    wires = [
        ("scapy", "kernel", 46, False),
        ("af_packet", "~1 Mpps", 22, False),
        ("dpdk", "line rate", 10, True),
    ]
    y = top + 186
    for label, note, step, bright in wires:
        draw_wire(d, left, y, 240, label, note, step, bright)
        y += 74

    # 256 цветов, как у остальных баннеров: PNG от этого втрое легче, а на
    # чёрном фоне с двумя акцентами потерять нечего.
    im.quantize(colors=256, method=Image.MEDIANCUT).save(BANNER, optimize=True)
    print(f"перерисовано: {BANNER.relative_to(ROOT)} {im.size}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
