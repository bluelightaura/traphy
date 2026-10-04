"""Argument parsing, and nothing else.

No network, no frame building, no engine work happens while a command line is
being read. That is worth stating because it is easy to lose: one convenience
import at the top of this module and ``traphy --help`` starts opening sockets
to answer a question about syntax. The subcommands import what they need when
they are actually called.
"""

from __future__ import annotations

import argparse

from traphy import __version__, engines


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="traphy",
        description="Собрать трафик руками, погнать его скриптом.",
        epilog="Без аргументов открывается меню.",
    )
    ap.add_argument("--version", action="version", version=f"traphy {__version__}")
    ap.add_argument("--profiles", metavar="DIR", default="profiles",
                    help="где лежат сохранённые профили (по умолчанию: profiles)")
    sub = ap.add_subparsers(dest="command")

    gen = sub.add_parser("gen", help="сгенерировать скрипт прогона")
    gen.add_argument("profile", help="имя пресета или путь к profile.json")
    gen.add_argument("--engine", default=engines.DEFAULT,
                     choices=sorted(engines.REGISTRY),
                     help="чем гнать: это решает, какой артефакт собирается")
    gen.add_argument("-o", "--out", metavar="FILE",
                     help="куда записать (по умолчанию - в stdout)")

    run = sub.add_parser("run", help="прогнать профиль на цели")
    run.add_argument("profile", help="имя пресета или путь к profile.json")
    run.add_argument("-t", "--target", default="", help="имя сохранённой цели")
    run.add_argument("-d", "--duration", type=float, default=10.0, help="секунд")
    run.add_argument("--pps", type=float, default=0.0, help="общая цель по pps")
    run.add_argument("-c", "--count", type=int, default=0,
                     help="всего кадров; отменяет --duration")
    run.add_argument("--dry-run", action="store_true",
                     help="собрать кадры, ничего не слать")
    run.add_argument("--no-capture", action="store_true",
                     help="не записывать кадры - запись занижает потолок "
                          "скорости, для предельного замера её выключают")
    run.add_argument("--capture-limit", type=int, default=1000,
                     help="сколько кадров записать на сторону (по умолчанию 1000)")
    run.add_argument("--force", action="store_true",
                     help="отобрать порт у чужого прогона - только на этот "
                          "раз, в цель не записывается")
    run.add_argument("--json", action="store_true", help="результат как JSON")

    recover = sub.add_parser(
        "recover",
        help="убрать за прогоном, который не убрал за собой: порты, "
             "сервисный режим, записи")
    recover.add_argument("-t", "--target", default="",
                         help="имя сохранённой цели")

    probe = sub.add_parser("probe", help="что есть на цели: интерфейсы, root, scapy")
    probe.add_argument("-t", "--target", default="", help="имя сохранённой цели")
    probe.add_argument("--json", action="store_true")

    sub.add_parser("presets", help="список пресетов")
    sub.add_parser("targets", help="список сохранённых целей")

    history = sub.add_parser("history", help="прошлые прогоны")
    history.add_argument("-n", type=int, default=10, help="сколько показать")
    return ap
