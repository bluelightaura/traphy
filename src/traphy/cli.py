"""The command line: the menu by default, and the same work without it.

Running ``traphy`` with no arguments opens the launcher, which is how the tool
is meant to be used - compose by hand, connect, send. The subcommands exist so
the same profiles are usable from a script or a CI job: generate a file, run a
saved profile against a named target, ask a target what it has.

Everything a subcommand does is something the menu does too, through the same
functions. There is no second implementation to drift.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traphy import __version__, codegen, menu, presets
from traphy.models import Profile
from traphy.probe import inspect
from traphy.runner import RunSpec, execute, recent_runs
from traphy.target import Target, TargetStore
from traphy.transport import TransportError, open_transport


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

    gen = sub.add_parser("gen", help="сгенерировать Scapy-скрипт")
    gen.add_argument("profile", help="имя пресета или путь к profile.json")
    gen.add_argument("-o", "--out", metavar="FILE",
                     help="куда записать (по умолчанию - в stdout)")

    run = sub.add_parser("run", help="прогнать профиль на цели")
    run.add_argument("profile", help="имя пресета или путь к profile.json")
    run.add_argument("-t", "--target", default="", help="имя сохранённой цели")
    run.add_argument("-d", "--duration", type=float, default=10.0, help="секунд")
    run.add_argument("--pps", type=float, default=0.0, help="общая цель по pps")
    run.add_argument("--dry-run", action="store_true",
                     help="собрать кадры, ничего не слать")
    run.add_argument("--json", action="store_true", help="результат как JSON")

    probe = sub.add_parser("probe", help="что есть на цели: интерфейсы, root, scapy")
    probe.add_argument("-t", "--target", default="", help="имя сохранённой цели")
    probe.add_argument("--json", action="store_true")

    sub.add_parser("presets", help="список пресетов")
    sub.add_parser("targets", help="список сохранённых целей")

    history = sub.add_parser("history", help="прошлые прогоны")
    history.add_argument("-n", type=int, default=10, help="сколько показать")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = {
        None: lambda a: menu.run(__version__, Path(a.profiles)),
        "gen": cmd_gen,
        "run": cmd_run,
        "probe": cmd_probe,
        "presets": cmd_presets,
        "targets": cmd_targets,
        "history": cmd_history,
    }[args.command]
    return handler(args)


# --------------------------------------------------------------------------- #
def load_profile(name: str, profile_dir: Path) -> Profile:
    """A profile by preset key, by path, or by name inside the profiles dir.

    Raises SystemExit with a usable message rather than a traceback: this is
    the first thing every subcommand does, and "no such preset" deserves a line,
    not a stack.
    """
    if name in presets.PRESETS:
        return presets.build(name)
    for candidate in (Path(name), profile_dir / name, profile_dir / f"{name}.json"):
        if candidate.is_file():
            try:
                return Profile.load(candidate)
            except (OSError, ValueError) as exc:
                raise SystemExit(f"{candidate}: не читается - {exc}") from exc
    known = ", ".join(presets.keys())
    raise SystemExit(f"не нашёл профиль «{name}». Пресеты: {known}")


def load_target(name: str) -> Target:
    """A saved target by name, or the seeded local one when nothing is named."""
    store = TargetStore()
    if not name:
        return store.ensure_seed()
    found = store.try_load(name)
    if found is None:
        known = ", ".join(store.list()) or "нет ни одной"
        raise SystemExit(f"не нашёл цель «{name}». Сохранённые: {known}")
    return found


# --------------------------------------------------------------------------- #
def cmd_gen(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, Path(args.profiles))
    problems = profile.validate()
    if problems:
        for problem in problems:
            print(f"! {problem}", file=sys.stderr)
        return 2
    text = codegen.generate(profile)
    if not args.out:
        sys.stdout.write(text)
        return 0
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    print(f"записано: {path}  ({codegen.frame_count(profile)} кадров)")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, Path(args.profiles))
    target = load_target(args.target)
    spec = RunSpec(duration=args.duration, pps=args.pps, dry_run=args.dry_run,
                   save_pcap=True)
    try:
        result = execute(profile, target, spec, on_event=_echo)
    except TransportError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(result.summary())
        for warning in result.warnings():
            print(f"  ! {warning}", file=sys.stderr)
    return result.rc


def _echo(event: dict) -> None:
    """Mirror the run's progress on stderr so stdout stays the result."""
    if event.get("ev") == "tick":
        print(f"  {event.get('t', 0):5.1f} c  tx={event.get('tx', 0)}"
              f"  rx={event.get('rx', 0)}  {event.get('pps', 0):.0f} pps",
              file=sys.stderr)


def cmd_probe(args: argparse.Namespace) -> int:
    target = load_target(args.target)
    try:
        transport = open_transport(target)
    except TransportError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 3
    try:
        info = inspect(transport)
    finally:
        transport.close()

    if args.json:
        print(json.dumps({
            "ok": info.ok, "error": info.error, "hostname": info.hostname,
            "kernel": info.kernel, "python": info.python,
            "has_scapy": info.has_scapy, "scapy_version": info.scapy_version,
            "is_root": info.is_root, "can_sudo": info.can_sudo,
            "ifaces": [vars(i) for i in info.ifaces],
        }, ensure_ascii=False, indent=2))
        return 0 if info.ok else 3

    if not info.ok:
        print(f"! {info.error}", file=sys.stderr)
        return 3
    print(f"{info.hostname} · {info.kernel} · python {info.python}")
    print("scapy: " + (info.scapy_version if info.has_scapy else "нет"))
    print("root: " + ("да" if info.is_root else
                      "нет, sudo без пароля" if info.can_sudo else "нет"))
    for iface in info.usable_ifaces():
        print(f"  {iface.name:<16} {iface.describe()}")
    for blocker in info.blockers():
        print(f"  ! {blocker}", file=sys.stderr)
    return 0


def cmd_presets(_args: argparse.Namespace) -> int:
    for key, (title, hint, _fn) in presets.PRESETS.items():
        print(f"{key:<14} {title:<18} {hint}")
    return 0


def cmd_targets(_args: argparse.Namespace) -> int:
    store = TargetStore()
    names = store.list()
    if not names:
        print("сохранённых целей нет - открой меню и настрой первую")
        return 0
    for name in names:
        target = store.try_load(name)
        print(f"{name:<16} {target.endpoint() if target else 'не читается'}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    runs = recent_runs(args.n)
    if not runs:
        print("прогонов ещё не было")
        return 0
    for run in runs:
        loss = (f"потери {run.get('loss_pct', 0):.2f}%" if run.get("reliable")
                else "приём не мерян")
        print(f"{str(run.get('started_at', ''))[:16]}  "
              f"{run.get('profile', '')!s:<14} tx={run.get('tx_pkts', 0):<10} {loss}")
    return 0
