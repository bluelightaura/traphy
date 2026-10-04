"""What each subcommand actually does.

One handler per command, and every one of them is a thin call into the same
functions the menu uses. There is no second implementation to drift: a
subcommand that behaved differently from the screen doing the same thing would
be a bug nobody would find until a CI job disagreed with an operator.

stdout carries the result, stderr carries everything about it. That split is
what makes ``traphy run … --json | jq`` work while the run is still narrating
itself into the terminal.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traphy import codegen, engines, presets
from traphy.cli.resolve import load_profile, load_target
from traphy.probe import inspect
from traphy.runner import (
    RunSpec,
    execute,
    explain_zero,
    parse_event,
    recent_runs,
)
from traphy.transport import ssh_password, sudo_password
from traphy.target import TargetStore
from traphy.transport import TransportError, open_transport


def cmd_gen(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, Path(args.profiles))
    problems = profile.validate()
    if problems:
        for problem in problems:
            print(f"! {problem}", file=sys.stderr)
        return 2
    engine = engines.get(args.engine)
    try:
        text = engine.generate(profile, tag=codegen.DEFAULT_TAG)
    except engines.EngineNotReady as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    for warning in engine.warnings(profile):
        print(f"! {warning}", file=sys.stderr)
    if not args.out:
        sys.stdout.write(text)
        return 0
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    print(f"записано: {path}  ({engine.frame_count(profile)} кадров)")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, Path(args.profiles))
    target = load_target(args.target)
    spec = RunSpec(duration=args.duration, pps=args.pps, dry_run=args.dry_run,
                   count=args.count, capture=not args.no_capture,
                   capture_limit=args.capture_limit, force=args.force)
    # Откуда именно полетит - первым делом и на stderr, чтобы в конвейере
    # остался только результат. Два режима Scapy различаются здесь и нигде
    # больше: локально скрипт исполняется тут же, по SSH - на той машине.
    print(f"режим: {target.endpoint()}", file=sys.stderr)
    try:
        result = execute(profile, target, spec, on_event=_echo,
                         password=ssh_password(), sudo_password=sudo_password())
    except TransportError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(result.summary())
        print(f"  транспорт: {result.transport}", file=sys.stderr)
        # Всё, что прогон сказал вслух по ходу дела. Раньше этого в CLI не было
        # вовсе: отъём портов, пустая запись, незапустившийся захват - каждая
        # такая фраза доезжала только до архива и до панели в меню, а человек
        # с терминалом узнавал о них в лучшем случае потом.
        for said in result.notes:
            print(f"  · {said}", file=sys.stderr)
        if result.captures:
            for name in sorted(result.captures):
                print(f"  дамп {name}: {result.captures[name]}", file=sys.stderr)
        for warning in result.warnings():
            print(f"  ! {warning}", file=sys.stderr)
        # A zero is never left bare. The reasoning goes to stderr with the rest
        # of the commentary so a piped run still yields only its result.
        for line in explain_zero(result, profile, target):
            print(f"  {line}", file=sys.stderr)
    return result.rc


def _echo(event: dict) -> None:
    """Mirror the run's progress on stderr so stdout stays the result."""
    kind = event.get("ev")
    if kind == "tick":
        print(f"  {event.get('t', 0):5.1f} c  tx={event.get('tx', 0)}"
              f"  rx={event.get('rx', 0)}  {event.get('pps', 0):.0f} pps",
              file=sys.stderr)
    elif kind in ("note", "error"):
        # Сказанное по ходу прогона печатается тогда же, когда сказано.
        # Дождаться итога тут мало: прогон, оборвавшийся после такой фразы,
        # уносил её с собой.
        said = str(event.get("msg", "")).strip()
        if said:
            print(f"  · {said}", file=sys.stderr)


def cmd_recover(args: argparse.Namespace) -> int:
    """Убрать за прогоном, который не убрал за собой.

    Отдельная команда, а не флаг прогона, потому что это и не прогон: ничего не
    отправляется, и профиль тут ни при чём. Нужна она ровно для одного случая -
    прогон убили сигналом или оборвали SSH, его ``finally`` не исполнился, и на
    машине остались занятые порты, включённый сервисный режим и живая запись.
    Следующий человек видит отказ, к его работе отношения не имеющий.
    """
    target = load_target(args.target)
    engine = engines.get(target.engine)
    if not engine.can_recover:
        print(f"! «{engine.title}» убирать за прогоном не умеет: у него нет ни "
              f"следа аренды на той машине, ни владения портами", file=sys.stderr)
        return 2
    spec = RunSpec(recover=True, archive=False, capture=False)
    # Артефакт тот же, что у прогона: уборка - его отдельный режим, а не второй
    # скрипт, который пришлось бы поддерживать отдельно. Профиль ему при этом не
    # нужен ни для чего - до сборки потоков дело не доходит, - поэтому берётся
    # самый простой.
    script = engine.generate(presets.build("l2_ethernet"),
                             tag=codegen.DEFAULT_TAG)
    print(f"режим: {target.endpoint()}", file=sys.stderr)
    try:
        transport = open_transport(target, password=ssh_password())
    except TransportError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 3

    def say(line: str) -> None:
        event = parse_event(line)
        if event is not None:
            _echo(event)

    try:
        completed = transport.run_stream(
            script, engine.args(target, spec, None), say, timeout=120,
            sudo=target.use_sudo and engine.needs_root(spec),
            secret=sudo_password())
    except TransportError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 3
    finally:
        transport.close()
    return completed.rc


def cmd_probe(args: argparse.Namespace) -> int:
    target = load_target(args.target)
    try:
        transport = open_transport(target, password=ssh_password())
    except TransportError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 3
    try:
        info = inspect(transport, trex_dir=target.trex_dir)
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
    # The target's own engine judges, not Scapy by default: telling a TRex
    # host it is missing Scapy and root is noise, and noise in this list is
    # how the real blocker underneath it gets skipped over.
    for blocker in info.blockers(target.engine):
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
