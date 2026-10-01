"""Turning a name on the command line into the thing it names.

Both lookups fail with a line rather than a traceback, and both say what *is*
available when they do. This is the first thing every subcommand does, and
"нет такого пресета" followed by the list of presets is the difference between
one more keystroke and a trip to the README.
"""

from __future__ import annotations

from pathlib import Path

from traphy import presets
from traphy.models import Profile
from traphy.target import Target, TargetStore


def load_profile(name: str, profile_dir: Path) -> Profile:
    """A profile by preset key, by path, or by name inside the profiles dir."""
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
