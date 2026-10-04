"""The handful of answers the launcher should not ask twice.

Language, theme, which target was last worked on, and a short run history. All
of it is per-person UI memory, so it lives under the XDG state directory rather
than in the working tree - the same reasoning as CLIRadar's: this is not project
configuration and it must never turn up in a commit.

Nothing secret is written. A target *name*, two preference words and a few run
stamps are all already visible on the screen that saves them; the file staying
readable is the point. Every read and write is best-effort - a missing or
hand-mangled state file degrades to the defaults instead of taking the menu
down on start-up.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from traphy.target import state_dir

# How many past runs to keep: enough to answer "what did I just do", short
# enough that the launcher stays a glance rather than a log.
MAX_RUNS = 6

# How many past values to keep per field. Five is the number that fits under a
# field without the list becoming something to read: the point is recognising
# the address typed last week, not browsing a log of everything ever entered.
MAX_RECENT = 5

LANGS = ("ru", "en")
THEMES = ("dark", "light")

# Поля, значения которых не запоминаются вовсе. Это ключи полей формы цели, и
# всё, что в них вводят, - инвентарь стенда: адрес машины, логин, путь к ключу
# (а в нём ещё и домашний каталог), адрес демона, адрес шасси и API-сервера.
#
# Почему решено не запоминать, а не «дать способ забыть»: список прошлых значений
# показывается на экране при правке поля («вводилось раньше»), то есть снимок
# формы выносит наружу перечень машин - и выносит тем вернее, чем аккуратнее
# человек работал. Забывать пришлось бы вручную и до скриншота, а не после.
# Собственного смысла у этой памяти тут нет: адрес и логин хранит сама цель, и
# между машинами переключаются выбором цели, а не перенабором адреса. Для пароля
# это уже сделано одним флагом remember=False - здесь то же решение.
#
# Две точки исполнения: форма цели снимает с этих полей remember (см.
# traphy.screens.connect._fields), а :func:`forget_values` на старте выметает то,
# что успела записать прежняя версия - иначе уже записанное жило бы на экране
# дальше, и «мы это больше не храним» было бы правдой только для новых значений.
NEVER_REMEMBERED = ("host", "ssh_user", "ssh_key", "trex_server",
                    "ixia_api", "ixia_user", "ixia_chassis",
                    # Адреса кадра - это инвентарь устройства под тестом, а не
                    # удобство: MAC коробки и адреса её плеч запоминались так же
                    # охотно, как адрес генератора, и так же показывались на
                    # экране списком «вводилось раньше». Концы диапазона (min,
                    # max) туда же - это те же адреса, только парой.
                    "eth_src", "eth_dst", "ip_src", "ip_dst", "min", "max")

_DEFAULTS: dict[str, Any] = {
    "lang": "ru",
    "theme": "dark",
    "target": "",
    "profile": "",
    "runs": [],
    # Per-field: values this person has entered before, newest first. UI memory
    # like everything else here, and never anything secret - a field marked as
    # such is not remembered at all.
    "recent": {},
}


def state_path() -> Path:
    return state_dir() / "menu.json"


def load_prefs() -> dict[str, Any]:
    """The saved preferences, with defaults filled in for anything missing.

    The file is written by this process and nobody else, and is still treated
    as untrusted: a value of the wrong type is dropped for the default rather
    than reaching the render code and crashing a screen.
    """
    prefs = dict(_DEFAULTS)
    prefs["runs"] = []
    prefs["recent"] = {}
    try:
        raw = json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return prefs
    if not isinstance(raw, dict):
        return prefs
    if raw.get("lang") in LANGS:
        prefs["lang"] = raw["lang"]
    if raw.get("theme") in THEMES:
        prefs["theme"] = raw["theme"]
    for key in ("target", "profile"):
        if isinstance(raw.get(key), str):
            prefs[key] = raw[key]
    prefs["runs"] = _clean_runs(raw.get("runs"))
    prefs["recent"] = _clean_recent(raw.get("recent"))
    return prefs


def _clean_runs(runs: Any) -> list[dict[str, str]]:
    if not isinstance(runs, list):
        return []
    out: list[dict[str, str]] = []
    for item in runs[:MAX_RUNS]:
        if isinstance(item, dict) and item.get("profile"):
            out.append({
                "profile": str(item.get("profile", "")),
                "at": str(item.get("at", "")),
                "summary": str(item.get("summary", "")),
            })
    return out


def _clean_recent(recent: Any) -> dict[str, list[str]]:
    """Past values per field, with anything of the wrong shape dropped.

    Read defensively for the same reason as the rest of this file: the state
    file is ours, and a hand-edited one must degrade to "nothing remembered"
    rather than reach the chooser and take a screen down.
    """
    if not isinstance(recent, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, values in recent.items():
        if not isinstance(key, str) or not isinstance(values, list):
            continue
        kept = [v for v in values if isinstance(v, str) and v.strip()]
        if kept:
            out[key] = kept[:MAX_RECENT]
    return out


def remember_value(prefs: dict[str, Any], key: str, value: str) -> dict[str, Any]:
    """Push a value onto the front of one field's list, newest first.

    Re-entering a value moves it up rather than duplicating it: the list is
    "what you use", and a value used twice is more likely, not less.

    Which fields get here at all is the form's call - see :data:`NEVER_REMEMBERED`
    and ``Field.remember``. This end stays a plain list, so there is one place
    that decides and one that stores.
    """
    value = (value or "").strip()
    if not key or not value:
        return prefs
    recent = _clean_recent(prefs.get("recent"))
    values = [v for v in recent.get(key, []) if v != value]
    values.insert(0, value)
    recent[key] = values[:MAX_RECENT]
    prefs["recent"] = recent
    return prefs


def forget_values(prefs: dict[str, Any], *keys: str) -> bool:
    """Drop what was entered into these fields. True when something was there.

    The return value is what tells the caller whether the state file needs
    rewriting: sweeping on every start-up must not rewrite the file every
    start-up, or "nothing changed" stops being visible in its timestamp.

    With no keys given it forgets every field - the whole "entered before"
    memory, which is the one request that cannot be served by editing a list.
    """
    recent = _clean_recent(prefs.get("recent"))
    wanted = set(keys) if keys else set(recent)
    dropped = {key: values for key, values in recent.items() if key not in wanted}
    prefs["recent"] = dropped
    return len(dropped) != len(recent)


def save_prefs(prefs: dict[str, Any]) -> bool:
    """Persist the preferences. False when the write could not happen.

    Written to a sibling temp file and moved into place, so an interrupted
    write leaves the previous state intact instead of a half-file.
    """
    path = state_path()
    payload = {key: prefs.get(key, _DEFAULTS[key]) for key in _DEFAULTS}
    payload["runs"] = _clean_runs(payload.get("runs"))
    payload["recent"] = _clean_recent(payload.get("recent"))
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        tmp.replace(path)
    except OSError:
        return False
    return True


def remember_run(prefs: dict[str, Any], profile: str, at: str,
                 summary: str = "") -> dict[str, Any]:
    """Push a finished run onto the front of the history, newest first.

    Pure on purpose: the caller decides when to save, and supplies the stamp
    rather than having this read the clock, which keeps it testable and puts
    the formatting in one place.
    """
    runs = [dict(item) for item in prefs.get("runs", []) if isinstance(item, dict)]
    runs.insert(0, {"profile": profile, "at": at, "summary": summary})
    prefs["runs"] = runs[:MAX_RUNS]
    return prefs
