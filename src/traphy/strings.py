"""Every piece of text the screens show, Russian and English side by side.

One table, keyed by a short id. :func:`t` falls back to Russian and then to the
key itself, so a string added to one language and forgotten in the other shows
up as a visible key rather than a crash or an empty row.

Russian is the default because that is the language the tool is used in; the
English column exists so the launcher's toggle is real rather than decorative.
"""

from __future__ import annotations

_LANG = {"cur": "ru"}


def set_lang(lang: str) -> None:
    if lang in ("ru", "en"):
        _LANG["cur"] = lang


def lang() -> str:
    return _LANG["cur"]


def toggle_lang() -> str:
    set_lang("en" if _LANG["cur"] == "ru" else "ru")
    return _LANG["cur"]


def t(key: str, **fmt: object) -> str:
    """The string for ``key`` in the current language, formatted if asked."""
    entry = S.get(key)
    if not entry:
        return key
    text = entry.get(_LANG["cur"]) or entry.get("ru") or key
    return text.format(**fmt) if fmt else text


S: dict[str, dict[str, str]] = {
    # ---- launcher chrome ---------------------------------------------- #
    "tagline": {"ru": "собрать трафик руками - погнать его скриптом",
                "en": "compose traffic by hand - send it as a script"},
    "target": {"ru": "Цель: ", "en": "Target: "},
    "profile": {"ru": "Профиль: ", "en": "Profile: "},
    "no_target": {"ru": "цель не настроена", "en": "no target set"},
    "no_profile": {"ru": "трафик не собран", "en": "nothing composed yet"},
    "reachable": {"ru": "связь есть", "en": "reachable"},
    "unreachable": {"ru": "связи нет", "en": "unreachable"},
    "unchecked": {"ru": "связь не проверена", "en": "not checked"},
    "last_run": {"ru": "прошлый прогон", "en": "last run"},
    "locked": {"ru": "сначала проверь связь с целью",
               "en": "check the target first"},

    # ---- launcher rows ------------------------------------------------ #
    "setup_title": {"ru": "Настроить цель", "en": "Set up target"},
    "setup_hint": {"ru": "хост, интерфейсы, связь", "en": "host, NICs, reach"},
    "compose_title": {"ru": "Собрать трафик", "en": "Compose traffic"},
    "compose_hint": {"ru": "пресет или по слоям", "en": "preset or layer by layer"},
    "streams_title": {"ru": "Потоки профиля", "en": "Profile streams"},
    "streams_hint": {"ru": "править, включать, диапазоны",
                     "en": "edit, toggle, ranges"},
    "script_title": {"ru": "Показать скрипт", "en": "Show the script"},
    "script_hint": {"ru": "то, что уйдёт на хост", "en": "what ships to the host"},
    "run_title": {"ru": "Запустить", "en": "Run it"},
    "run_hint": {"ru": "погнать трафик и смотреть счётчики",
                 "en": "send and watch the counters"},
    "dry_title": {"ru": "Сухой прогон", "en": "Dry run"},
    "dry_hint": {"ru": "собрать кадры, ничего не слать",
                 "en": "build frames, send nothing"},
    "save_title": {"ru": "Сохранить скрипт", "en": "Save the script"},
    "save_hint": {"ru": "положить .py рядом", "en": "write the .py out"},
    "history_title": {"ru": "История прогонов", "en": "Run history"},
    "history_hint": {"ru": "что и когда гнали", "en": "what ran, and when"},
    "lang_title": {"ru": "Язык", "en": "Language"},
    "theme_title": {"ru": "Тема", "en": "Theme"},
    "theme_dark": {"ru": "тёмная", "en": "dark"},
    "theme_light": {"ru": "светлая", "en": "light"},

    # ---- key hints ---------------------------------------------------- #
    "keys_main": {"ru": "↑/↓ выбор   ↵ пуск   q выход",
                  "en": "↑/↓ move   ↵ go   q quit"},
    "pick_target": {"ru": "Какая цель?", "en": "Which target?"},
    "keys_pick": {"ru": "↑/↓ выбор   ↵ ок   q назад",
                  "en": "↑/↓ move   ↵ ok   q back"},
    "keys_form": {"ru": "↑/↓ поле   ↵ править   t цель   c связь   "
                        "p спросить у цели   q назад",
                  "en": "↑/↓ field   ↵ edit   t target   c check   "
                        "p ask the target   q back"},
    "keys_streams": {"ru": "↑/↓ поток   ↵ править   space вкл/выкл   d удалить   q назад",
                     "en": "↑/↓ stream   ↵ edit   space on/off   d delete   q back"},
    "keys_scroll": {"ru": "↑/↓ строка   PgUp/PgDn страница   q назад",
                    "en": "↑/↓ line   PgUp/PgDn page   q back"},
    "keys_any": {"ru": "любая клавиша - назад", "en": "any key - back"},
    # Почему строка меню заперта движком. Своё поле `status` у движка есть, но
    # оно только по-русски, а замок обязан читаться на обоих языках.
    "engine_locked": {"ru": "движок не умеет слать - выбери другой",
                      "en": "this engine cannot send - pick another"},
    "keys_run": {"ru": "Ctrl-C - прервать прогон", "en": "Ctrl-C - stop the run"},

    # ---- target form -------------------------------------------------- #
    "form_title": {"ru": "Цель - куда ставить генератор",
                   "en": "Target - where traffic comes from"},
    "f_name": {"ru": "имя цели", "en": "target name"},
    "f_engine": {"ru": "чем гнать", "en": "engine"},
    "engine_pick": {"ru": "Движок", "en": "Engine"},
    "engine_soon": {"ru": "выбран, но ещё не реализован - гнать нечем",
                    "en": "selected, but not implemented yet"},
    "f_use_ssh": {"ru": "машина", "en": "machine"},
    "f_host": {"ru": "адрес", "en": "host"},
    "f_ssh_user": {"ru": "логин SSH", "en": "SSH user"},
    "f_ssh_port": {"ru": "порт SSH", "en": "SSH port"},
    "f_ssh_key": {"ru": "ключ SSH", "en": "SSH key"},
    "f_strict": {"ru": "ключ хоста", "en": "host key"},
    "f_fingerprint": {"ru": "закреплённый отпечаток", "en": "pinned fingerprint"},
    "f_python": {"ru": "python на хосте", "en": "python on host"},
    "f_sudo": {"ru": "запускать через sudo", "en": "run under sudo"},
    "f_tx": {"ru": "интерфейс отправки", "en": "TX interface"},
    "f_rx": {"ru": "интерфейс приёма", "en": "RX interface"},
    "f_link": {"ru": "скорость линии, Мбит/с", "en": "link rate, Mbit/s"},
    "f_trex_dir": {"ru": "каталог TRex на цели", "en": "TRex directory"},
    "f_trex_server": {"ru": "демон TRex", "en": "TRex daemon"},
    "f_trex_sync": {"ru": "порт управления TRex", "en": "TRex sync port"},
    "f_trex_tx": {"ru": "порт отправки TRex", "en": "TRex TX port"},
    "f_trex_rx": {"ru": "порт приёма TRex", "en": "TRex RX port"},
    "trex_rx_unset": {"ru": "не задан - потери мерить нечем",
                      "en": "unset - loss cannot be measured"},
    "f_ixia_api": {"ru": "API-сервер IxNetwork", "en": "IxNetwork API server"},
    "f_ixia_api_port": {"ru": "порт API", "en": "API port"},
    "f_ixia_user": {"ru": "логин API", "en": "API user"},
    "f_ixia_chassis": {"ru": "адрес шасси", "en": "chassis"},
    "f_ixia_tx": {"ru": "порт отправки, карта/порт", "en": "TX port, card/port"},
    "f_ixia_rx": {"ru": "порт приёма, карта/порт", "en": "RX port, card/port"},
    "f_ixia_force": {"ru": "отбирать занятый порт", "en": "force port ownership"},
    "f_trex_force": {"ru": "отбирать занятый порт", "en": "force port ownership"},
    "yes": {"ru": "да", "en": "yes"},
    "no": {"ru": "нет", "en": "no"},
    "unset": {"ru": "не задан", "en": "unset"},
    "l_approx": {"ru": "приблизительно", "en": "approximate"},
    # Разделы главного меню. Плоский список из десяти строк не отвечал на
    # вопрос «что я вообще настраиваю»: цель, кадр и прогон лежали вперемешку.
    "sec_gen": {"ru": "ГЕНЕРАТОР - чем и откуда шлём",
                "en": "GENERATOR - what sends, and from where"},
    "sec_what": {"ru": "ЧТО ОТПРАВЛЯЕМ", "en": "WHAT WE SEND"},
    "sec_run": {"ru": "ПРОГОН", "en": "THE RUN"},
    "sec_view": {"ru": "ВИД", "en": "LOOK"},
    "f_ssh_password": {"ru": "пароль SSH", "en": "SSH password"},
    "pw_set": {"ru": "задан на этот сеанс", "en": "set for this session"},
    "pw_env": {"ru": "из TRAPHY_SSH_PASSWORD", "en": "from TRAPHY_SSH_PASSWORD"},
    "pw_unset": {"ru": "не задан - ключ или агент", "en": "unset - key or agent"},
    # Откуда уходят кадры. Два варианта названы словами, а не «да/нет»:
    # «use ssh: нет» не отвечает на вопрос «а откуда тогда».
    "w_local": {"ru": "с этой машины", "en": "from this machine"},
    "w_local_hint": {"ru": "кадры летят с карты этого компьютера",
                     "en": "frames leave this computer's own NIC"},
    "w_ssh": {"ru": "с другой машины по SSH", "en": "from another machine over SSH"},
    "w_ssh_hint": {"ru": "скрипт уезжает туда, кадры летят с её карты",
                   "en": "the script ships there and sends from its NIC"},
    # Выборка значения поля: обычное, вводившееся раньше, и ручной ввод.
    "v_standard": {"ru": "обычное значение", "en": "usual value"},
    "v_recent": {"ru": "вводилось раньше", "en": "used before"},
    "v_current": {"ru": "сейчас в поле", "en": "current value"},
    "v_own": {"ru": "ввести своё…", "en": "type a new value…"},
    "v_own_hint": {"ru": "набрать вручную", "en": "type it in"},
    "keys_value": {"ru": "↑/↓ выбор   ↵ ок   буква - ввод   q назад",
                   "en": "↑/↓ pick   ↵ ok   a letter types   q back"},
    "rx_unset": {"ru": "не задан - потери мерить нечем",
                 "en": "unset - loss cannot be measured"},
    "checking": {"ru": "проверяю связь с {host}…", "en": "checking {host}…"},
    "saved_target": {"ru": "цель сохранена", "en": "target saved"},

    # ---- compose ------------------------------------------------------ #
    "compose_pick": {"ru": "С чего начать?", "en": "Where do we start?"},
    "from_preset": {"ru": "Из пресета", "en": "From a preset"},
    "from_preset_hint": {"ru": "готовый профиль, потом правь",
                         "en": "a ready profile, then edit"},
    "by_hand": {"ru": "По слоям", "en": "Layer by layer"},
    "by_hand_hint": {"ru": "шаг за шагом: слой → поля → скорость",
                     "en": "step by step: layer → fields → rate"},
    "load_saved": {"ru": "Загрузить сохранённый", "en": "Load a saved one"},
    "load_saved_hint": {"ru": "профиль из папки", "en": "a profile from disk"},
    "pick_preset": {"ru": "Пресет", "en": "Preset"},
    "step": {"ru": "шаг {n} из {total}", "en": "step {n} of {total}"},
    "w_layer": {"ru": "Какой трафик гоним?", "en": "What kind of traffic?"},
    "w_l2": {"ru": "L2 Ethernet", "en": "L2 Ethernet"},
    "w_l2_hint": {"ru": "коммутация, MAC-таблица", "en": "switching, MAC table"},
    "w_l3": {"ru": "L3 IPv4", "en": "L3 IPv4"},
    "w_l3_hint": {"ru": "маршрутизация, FIB", "en": "routing, FIB"},
    "w_l4": {"ru": "L4 UDP/TCP", "en": "L4 UDP/TCP"},
    "w_l4_hint": {"ru": "сессии, ACL, NAT", "en": "sessions, ACL, NAT"},
    "w_fields": {"ru": "Поля кадра", "en": "Frame fields"},
    "w_rate": {"ru": "Как быстро и как долго", "en": "How fast, how long"},
    "w_ranges": {"ru": "Что перебирать", "en": "What walks"},
    "w_no_range": {"ru": "ничего - фиксированный кадр",
                   "en": "nothing - a fixed frame"},
    "w_done": {"ru": "профиль собран: {name}", "en": "profile ready: {name}"},

    # ---- fields ------------------------------------------------------- #
    "p_name": {"ru": "имя потока", "en": "stream name"},
    "p_eth_src": {"ru": "MAC источника", "en": "source MAC"},
    "p_eth_dst": {"ru": "MAC назначения", "en": "destination MAC"},
    "p_vlan": {"ru": "VLAN (пусто - без тега)", "en": "VLAN (blank = untagged)"},
    "p_ip_src": {"ru": "IP источника", "en": "source IP"},
    "p_ip_dst": {"ru": "IP назначения", "en": "destination IP"},
    "p_ttl": {"ru": "TTL", "en": "TTL"},
    "p_proto": {"ru": "протокол", "en": "protocol"},
    "p_sport": {"ru": "порт источника", "en": "source port"},
    "p_dport": {"ru": "порт назначения", "en": "destination port"},
    "p_size": {"ru": "размер кадра, B", "en": "frame size, B"},
    "p_rate_type": {"ru": "единица скорости", "en": "rate unit"},
    "p_rate": {"ru": "скорость", "en": "rate"},
    "p_mode": {"ru": "режим отправки", "en": "TX mode"},
    "p_burst": {"ru": "пакетов в очереди", "en": "packets per burst"},
    "p_bursts": {"ru": "сколько очередей", "en": "number of bursts"},
    "p_ibg": {"ru": "пауза между очередями, мкс", "en": "inter-burst gap, µs"},
    "p_duration": {"ru": "сколько секунд гнать", "en": "seconds to send"},
    "m_continuous": {"ru": "непрерывно", "en": "continuous"},
    "m_single": {"ru": "одна очередь", "en": "single burst"},
    "m_multi": {"ru": "много очередей", "en": "multi burst"},
    "u_pps": {"ru": "пакетов/с", "en": "packets/s"},
    "u_bps": {"ru": "бит/с (L2)", "en": "bits/s (L2)"},
    "u_pct": {"ru": "% от линии", "en": "% of line"},

    # ---- streams screen ----------------------------------------------- #
    "streams_head": {"ru": "Потоки - «{name}»", "en": "Streams - “{name}”"},
    "add_stream": {"ru": "+ добавить поток", "en": "+ add a stream"},
    "profile_line": {"ru": "{name} · {on} из {all} потоков · {pps} pps",
                     "en": "{name} · {on} of {all} streams · {pps} pps"},
    "total_rate": {"ru": "всего {pps} pps, {frames} кадров",
                   "en": "{pps} pps total, {frames} frames"},
    "stream_off": {"ru": "выключен", "en": "off"},
    "confirm_delete": {"ru": "удалить поток «{name}»? (y/n)",
                       "en": "delete stream “{name}”? (y/n)"},
    "last_stream": {"ru": "это последний поток - удалять нечего",
                    "en": "that is the only stream - nothing to delete"},

    # ---- script ------------------------------------------------------- #
    "script_head": {"ru": "Скрипт - {name} ({lines} строк)",
                    "en": "Script - {name} ({lines} lines)"},
    "script_pager": {"ru": "строки {a}-{b} из {n}   ·   s сохранить   ·   {keys}",
                     "en": "lines {a}-{b} of {n}   ·   s save   ·   {keys}"},
    "script_saved": {"ru": "записано: {path}", "en": "written: {path}"},
    "script_where": {"ru": "куда сохранить (Enter - {default}): ",
                     "en": "where to save (Enter - {default}): "},

    # ---- run ---------------------------------------------------------- #
    "run_head": {"ru": "Прогон - {name} → {target}", "en": "Run - {name} → {target}"},
    "run_building": {"ru": "собираю кадры на хосте…", "en": "building frames on the host…"},
    "run_sending": {"ru": "гоню трафик", "en": "sending"},
    "run_done": {"ru": "прогон закончен", "en": "run finished"},
    "run_failed": {"ru": "прогон не состоялся", "en": "the run did not happen"},
    "run_stopped": {"ru": "прервано", "en": "stopped"},
    "l_sent": {"ru": "отправлено", "en": "sent"},
    "l_recv": {"ru": "принято", "en": "received"},
    "l_loss": {"ru": "потери", "en": "loss"},
    "l_rate": {"ru": "скорость", "en": "rate"},
    "l_elapsed": {"ru": "прошло", "en": "elapsed"},
    "l_unmeasured": {"ru": "не мерялось", "en": "unmeasured"},
    "run_archive": {"ru": "прогон записан: {path}", "en": "archived: {path}"},
    "how_long": {"ru": "сколько секунд гнать (Enter - {default}): ",
                 "en": "how many seconds (Enter - {default}): "},

    # ---- history ------------------------------------------------------ #
    "history_head": {"ru": "История прогонов", "en": "Run history"},
    "history_empty": {"ru": "прогонов ещё не было", "en": "nothing has run yet"},

    # ---- problems ----------------------------------------------------- #
    "problems": {"ru": "Так гнать нельзя:", "en": "This will not run:"},
    "bad_input": {"ru": "не понял ввод: {what}", "en": "could not read that: {what}"},
    "no_scapy_note": {"ru": "Scapy нужен на цели, не здесь",
                      "en": "Scapy is needed on the target, not here"},
    "not_a_tty": {"ru": "это не терминал - меню не открыть; "
                        "смотри traphy --help",
                  "en": "not a terminal - no menu here; see traphy --help"},
}
