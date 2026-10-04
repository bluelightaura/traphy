"""Sending recorded frames home - one piece of generated code, two engines.

Both generated scripts face the same problem and it is not obvious until the
first remote run: the pcap is written on the machine that did the sending, and
the person who wants to open it is somewhere else. Three answers were possible
and two of them are worse.

Leaving the file behind is worse because the generator is shared. A tool that
scatters pcaps across somebody else's box is a tool that gets uninstalled.

Fetching it afterwards over SFTP is worse because it needs a second mechanism -
a remote path that outlives the script's own temporary directory, a way to name
it, cleanup when the fetch fails, and a local transport that has to pretend to
do the same thing. All of that to move a file that is already small enough to
carry.

So it travels back inside the event stream, base64 in bounded lines, and the
archive on the operator's machine assembles it. Nothing is left on the
generator, nothing needs a second connection, and the local and the remote case
are the same case.

The cap matters and is not a detail: a capture that has to be asked for is a
capture nobody has when the question arrives, and a capture with no ceiling is
a run that tries to ship a line-rate minute through a JSON stream. Hence a
limit, always reported alongside the frames, so a partial recording is never
read as a whole one.
"""

from __future__ import annotations

# How much base64 goes in one event line. Big enough that a capture is a
# handful of lines, small enough that a line stays something a person can
# scroll past in a log without the terminal giving up.
CHUNK = 48000

# Embedded verbatim in both generated scripts, which is why it is text rather
# than a function: the scripts are standalone files that run on a machine where
# TRaphy is not installed. It expects ``emit`` and ``base64`` to already be
# there - both generators have them.
SHIP = f'''\
# Ширина куска base64 в одной строке события - см. traphy/codegen_ship.py.
CHUNK = {CHUNK}


def ship_pcap(kind, raw, quiet, limit=0):
    """Отправить одну записанную сторону домой внутри потока событий.

    Кадры не остаются на машине-генераторе: она общая, и подбирать за собой
    файлы никто не будет. Приёмная сторона склеит куски обратно в pcap.
    """
    if not raw:
        # НЕ "кадров не было". Пустой захват при работающем счётчике - вещь
        # наблюдаемая: часть карт и драйверов отдаёт пустой L2-захват, а запись
        # отправки не всегда совмещается с аппаратным счётом по группам. Сказать
        # здесь "кадров не было" значит выдать свойство захвата за потери, и
        # человек пойдёт искать поломку в устройстве.
        emit(quiet, ev="note",
             msg="запись %s пуста - по этому НЕЛЬЗЯ судить о потерях: "
                 "пустой захват бывает и при работающем счётчике. "
                 "Смотри цифру приёма, а не отсутствие кадров" % kind)
        # Событие о записи отдаётся и для пустой стороны. Цену за запись прогон
        # уже заплатил - у TRex это сервисный режим и просаженный потолок, - и
        # без этой строки оговорка про цену исчезала вместе с пустым файлом:
        # прогон выглядел медленным без всякого объяснения.
        emit(quiet, ev="capture", name=kind, bytes=0, limit=limit)
        return
    text = base64.b64encode(raw).decode("ascii")
    parts = [text[i:i + CHUNK] for i in range(0, len(text), CHUNK)]
    for number, part in enumerate(parts):
        emit(quiet, ev="capture_data", name=kind, seq=number,
             last=(number == len(parts) - 1), data=part)
    emit(quiet, ev="capture", name=kind, bytes=len(raw), limit=limit)'''

__all__ = ["CHUNK", "SHIP"]
