"""What one run asks for, kept apart from the code that carries it out.

An engine needs to read a run's parameters to build its arguments, and the
runner needs an engine to do the run - so the parameters live in their own
module and neither has to import the other. Small file, but it is what keeps
adding an engine from being a circular-import puzzle.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RunSpec:
    """Everything one run needs beyond the profile and the target."""

    duration: float = 10.0
    count: int = 0               # total packets; overrides duration when > 0
    pps: float = 0.0             # aggregate override; 0 = whatever the profile says
    dry_run: bool = False        # build and report, send nothing
    save_pcap: bool = False
    archive: bool = True

    # Recording is on by default, and that is the point of it. A capture that
    # has to be asked for is a capture nobody has when the question arrives -
    # and the question ("что именно прилетело?") always arrives after the run,
    # never before it.
    capture: bool = True
    # Per side. TRex copies captured frames up to the control plane, so this
    # cannot follow a line-rate run; the result says how much it kept rather
    # than implying it kept everything.
    capture_limit: int = 1000

    # Отобрать порт у чужого прогона - решение на один раз, а не настройка.
    # В цели такой тумблер есть, но он липкий: включённый ради одной проверки,
    # он остаётся включённым для всех следующих прогонов, и на общем генераторе
    # это ровно тот способ испортить чужой замер, которого инструмент и должен
    # не допускать. Здесь оно живёт один прогон и никуда не сохраняется.
    force: bool = False

    # Не прогон, а уборка за прогоном, который не убрал за собой. Живёт здесь,
    # а не отдельным путём, чтобы движок собирал аргументы в одном месте: иначе
    # у уборки появится своя копия знания про порты и адрес демона.
    recover: bool = False
