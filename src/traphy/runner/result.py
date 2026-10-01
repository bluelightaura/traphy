"""What one run produced, and how much of it to believe.

Kept apart from the code that performs the run for a reason that shows up the
moment a second way of running appears: a result is read by the screen, by the
history, by the JSON output and by a comparison between two runs, while the
executing side is read by nobody. Mixing them means every reader drags the
transport in behind it.

There are four ways the receive side can be counted and they are not worth the
same: ``flow_stats`` is a hardware counter per stream group and needs no
caveat, ``port_counter`` also sees traffic that is not ours, ``mixed`` covers
only part of the run, and ``none`` means nobody was counting at all. The result
carries which one it was, and every place that displays it has to say so: a
zero in the loss column that actually means "nobody was counting" is the single
most misleading thing a traffic tool can print.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RunResult:
    """One run, as everything downstream of it sees it."""

    profile: str = ""
    target: str = ""
    engine: str = "scapy"
    transport: str = ""
    tx_iface: str = ""
    rx_iface: str = ""

    tx_pkts: int = 0
    rx_pkts: int = 0
    tx_bytes: int = 0
    seconds: float = 0.0
    requested_pps: float = 0.0
    achieved_pps: float = 0.0

    # marker | flow_stats | traffic_item | port_counter | mixed | partial |
    # none - see the module note
    rx_source: str = "none"
    reliable: bool = False       # False => the loss column needs its caveat
    rc: int = 0
    # A run that was never going to send. Carried because the honesty rules
    # read differently here: "приём не измерялся" is the expected outcome of a
    # dry run, not a finding, and advising the operator to configure a receive
    # port they already configured teaches them to skip the warnings.
    dry_run: bool = False
    note: str = ""
    truncated: list[str] = field(default_factory=list)
    started_at: str = ""
    run_dir: str = ""
    # Where the frames themselves ended up: {"tx": path, "rx": path}. Empty
    # when nothing was recorded, which the run screen says rather than leaving
    # the operator to wonder whether it looked.
    captures: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def loss_pkts(self) -> int:
        """Frames sent but not seen coming back. Meaningless when unreliable."""
        return max(0, self.tx_pkts - self.rx_pkts)

    @property
    def loss_pct(self) -> float:
        return (self.loss_pkts / self.tx_pkts * 100.0) if self.tx_pkts else 0.0

    @property
    def rate_shortfall(self) -> float:
        """How far under the asked-for rate the run actually landed, in percent.

        Scapy pacing gives out well before a NIC does. A run that asked for
        100k pps and delivered 30k has not tested the device at 100k, and the
        number that matters for that judgement is this one.
        """
        if self.requested_pps <= 0 or self.achieved_pps <= 0:
            return 0.0
        return max(0.0, (1 - self.achieved_pps / self.requested_pps) * 100.0)

    def summary(self) -> str:
        """One line for the menu's history and for the run screen's footer."""
        if self.dry_run:
            return "холостой прогон - кадры собраны, в кабель не ушло ничего"
        head = f"tx={self.tx_pkts} за {self.seconds:.1f} c ({self.achieved_pps:.0f} pps)"
        if self.reliable:
            return f"{head} · rx={self.rx_pkts} · потери {self.loss_pct:.2f}%"
        if self.rx_source == "none":
            return f"{head} · приём не измерялся"
        if self.rx_pkts > self.tx_pkts:
            # Процент потерь тут арифметически ноль и ровно ничего не значит:
            # в приёмный счётчик легло больше, чем мы послали. Напечатать
            # «потери 0.00%» - значит выдать за хороший результат прогон, по
            # которому потери не считаются вовсе.
            return (f"{head} · rx={self.rx_pkts} · потери не считаются "
                    f"· приблизительно ({self.rx_source})")
        # Measured, just not by something that counts only our frames. Saying
        # "не измерялся" about a figure that is right there on the screen
        # teaches the reader to stop believing the line.
        return (f"{head} · rx={self.rx_pkts} · потери {self.loss_pct:.2f}% "
                f"· приблизительно ({self.rx_source})")

    def warnings(self) -> list[str]:
        """Everything about this result a reader should not have to infer."""
        out: list[str] = []
        if not self.reliable and not self.dry_run:
            said = self._rx_caveat()
            if said:
                out.append(said)
        if self.rate_shortfall > 10:
            out.append(self._rate_caveat())
        if self.rx_pkts > self.tx_pkts and not self.dry_run:
            out.append(self._impossible_caveat())
        if self.recorded_traffic():
            out.append(self._capture_caveat())
        out.extend(f"диапазон урезан - {t}" for t in self.truncated)
        if self.rc != 0:
            why = f": {self.note}" if self.note else ""
            out.append(f"скрипт завершился с кодом {self.rc}{why}")
        return out

    def _rx_caveat(self) -> str:
        """Why this run's loss figure cannot be read at face value.

        Four different situations, and they call for four different next
        moves - which is the whole reason the source is carried rather than
        just a boolean.
        """
        if self.rx_source == "marker":
            return ("приём считан сниффером по метке в кадре - он видит "
                    "только наши кадры, но под нагрузкой теряет их сам; "
                    "на высокой скорости эти потери описывают сниффер, "
                    "а не устройство")
        if self.rx_source == "port_counter":
            return ("приём считан счётчиком порта - туда легло всё, что в "
                    "него прилетело, так что потери по нему приблизительны")
        if self.rx_source == "flow_stats_blind":
            return ("аппаратные группы не сосчитали приём, хотя порт кадры "
                    "принял - цифра со счётчика порта; подозревать надо карту "
                    "и драйвер генератора, а не устройство под нагрузкой")
        if self.rx_source == "mixed":
            return ("часть потоков ушла без аппаратного счёта - потери "
                    "посчитаны не по всему прогону")
        if self.rx_source == "partial":
            return ("счётчики пришли не по всем потокам - потери посчитаны "
                    "не по всему прогону")
        if self.rx_source == "flow_stats_unverified":
            return ("группы показали ноль, а счётчик порта приёма прочитать не "
                    "удалось - сверить было нечем, поэтому ноль подан как "
                    "неточный")
        if self.rx_source == "none":
            where = ("порт приёма" if self.engine in ("trex", "ixia")
                     else "интерфейс приёма")
            return (f"приём не измерялся - колонка потерь ничего не значит; "
                    f"задай {where} в настройке цели")
        # Аппаратный счёт, потерявший доверие не сам по себе, а по противоречию:
        # объясняет его та оговорка, которая это противоречие и нашла. Советовать
        # тут «задай порт приёма» - советовать настроить уже настроенное, а это
        # ровно то, после чего предупреждения перестают читать.
        return ""

    def _impossible_caveat(self) -> str:
        """Принято больше, чем отправлено - значит считали не то.

        Само по себе это не бывает: лишние кадры либо чужие, либо наши же,
        посчитанные дважды. На петле второе - кадр виден и на выходе, и на
        входе. Колонка потерь при этом показывает аккуратный ноль, потому что
        отрицательные потери обрезаются, - и прогон выглядит образцовым
        ровно тогда, когда мерить по нему нечего.
        """
        return (f"принято больше, чем отправлено ({self.rx_pkts} против "
                f"{self.tx_pkts}) - счётчик приёма ловит не только наши кадры "
                f"либо считает их дважды, как бывает на петле; потери по "
                f"такому прогону не считаются")

    def recorded_traffic(self) -> list[str]:
        """Записанные стороны прогона - и только они.

        Отдельно от ``captures`` потому, что туда же приезжают образцы кадров
        (``streams``): по одному на поток, собранные ДО field engine, к
        сервисному режиму и к потолку скорости отношения не имеющие. Сказать
        про них «порты были в сервисном режиме» значит объяснить цену, которой
        не было.
        """
        return [name for name in self.captures if name in ("tx", "rx")]

    def _capture_caveat(self) -> str:
        """What recording the frames cost this particular run.

        Recording is on by default because the question it answers always
        arrives after the run. It is never free, but the price differs by
        engine, and naming the wrong one is worse than naming none: an
        operator told about service mode after a Scapy run goes looking for a
        setting that does not exist there.

        On TRex the frames have to come up through the software path to be
        copied, which means service mode and a lower ceiling. On Scapy there
        is no service mode - the cost is the sniffer holding frames and the
        copy competing with the send loop for the same interpreter.
        """
        # Send before receive, then anything else. Alphabetical would put the
        # receive side first, which is not the order the run happened in.
        order = {"tx": 0, "rx": 1}
        where = ", ".join(sorted(self.recorded_traffic(),
                                 key=lambda n: (order.get(n, 2), n)))
        if self.engine == "scapy":
            why = ("сниффер держал кадры в памяти, а копирование отнимало "
                   "время у самой отправки")
        else:
            why = "порты были в сервисном режиме, потолок скорости ниже обычного"
        return (f"кадры записаны ({where}) - {why}; для замера предельной "
                f"скорости запись надо выключить")

    def _rate_caveat(self) -> str:
        """The rate the run actually held, and what falling short of it means.

        On Scapy it usually means the kernel path ran out of road; on TRex the
        generator is not the suspect, so the sentence points elsewhere. Either
        way the conclusion is the same and it is the one that matters: the
        device was not tested at the rate that was asked for.
        """
        head = (f"выдано {self.achieved_pps:.0f} pps из "
                f"{self.requested_pps:.0f} запрошенных "
                f"(-{self.rate_shortfall:.0f}%)")
        if self.engine == "trex":
            why = ("TRex не вышел на заданную скорость - обычно это потолок "
                   "порта или профиль, который его не набирает")
        elif self.engine == "ixia":
            why = ("шасси не вышло на заданную скорость - обычно это потолок "
                   "порта или профиль, который его не набирает")
        else:
            why = "Scapy упёрся"
        return f"{head} - {why}, устройство на этой скорости не проверено"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["loss_pkts"] = self.loss_pkts
        d["loss_pct"] = round(self.loss_pct, 3)
        d["rate_shortfall_pct"] = round(self.rate_shortfall, 1)
        return d
