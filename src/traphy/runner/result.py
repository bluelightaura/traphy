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
    # Everything the script said, in order. ``note`` is the headline and the
    # last writer wins it; a run that announced an empty recording and then
    # finished with something to say about the counters would otherwise lose
    # the first sentence entirely.
    notes: list[str] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)
    started_at: str = ""
    run_dir: str = ""
    # Where the frames themselves ended up: {"tx": path, "rx": path}. Empty
    # when nothing was recorded, which the run screen says rather than leaving
    # the operator to wonder whether it looked.
    captures: dict[str, str] = field(default_factory=dict)
    # Which sides recording was actually running on, empty files included.
    # What the recording cost - service mode on TRex, a sniffer competing with
    # the send loop on Scapy - was paid whether or not any frame landed in the
    # file, so the caveat has to key on this and not on what arrived.
    recorded: list[str] = field(default_factory=list)
    # Шёл ли прогон с портами в сервисном режиме, и что показывал приём, пока
    # мы молчали. Структурно, а не внутри текста ноты: сравнить два прогона
    # между собой иначе можно только диффом сгенерированных скриптов.
    service_mode: bool = False
    idle_rx: int = 0
    idle_rx_groups: int = 0
    # Сколько кадров нашей группы пришло мимо порта, который обязан принимать.
    rx_foreign: int = 0
    # Приём поимённо по группам: номер группы -> её собственные цифры
    # (``tx``, ``rx``, ``rx_port``, ``rx_foreign``, ``port_seen``). Сумма
    # отвечает «сколько принято» и молчит про «какой именно группой», а
    # отравленной на стенде оказывалась одна группа из трёх.
    rx_per_group: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Сколько помеченных кадров генератор не отнёс ни к одной группе -
    # ``flow_stats['global']``. Это недостача самого учёта, и в колонке потерь
    # она выглядит точно как кадры, съеденные устройством.
    flow_err_rx: int = 0
    flow_err_tx: int = 0
    # Сколько кадров прогон собирался послать. Больше нуля только когда план
    # конечен - профиль из очередей с известным числом кадров. У continuous
    # плана нет, и строгое сравнение там невозможно по устройству режима.
    ordered_pkts: int = 0
    # Сколько секунд просили. Нужно, чтобы заметить прогон, шедший дольше плана.
    requested_seconds: float = 0.0
    # Падал ли линк на наших портах по ходу прогона. Упавший посреди замера
    # линк не ловится ничем другим: старт отказался бы, а середина - нет.
    link_down: bool = False
    # Счётчики ошибок портов, выросшие за прогон: имя -> прирост. И отдельно
    # те из них, что говорят про генератор, а не про линк и не про устройство.
    port_errors: dict[str, int] = field(default_factory=dict)
    generator_errors: list[str] = field(default_factory=list)

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
    def loss_countable(self) -> bool:
        """Есть ли вообще, на чём держится цифра потерь.

        Два условия, и оба арифметические. Приём кто-то считал - иначе вычитать
        не из чего. И в счёт приёма не легло больше, чем мы послали: лишние
        кадры либо чужие, либо наши же, посчитанные дважды на петле, и в обоих
        случаях «послали минус приняли» не описывает ничего. Отрицательные
        потери при этом обрезаются в ноль, поэтому прогон, по которому мерить
        нечего, выглядит образцовым - ровно та ловушка, против которой написан
        весь модуль.

        Отдельно от :meth:`disqualified`: негодный замер цифру потерь не
        отменяет. Недобравший скорость генератор послал меньше, но то, что
        ушло, посчитано верно. Здесь - только про саму возможность вычитания.
        """
        return self.measured() and self.rx_pkts <= self.tx_pkts

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

    def disqualified(self) -> list[str]:
        """Почему этот прогон не годится как измерение - по каждой причине фраза.

        Один гейт вместо набора оговорок, разъехавшихся по модулю. Решение
        «годится ли замер» раньше складывалось из скрипта (он ставил
        ``reliable``) и из :meth:`warnings`, и два места расходились при первой
        же правке.

        Важно, чего здесь НЕТ: цифру потерь это не отменяет. Потери считаются
        от того, что реально ушло, и остаются верной арифметикой даже когда
        генератор не добрал скорость. Негодным становится **замер**: прогон,
        выдавший пятую часть заданного, ничего не сказал об устройстве на
        заданной скорости. Обнулить тут цифру значило бы выбросить верное
        вместе с бесполезным.
        """
        if self.dry_run:
            return []
        out: list[str] = []
        if self.rx_pkts > self.tx_pkts:
            out.append("в счёт приёма попало не только наше")
        if self.rx_source in ("flow_stats_tainted", "flow_stats_foreign",
                              "flow_stats_noport"):
            out.append("аппаратный счёт по этому прогону недостоверен")
        if self.rx_source == "flow_stats_blind":
            # Два счётчика противоречат друг другу: группы на приёме стоят в
            # нуле, а порт кадры принял. Это НЕ то же самое, что
            # приблизительность счётчика порта там, где аппаратного счёта и не
            # заказывали: здесь он заказан, существует и молчит, и какой из
            # двух описывает наш трафик, по этому прогону не установить.
            # Найдено живым прогоном 2026-10-05: отчёт говорил
            # «приблизительно», а в JSON уезжало measurement_valid=true при
            # потерях 99.99% и пяти принятых кадрах, из которых ни один не наш.
            # Формулировка короткая нарочно: куда смотреть, скажет оговорка
            # ниже - она же и знает, что подозревать карту генератора. Два
            # абзаца об одном выглядят как две разные беды.
            out.append("два счётчика приёма разошлись - в нуле только "
                       "группы, и какой из них описывает наш трафик, "
                       "не установить")
        if self.rx_source == "flow_stats_unverified":
            out.append("группы показали ноль, а счётчик порта приёма "
                       "прочитать не удалось - сверить было нечем")
        if self.flow_err_rx:
            # Недостача учёта, а не кабеля: эти кадры приехали, но в группу не
            # попали. Разницы с настоящими потерями в колонке потерь нет
            # никакой, поэтому замер негоден целиком, а не «с оговоркой».
            out.append(f"аппаратный счёт неполон: {self.flow_err_rx} принятых "
                       f"кадров не отнесено ни к одной группе")
        if self.ordered_pkts and self.tx_pkts != self.ordered_pkts:
            out.append(f"послано {self.tx_pkts} кадров из заказанных "
                       f"{self.ordered_pkts} - план не выполнен")
        elif self.rate_shortfall > 10:
            # Коротко: цифры и причину назовёт оговорка про скорость, она же
            # знает, какой движок и чем именно упёрся. Здесь только вывод.
            out.append("генератор не вышел на заданную скорость")
        if self.link_down:
            out.append("линк падал по ходу прогона")
        if self.generator_errors:
            grew = ", ".join(self.generator_errors)
            out.append(f"росли счётчики ошибок генератора ({grew}) - кадры "
                       f"терялись на нашей стороне")
        if self.requested_seconds and self.seconds > self.requested_seconds * 1.5:
            out.append(f"прогон шёл {self.seconds:.1f} c вместо "
                       f"{self.requested_seconds:.1f} c")
        return out

    def measured(self) -> bool:
        """Есть ли вообще цифра приёма, которую кто-то посчитал."""
        return self.rx_source != "none" and not self.dry_run

    def valid_measurement(self) -> bool:
        """Можно ли предъявлять этот прогон как результат."""
        return self.measured() and not self.disqualified()

    def stand_silent(self) -> bool:
        """Со стенда не вернулось почти ничего, хотя послали заметный объём.

        Это другой случай, чем «наш счётчик врёт»: там, где назад пришла
        пара кадров из десятков тысяч, виноват не замер, а путь через
        устройство - и человеку надо сказать именно это, а не «два счётчика
        разошлись». Порог высокий нарочно: 99% потерь на боевом железе бывают,
        50% - это уже про настройку стенда, а не про отказ.
        """
        return (bool(self.disqualified()) and self.loss_countable
                and self.tx_pkts >= 100 and self.loss_pct >= 99.0)

    def _verdict(self) -> str:
        """Заголовок негодного прогона - словами той беды, что случилась."""
        if self.stand_silent():
            return (f"СТЕНД НЕ ОТВЕЧАЕТ: назад пришло {self.rx_pkts} из "
                    f"{self.tx_pkts} - проверь путь через устройство")
        return f"ЗАМЕР НЕ ГОДИТСЯ: {self.disqualified()[0]}"

    def summary(self) -> str:
        """One line for the menu's history and for the run screen's footer."""
        if self.dry_run:
            return "холостой прогон - кадры собраны, в кабель не ушло ничего"
        head = f"tx={self.tx_pkts} за {self.seconds:.1f} c ({self.achieved_pps:.0f} pps)"
        if self.reliable and not self.disqualified():
            return f"{head} · rx={self.rx_pkts} · потери {self.loss_pct:.2f}%"
        if self.reliable:
            # Счёт сошёлся сам с собой, а замером прогон не стал. Напечатать
            # тут голые потери - значит выдать негодный прогон за результат. А
            # когда приём больше отправки, цифры нет вовсе: вычитать не из чего,
            # и аккуратный ноль тут - самое неверное, что можно напечатать.
            lost = (f"потери {self.loss_pct:.2f}%" if self.loss_countable
                    else "потери не считаются")
            return f"{head} · rx={self.rx_pkts} · {lost} · {self._verdict()}"
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
        said = (f"{head} · rx={self.rx_pkts} · потери {self.loss_pct:.2f}% "
                f"· приблизительно ({self.rx_source})")
        # «Приблизительно» и «негоден как замер» - разные вещи, и вторую в
        # одну строку истории раньше не выносило ничто: прогон со слепыми
        # группами выглядел там так же, как честный приблизительный.
        return f"{said} · {self._verdict()}" if self.disqualified() else said

    def warnings(self) -> list[str]:
        """Everything about this result a reader should not have to infer."""
        out: list[str] = []
        # Первым делом - почему прогон не годится как измерение. Это вывод, а
        # не подробность, и читается он раньше всего остального.
        out.extend("замер не годится: " + why for why in self.disqualified())
        if not self.reliable and not self.dry_run:
            said = self._rx_caveat()
            if said:
                out.append(said)
        if self.rate_shortfall > 2:
            # Цифры и причина недобора - здесь; вывод «замер не годится» уже
            # сказан выше. Одно без другого читается плохо: вывод без цифр не
            # проверить, цифры без вывода можно принять за результат.
            out.append(self._rate_caveat())
        if self.rx_pkts > self.tx_pkts and not self.dry_run:
            out.append(self._impossible_caveat())
        blamed = self._generator_caveat()
        if blamed:
            out.append(blamed)
        if self.recorded_traffic():
            out.append(self._capture_caveat())
        out.extend(f"ошибки порта: {name} +{count}"
                   for name, count in sorted(self.port_errors.items())
                   if name not in self.generator_errors)
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
        if self.rx_source == "flow_stats_tainted":
            return (f"в наши группы на приёме легло {self.idle_rx_groups} "
                    f"кадров ещё до старта - в сегменте идёт чужой трафик с "
                    f"той же меткой группы, так что аппаратный счёт по этому "
                    f"прогону ничего не измеряет, как бы ровно он ни выглядел")
        if self.flow_err_rx:
            return (f"генератор не отнёс к группам {self.flow_err_rx} "
                    f"принятых кадров - ровно столько аппаратный счёт недодал "
                    f"и ровно столько выглядит потерями устройства; смотреть "
                    f"надо счёт на генераторе, а не кабель")
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
        sides = self.recorded or list(self.captures)
        return [name for name in sides if name in ("tx", "rx")]

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
        tail = ("устройство на этой скорости не проверено"
                if self.rate_shortfall > 10
                else "замер шёл не на той скорости, которую задали")
        return f"{head} - {why}, {tail}"

    def _generator_caveat(self) -> str:
        """Loss that lines up with the sending side, said in one sentence.

        A rate the generator could not hold, and a recording it was paying for,
        both make frames go missing before the device under test ever sees
        them - and the column they land in is the one labelled loss. The two
        facts are printed in separate lines above; leaving the reader to connect
        them is how a generator that fell behind gets written down as a device
        that drops frames.
        """
        if self.dry_run or self.rx_source == "none" or self.loss_pct <= 0.1:
            return ""
        because = []
        if self.rate_shortfall > 0.5:
            because.append("генератор не держал заданную скорость")
        if self.recorded_traffic():
            because.append("шла запись кадров")
        if not because:
            return ""
        why = " и ".join(because)
        return (f"потери {self.loss_pct:.2f}% совпали с тем, что {why} - это "
                f"сходится с потерей кадров на стороне отправки, так что "
                f"первый подозреваемый здесь генератор, а не устройство "
                f"под нагрузкой")

    def to_dict(self) -> dict[str, Any]:
        """The machine-readable form - held to the same honesty as the screen.

        Человеческие поверхности давно не печатают ноль потерь там, где никто
        не считал, а JSON печатал: ``"loss_pct": 100.0`` рядом с
        ``"rx_source": "none"``. Кто читает JSON, а не ``rx_source``, получал
        ровно то, от чего инструмент защищает на экране.

        Второй такой случай - приём больше отправки. ``summary()`` на нём
        говорит «потери не считаются», а в JSON уезжало ``"loss_pct": 0.0`` с
        ``"loss_measured": true`` рядом с ``"measurement_valid": false``: кто
        собирает отчёт скриптом и берёт ``loss_pct``, получал «потери 0%» по
        дисквалифицированному прогону. Поэтому цифры потерь здесь нет там, где
        её не на чем основать, а ``loss_countable`` говорит, почему её нет, -
        и равен он ровно тому, есть ли в ответе число.
        """
        d = asdict(self)
        countable = self.loss_countable
        d["loss_measured"] = self.measured()
        d["loss_countable"] = countable
        # Цифра потерь остаётся цифрой, когда её есть из чего вычесть; годность
        # замера - отдельное поле, и читатель, которому нужен результат,
        # смотрит на него, а не на потери.
        d["measurement_valid"] = self.valid_measurement()
        d["disqualified"] = self.disqualified()
        d["loss_pkts"] = self.loss_pkts if countable else None
        d["loss_pct"] = round(self.loss_pct, 3) if countable else None
        d["rate_shortfall_pct"] = round(self.rate_shortfall, 1)
        return d
