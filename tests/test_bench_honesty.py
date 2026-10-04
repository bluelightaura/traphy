"""Что прогон обязан сказать про собственные условия, а не только про цифры.

Всё здесь появилось из одного живого прогона на стенде. Аппаратный счёт отдал
142 250 747 принятых кадров против 4001 отправленных, а прогон до него на том же
железе показал на приёме ноль - и оба раза цифра выглядела как показание
прибора. Причины оказались скучные и обе про условия, а не про коробку: номер
группы был один и тот же каждый прогон, так что хвост прошлого прогона считался
своим, а счётчики обнулялись до того, как наши группы на сервере вообще
появлялись, поэтому первое чтение возвращало абсолют демона со времени старта.

Отсюда правило, которое эти тесты и охраняют: прогон измеряет разницу, считает
приём там, где обязан принимать, и отказывается называть цифру надёжной, когда
условия этого не позволяют.
"""

from __future__ import annotations

import json

import pytest

from traphy import codegen_stl, engines, presets
from traphy.cli.parser import build_parser
from traphy.runner import RunResult, RunSpec, apply_events, execute
from traphy.target import Target
from traphy.transport import Completed, Transport, TransportError

# Подделка релиза TRex живёт рядом с тестами самого движка - второй копии быть
# не должно, иначе однажды они разойдутся.
import test_trex
from test_trex import FakeClient, events, run_stl


@pytest.fixture
def trex(monkeypatch):
    """Та же подделка релиза, что у тестов движка, под своим именем.

    Импортировать чужую фикстуру прямо в этот модуль нельзя: линтер видит в
    параметре каждого теста переопределение импортированного имени и ругается
    девять раз подряд. Обёртка - одна, и она хотя бы говорит, откуда берётся
    подделка.
    """
    yield from test_trex.fake_trex.__wrapped__(monkeypatch)

# Быстрый прогон: пауза на дослёт и холостое слушание тут ни при чём, и платить
# за них секундами в каждом тесте незачем.
QUICK = ["--trex-dir", "/nowhere", "--tx-port", "0", "--rx-port", "1",
         "--duration", "1", "--settle", "0", "--idle-check", "0.1"]


def done_event(capsys) -> dict:
    said = [e for e in events(capsys) if e["ev"] == "done"]
    assert said, "прогон не сказал done"
    return said[-1]


# --------------------------------------------------------------------------- #
# Своя группа на каждый прогон
# --------------------------------------------------------------------------- #
def test_each_run_takes_a_counter_group_of_its_own():
    """Группа была нулевой всегда, и кадр несёт только её номер - личности
    прогона в нём нет. Поэтому кадры прошлого прогона, ещё летающие в сегменте,
    попадали в счёт текущего как свои."""
    profile = presets.build("l3_ip")
    bases = {codegen_stl._pg_base(tag, 1) for tag in ("a1b2c3", "d4e5f6", "99")}
    assert len(bases) > 1, "метка прогона не влияет на номер группы"
    assert all(0 <= b < codegen_stl.MAX_PG_ID for b in bases)

    first = codegen_stl.generate(profile, tag="a1b2c3")
    second = codegen_stl.generate(profile, tag="d4e5f6")
    assert first != second
    # И номер остаётся в пределах, которые железо вообще поддерживает.
    for text in (first, second):
        line = next(ln for ln in text.splitlines() if "pg_next = " in ln)
        assert 0 <= int(line.split("= ")[1]) < codegen_stl.MAX_PG_ID


# --------------------------------------------------------------------------- #
# Разница, а не абсолют
# --------------------------------------------------------------------------- #
def test_counters_that_did_not_clear_are_subtracted_rather_than_reported(
        trex, capsys):
    """Обнуление в take_ports наших групп не касается: их на сервере тогда ещё
    нет. Прочитанный абсолют выглядит как измерение - именно так 4001
    отправленных кадров превратились в 142 млн принятых."""
    FakeClient.stale_rx = 500         # столько уже стоит в счётчиках до старта
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    said = events(capsys)

    base = [e for e in said if e["ev"] == "base"]
    assert base and base[0]["group_rx"] == 500, "опорная точка не снята"
    final = [e for e in said if e["ev"] == "done"][-1]
    # 995 насчитала группа всего, 500 из них стояло там до нас.
    assert final["rx"] == 495, "цифра приёма не стала разницей к опорной точке"
    # И замер остаётся замером: постоянное смещение - не повод не верить
    # цифре, повод её поправить. Отказываться тут значило бы хоронить любой
    # прогон на демоне, который живёт неделю.
    assert final["reliable"] is True
    assert final["rx_source"] == "flow_stats"


def test_a_segment_already_busy_disqualifies_the_hardware_count(
        trex, capsys):
    """Кадры, попадающие в НАШУ группу до старта, отравляют единственную цифру,
    которой инструмент верит без оговорок. Ровная цифра из отравленной группы
    опаснее кривой: она выглядит как измерение."""
    FakeClient.idle_rx = 400
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    final = done_event(capsys)
    assert final["rx_source"] == "flow_stats_tainted"
    assert final["reliable"] is False
    assert final["idle_rx_groups"] > 0


def test_the_idle_reading_is_published_with_its_numbers(trex, capsys):
    """Иначе различие двух прогонов приходится доставать диффом скриптов."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    idle = [e for e in events(capsys) if e["ev"] == "idle"]
    assert idle, "холостой замер не объявлен"
    assert {"rx_port", "rx_groups", "seconds"} <= set(idle[0])


def test_every_tick_carries_the_receiving_port_counter_too(trex, capsys):
    """sample() читал счётчик порта и выбрасывал его, если группа была
    ненулевой, - и по архиву было уже не понять, сошлись они или разошлись."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    ticks = [e for e in events(capsys) if e["ev"] == "tick"]
    assert ticks and all("rx_port" in t and "rx_groups" in t for t in ticks)


# --------------------------------------------------------------------------- #
# Приём считается там, где обязан принимать
# --------------------------------------------------------------------------- #
def test_frames_of_our_group_that_came_in_elsewhere_are_not_our_receive(
        trex, capsys):
    """Агрегат группы складывает все порты шасси. Кадр с нашей меткой, пришедший
    не туда, где мы его ждём, в агрегате выглядит как наш принятый - а это
    вопрос к схеме стенда, не к устройству под нагрузкой."""
    FakeClient.group_rx_foreign = 300
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    final = done_event(capsys)
    assert final["rx_source"] == "flow_stats_foreign"
    assert final["reliable"] is False
    assert final["rx_foreign"] == 300
    assert final["rx"] == 995, "в приём попало то, что пришло мимо нашего порта"


def test_a_group_without_a_record_for_our_port_is_not_zero_received(
        trex, capsys):
    """Отсутствие счётчика и ноль принятых - разные вещи, и подменять первое
    вторым значит выдать «потери 100%» на исправном линке."""
    FakeClient.group_rx_no_port = True
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    final = done_event(capsys)
    assert final["rx_source"] == "flow_stats_noport"
    assert final["reliable"] is False
    assert final["rx"] > 0, "цифра подменена нулём"


# --------------------------------------------------------------------------- #
# Чужое не трогаем, своё убираем
# --------------------------------------------------------------------------- #
def test_a_refused_port_is_left_exactly_as_it_was(trex, capsys):
    """Отказ «порт занят» обязан быть безвредным для того, кто его занял. И
    release, и disconnect с умолчаниями бьют по чужим портам: умолчания
    disconnect - остановить трафик и отдать порты."""
    FakeClient.owner = "коллега"
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    assert namespace["_rc"] == 4
    calls = FakeClient.last.calls
    assert not any(isinstance(c, tuple) and c[0] == "release" for c in calls)
    assert "disconnect" not in calls, "чужие порты отданы на выходе"
    assert "clear_stats" not in calls, "чужие счётчики обнулены"


def test_ports_left_working_by_a_dead_run_stop_the_next_one(trex, capsys):
    """Прогон, убитый сигналом, до своего finally не доходит: на машине
    остаются идущий трафик, сервисный режим и живая запись. Следующий человек
    получает отказ, к его работе отношения не имеющий, - поэтому остаток надо
    назвать, а не молча переехать."""
    FakeClient.traffic_before_start = True
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    assert namespace["_rc"] == 5, "остаток на портах прошёл незамеченным"
    said = [e for e in events(capsys) if e["ev"] == "error"]
    assert said and "--force" in said[0]["msg"]
    assert not any(isinstance(c, tuple) and c[0] == "start"
                   for c in FakeClient.last.calls)


def test_force_clears_the_leftover_and_says_what_it_cleared(trex, capsys):
    """Убрать за мёртвым прогоном - решение оператора, а не услуга по умолчанию:
    молча переехать чужой замер тем же и кончится."""
    FakeClient.traffic_before_start = True
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")),
                        [*QUICK, "--force"])
    assert namespace["_rc"] == 0
    notes = [e["msg"] for e in events(capsys) if e["ev"] == "note"]
    assert any("убираю остаток" in n for n in notes), notes


# --------------------------------------------------------------------------- #
# Одноразовый отъём порта
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("engine,target", [
    ("trex", Target(engine="trex", trex_port_tx=0, trex_port_rx=1)),
    ("ixia", Target(engine="ixia", ixia_api_host="стенд",
                    ixia_chassis="шасси")),
])
def test_force_asked_for_one_run_reaches_the_engine(engine, target):
    """Флаг принимался, доезжал до RunSpec и там умирал: ни один движок его не
    читал. Форсить умел только липкий тумблер цели, который остаётся включённым
    для всех следующих прогонов - ровно то, чего флаг и должен избегать."""
    spec = RunSpec(duration=1, force=True)
    assert "--force" in engines.get(engine).args(target, spec, None)
    assert "--force" not in engines.get(engine).args(
        target, RunSpec(duration=1), None)


def test_the_command_line_offers_force_for_one_run_only():
    args = build_parser().parse_args(["run", "l3_ip", "--force"])
    assert args.force is True
    assert build_parser().parse_args(["run", "l3_ip"]).force is False


# --------------------------------------------------------------------------- #
# Сказанное доходит до человека
# --------------------------------------------------------------------------- #
def test_nothing_the_run_said_is_lost_to_the_next_sentence():
    """note - одно поле, и последний пишущий его забирает. Фраза про пустую
    запись затиралась тем, что done говорил про счётчики, и человек её не
    видел никогда."""
    result = RunResult()
    apply_events(result, [
        {"ev": "note", "msg": "запись rx пуста"},
        {"ev": "note", "msg": "порты отобраны с --force"},
        {"ev": "done", "tx": 10, "rx": 10, "note": "аппаратный счёт сошёлся"},
    ])
    assert result.notes == ["запись rx пуста", "порты отобраны с --force",
                            "аппаратный счёт сошёлся"]
    assert result.note == "аппаратный счёт сошёлся"


def test_an_empty_recording_still_admits_that_recording_happened():
    """Цену за запись прогон заплатил и с пустым файлом: у TRex это сервисный
    режим и просаженный потолок. Без этого прогон выглядел медленным без
    всякого объяснения."""
    result = RunResult(engine="trex", rx_source="flow_stats", reliable=True,
                       tx_pkts=10, rx_pkts=10)
    apply_events(result, [{"ev": "capture", "name": "rx", "bytes": 0}])
    assert result.recorded == ["rx"]
    assert any("сервисн" in w for w in result.warnings())


def test_json_prints_no_loss_figure_nobody_measured():
    """Экран давно не печатает ноль потерь там, где никто не считал, а JSON
    печатал: "loss_pct": 100.0 рядом с "rx_source": "none"."""
    blind = RunResult(tx_pkts=1000, rx_pkts=0, rx_source="none").to_dict()
    assert blind["loss_pct"] is None and blind["loss_pkts"] is None
    assert blind["loss_measured"] is False

    counted = RunResult(tx_pkts=1000, rx_pkts=990,
                        rx_source="flow_stats", reliable=True).to_dict()
    assert counted["loss_pct"] == 1.0 and counted["loss_measured"] is True


def test_loss_that_matches_the_sending_side_is_blamed_out_loud():
    """Недобор скорости и идущая запись теряют кадры до того, как их увидит
    устройство, - а колонка называется потерями. Печатать два факта отдельно и
    оставлять человека их сводить значит записать отставший генератор как
    коробку, которая роняет кадры."""
    result = RunResult(engine="trex", rx_source="flow_stats", reliable=True,
                       tx_pkts=1000, rx_pkts=950, requested_pps=1000,
                       achieved_pps=700, recorded=["rx"])
    said = " ".join(result.warnings())
    assert "первый подозреваемый здесь генератор" in said


# --------------------------------------------------------------------------- #
# Архив переживает обрыв
# --------------------------------------------------------------------------- #
class DyingTransport(Transport):
    """Отдаёт пару строк и обрывается - как оборванный SSH посреди прогона."""

    def __init__(self, lines):
        self.lines = lines
        self.script = ""

    def describe(self) -> str:
        return "тест"

    def run_stream(self, script, args, on_line, timeout=300, sudo=False,
                   secret=""):
        self.script = script
        for line in self.lines:
            on_line(line)
        raise TransportError("связь с целью потеряна")


def test_a_run_cut_short_still_leaves_its_archive():
    """Оборванный транспорт - ровно тот случай, ради которого архив и заводят:
    порты могли остаться за мёртвым прогоном, и единственный след того, что
    происходило, это накопленные события. Исключение уходило наверх до записи,
    и каталог прогона оставался недописанным мусором."""
    from pathlib import Path

    lines = ['@traphy {"ev": "tick", "t": 1.0, "tx": 10, "rx": 10}',
             '@traphy {"ev": "note", "msg": "идёт запись кадров"}']
    transport = DyingTransport(lines)
    with pytest.raises(TransportError):
        execute(presets.build("l3_ip"), Target(tx_iface="eth0"),
                RunSpec(duration=1), transport=transport)

    # Каталог прогона всё равно дописан, и в нём есть чем объяснить обрыв.
    from traphy.runner import run_dir_root

    latest = sorted(Path(run_dir_root()).iterdir())[-1]
    saved = json.loads((latest / "result.json").read_text(encoding="utf-8"))
    assert saved["rc"] != 0
    assert "идёт запись кадров" in saved["notes"]
    assert (latest / "events.jsonl").read_text(encoding="utf-8").count("\n") == 2


def test_completed_is_not_needed_for_the_archive_to_be_written():
    """Сторож от собственной ошибки: Completed импортируется ради подписи
    транспорта, и если он уедет, тест обрыва перестанет что-либо значить."""
    assert Completed(0, "", "").rc == 0


# --------------------------------------------------------------------------- #
# Гейт достоверности: когда прогон не стал измерением
# --------------------------------------------------------------------------- #
def test_a_port_left_in_service_mode_stops_the_next_run(trex, capsys):
    """Самый дорогой остаток: машина в сервисном режиме не пускает трафик
    вообще, и следующий человек видит отказ, к его работе отношения не имеющий.
    Связать его с записью, снятой часами раньше, не может никто."""
    FakeClient.port_service = True
    namespace = run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    assert namespace["_rc"] == 5
    said = [e["msg"] for e in events(capsys) if e["ev"] == "error"]
    assert said and "сервисном режиме" in said[0]


def test_a_link_that_drops_mid_run_disqualifies_the_measurement(trex, capsys):
    """До старта упавший линк заметит сам TRex и откажется стартовать. А линк,
    упавший посреди прогона, не ловится больше ничем: тишина в кабеле выглядит
    ровно как потери на устройстве."""
    FakeClient.port_link = "DOWN"
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    final = done_event(capsys)
    assert final["link_down"] is True

    result = RunResult(rx_source="flow_stats", reliable=True, tx_pkts=100,
                       rx_pkts=90, link_down=True)
    assert "линк падал по ходу прогона" in result.disqualified()
    assert result.valid_measurement() is False


def test_a_finite_plan_that_was_not_met_disqualifies_the_run(trex, capsys):
    """Недоотправка отменяет замер: прогон, не послав заказанного, ничего не
    сказал об устройстве. Но цифру потерь это не отменяет - она считается от
    того, что реально ушло, и остаётся верной арифметикой."""
    run_stl(codegen_stl.generate(presets.build("burst_probe")), QUICK)
    final = done_event(capsys)
    assert final["ordered"] > 0, "конечный план не объявлен"

    result = RunResult(rx_source="flow_stats", reliable=True,
                       ordered_pkts=final["ordered"], tx_pkts=1000, rx_pkts=990)
    why = result.disqualified()
    assert any("план не выполнен" in w for w in why), why
    # И цифра потерь на месте: выбросить верное вместе с бесполезным нельзя.
    assert result.loss_pct == pytest.approx(1.0)
    assert result.to_dict()["measurement_valid"] is False


def test_a_run_by_the_clock_has_no_plan_to_miss():
    """У continuous плана нет по устройству режима, и выдуманный план отменял бы
    годные замеры. Поэтому один такой поток делает бесплановым весь прогон."""
    assert codegen_stl.ordered_frames(presets.build("l3_ip")) == 0
    assert codegen_stl.ordered_frames(presets.build("burst_probe")) > 0


def test_a_clean_run_is_called_a_measurement(trex, capsys):
    """Сторож от перестраховки: гейт обязан пропускать нормальный прогон, иначе
    он просто перестанет что-либо значить."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    final = done_event(capsys)
    result = RunResult(rx_source=final["rx_source"], reliable=final["reliable"],
                       tx_pkts=final["tx"], rx_pkts=final["rx"],
                       requested_pps=1000, achieved_pps=1000,
                       ordered_pkts=final["ordered"],
                       link_down=final["link_down"])
    assert result.disqualified() == []
    assert result.valid_measurement() is True


# --------------------------------------------------------------------------- #
# Счётчики ошибок портов: про генератор, про линк или не про нас
# --------------------------------------------------------------------------- #
def test_generator_side_errors_take_the_loss_figure_away(trex, capsys):
    """Кадры, потерянные в приёмном тракте самого генератора, до устройства не
    дошли вообще. Посчитать их потерями значит записать нехватку буферов на
    нашей стороне как дефект коробки."""
    FakeClient.xstats_before = {"rx_missed": 0, "rx_crc_errors": 0}
    FakeClient.xstats_after = {"rx_missed": 1200, "rx_crc_errors": 0}
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    final = done_event(capsys)
    assert final["generator_errors"] == ["1:rx_missed"] or \
        "0:rx_missed" in final["generator_errors"]

    result = RunResult(rx_source="flow_stats", reliable=True, tx_pkts=100,
                       rx_pkts=90,
                       generator_errors=list(final["generator_errors"]),
                       port_errors=dict(final["port_errors"]))
    assert any("ошибок генератора" in w for w in result.disqualified())
    assert result.valid_measurement() is False


def test_link_side_errors_are_named_without_a_verdict(trex, capsys):
    """Ошибки линка - это кабель, оптика и согласование. Назвать их надо, а
    отменять по ним замер нельзя: это не наша сторона и не коробка."""
    FakeClient.xstats_before = {"rx_crc_errors": 5}
    FakeClient.xstats_after = {"rx_crc_errors": 42}
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    # capsys отдаёт накопленный вывод один раз, поэтому читаем его один раз.
    said = events(capsys)
    notes = [e["msg"] for e in said if e["ev"] == "note"]
    assert any("смотреть кабель" in n for n in notes), notes

    final = [e for e in said if e["ev"] == "done"][-1]
    assert not final["generator_errors"], "ошибки линка приняли за наши"
    result = RunResult(rx_source="flow_stats", reliable=True, tx_pkts=100,
                       rx_pkts=90, port_errors=dict(final["port_errors"]))
    assert result.disqualified() == []
    assert any("rx_crc_errors" in w for w in result.warnings())


def test_an_unfamiliar_counter_is_called_unfamiliar(trex, capsys):
    """Имена счётчиков приходят от драйвера, и одно и то же зовётся у разных
    карт по-разному. Выдумать приговор по незнакомому имени хуже, чем назвать
    его незнакомым и оставить разбор человеку."""
    FakeClient.xstats_after = {"rx_something_dropped_weirdly": 7}
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    notes = [e["msg"] for e in events(capsys) if e["ev"] == "note"]
    assert any("незнакомый счётчик" in n for n in notes), notes


def test_ordinary_frame_counters_are_not_mistaken_for_errors(trex, capsys):
    """Среди xstats полно обычных счётчиков кадров, и они растут на любом
    прогоне. Смешать их с ошибками значит утопить находку в шуме."""
    FakeClient.xstats_before = {"rx_good_packets": 0}
    FakeClient.xstats_after = {"rx_good_packets": 999999}
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    final = done_event(capsys)
    assert final["port_errors"] == {}, final["port_errors"]


# --------------------------------------------------------------------------- #
# Что меняем на чужой машине - возвращаем, и говорим об этом
# --------------------------------------------------------------------------- #
def promiscuous_calls(calls) -> list:
    return [c for c in calls if isinstance(c, tuple) and c[0] == "port_attr"]


def test_promiscuous_is_turned_on_for_the_run_and_put_back(trex, capsys):
    """Карта с выключенным promiscuous отбрасывает кадры с чужим MAC, и приём
    читается нулём при исправном линке. Пресеты шлют с выдуманными адресами, так
    что принимающий порт обязан их пропустить - но это изменение состояния чужой
    машины, и вернуть его обязаны мы."""
    FakeClient.port_service = False
    run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
    said = promiscuous_calls(FakeClient.last.calls)
    assert [c[2] for c in said] == [True, False], said
    assert all(c[1] == (1,) for c in said), "трогали не порт приёма"

    notes = [e["msg"] for e in events(capsys) if e["ev"] == "note"]
    assert any("promiscuous" in n for n in notes), notes


def test_promiscuous_already_on_is_left_alone(trex):
    """Не наше - не трогаем: включать уже включённое значит потом «вернуть» его
    в состояние, которого там не было."""
    FakeClient.port_link = "UP"
    monkey = {"prom": True, "link": "UP"}
    FakeClient.get_port_attr = lambda self, port: dict(monkey)
    try:
        run_stl(codegen_stl.generate(presets.build("l3_ip")), QUICK)
        assert promiscuous_calls(FakeClient.last.calls) == []
    finally:
        del FakeClient.get_port_attr


def test_a_service_mode_that_would_not_go_back_is_shouted_about(trex, capsys):
    """Молчащий отказ возврата - отравленный стенд без следа: следующий прогон
    на этой машине может не стартовать вовсе, и связать это с записью, снятой
    часами раньше, не сможет никто."""
    FakeClient.service_restore_fails = True
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            [*QUICK, "--capture", "--capture-limit", "10"])
    notes = [e["msg"] for e in events(capsys) if e["ev"] == "note"]
    assert any("ВЕРНУТЬ НЕ УДАЛОСЬ" in n for n in notes), notes


def test_only_the_ports_we_switched_are_switched_back(trex, capsys):
    """Возвращать чужое переключение так же неправильно, как не вернуть своё,
    поэтому запоминается список портов, а не «да/нет»."""
    run_stl(codegen_stl.generate(presets.build("l3_ip")),
            [*QUICK, "--capture", "--capture-limit", "10"])
    modes = [c for c in FakeClient.last.calls
             if isinstance(c, tuple) and c[0] == "service_mode"]
    assert modes, "сервисный режим не переключался"
    assert modes[0][2] is True and modes[-1][2] is False
    assert modes[0][1] == modes[-1][1], "вернули не то, что включали"


# --------------------------------------------------------------------------- #
# След аренды и уборка за убитым прогоном
# --------------------------------------------------------------------------- #
def lease_argv(folder, extra=()) -> list:
    return [*QUICK, "--lease-dir", str(folder), *extra]


def test_a_run_leaves_a_trace_while_it_holds_the_ports(trex, tmp_path):
    """Прогон, убитый сигналом, до своего finally не доходит - и без следа
    следующий человек видит порты, занятые неизвестно кем, и машину в
    состоянии, которого он не делал."""
    folder = tmp_path / "lease"
    seen = {}

    # Подсматриваем в момент, когда порты уже наши: после прогона след убран,
    # и снаружи его не увидеть - а проверять надо именно его существование.
    original = FakeClient.add_streams

    def peek(self, streams, ports=None):
        seen["files"] = sorted(p.name for p in folder.iterdir())
        return original(self, streams, ports=ports)

    FakeClient.add_streams = peek
    try:
        run_stl(codegen_stl.generate(presets.build("l3_ip")),
                lease_argv(folder))
    finally:
        FakeClient.add_streams = original

    assert seen["files"] == ["lease-0-1.json"], seen
    # А за собой прогон убрал: след остаётся только после смерти.
    assert list(folder.iterdir()) == []


def test_cleaning_up_after_nobody_says_there_was_nothing_to_clean(trex, capsys,
                                                                  tmp_path):
    """Уборка на чистой машине обязана быть безвредной и честной: «следа нет»
    это не ошибка инструмента и не повод что-то отбирать."""
    namespace = run_stl(codegen_stl.generate(presets.build("l2_ethernet")),
                        lease_argv(tmp_path, ["--recover-only"]))
    assert namespace["_rc"] == 2
    said = [e["msg"] for e in events(capsys) if e["ev"] == "error"]
    assert said and "убирать нечего" in said[0]
    assert FakeClient.last is None, "на демон полезли, хотя убирать нечего"


def test_a_living_run_is_never_cleaned_up_from_under_it(trex, capsys, tmp_path):
    """Отобрать у живого прогона - это --force, и это другое решение, которое
    принимает человек. Уборка трогает только мёртвых."""
    folder = tmp_path / "lease"
    folder.mkdir()
    live = json.loads(json.dumps(_identity_of_this_process()))
    (folder / "lease-0-1.json").write_text(
        json.dumps({**live, "ports": [0, 1], "tag": "живой", "at": "сейчас"}),
        encoding="utf-8")

    namespace = run_stl(codegen_stl.generate(presets.build("l2_ethernet")),
                        lease_argv(folder, ["--recover-only"]))
    assert namespace["_rc"] == 4
    said = [e["msg"] for e in events(capsys) if e["ev"] == "error"]
    assert said and "жив" in said[0]
    assert (folder / "lease-0-1.json").exists(), "след живого прогона удалён"
    assert FakeClient.last is None, "порты трогали у живого прогона"


def test_a_dead_run_is_cleaned_up_and_the_measurement_is_not_claimed_back(
        trex, capsys, tmp_path):
    """То, ради чего всё это: порты отданы, режим выключен, promiscuous
    возвращён. И сказано вслух, что измерение НЕ восстановлено - прогон, за
    которым убирали, не состоялся."""
    folder = tmp_path / "lease"
    folder.mkdir()
    (folder / "lease-0-1.json").write_text(json.dumps({
        "pid": 999999, "boot": "машина-с-тех-пор-перезагружалась",
        "started": "1", "ports": [0, 1], "tag": "мёртвый",
        "at": "2026-10-01 15:10:45", "service_ports": [0, 1],
        "promiscuous": [1, False],
    }), encoding="utf-8")

    namespace = run_stl(codegen_stl.generate(presets.build("l2_ethernet")),
                        lease_argv(folder, ["--recover-only"]))
    assert namespace["_rc"] == 0
    calls = FakeClient.last.calls
    assert ("acquire", (0, 1), True) in calls, "порты не забрали у мёртвого"
    assert ("service_mode", (0, 1), False) in calls
    assert ("port_attr", (1,), False) in calls, "promiscuous не возвращён"
    assert ("release", (0, 1)) in calls

    notes = [e["msg"] for e in events(capsys) if e["ev"] == "note"]
    assert any("ИЗМЕРЕНИЕ НЕ ВОССТАНОВЛЕНО" in n for n in notes), notes
    assert not list(folder.iterdir()), "след не убран после уборки"


def _identity_of_this_process() -> dict:
    """Опознание текущего процесса - того самого, что сейчас жив."""
    import os

    boot = ""
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            boot = fh.read().strip()
    except OSError:
        pass
    started = ""
    try:
        with open(f"/proc/{os.getpid()}/stat") as fh:
            started = fh.read().rsplit(") ", 1)[-1].split()[19]
    except (OSError, IndexError):
        pass
    return {"pid": os.getpid(), "boot": boot, "started": started}


def test_only_an_engine_that_owns_ports_offers_to_clean_up():
    """У Scapy нет ни следа аренды, ни владения портами - заставлять его
    реализовать уборку нельзя, поэтому умолчание отрицательное."""
    assert engines.get("trex").can_recover is True
    assert engines.get("scapy").can_recover is False
    assert engines.get("jmeter").can_recover is False
