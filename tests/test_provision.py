"""Подготовка генератора: что инструмент обязан отказаться делать.

Привязка карты к DPDK уводит её из ядра целиком, и ошибиться тут дорого: в
худшем случае человек теряет доступ к машине, которую настраивал, и узнаёт об
этом по тишине. Поэтому главное здесь не «план построился», а «план отказался
строиться, и сказал почему».

Ни одного подключения: план - чистая функция от состояния генератора. Все
адреса и имена выдуманы.
"""
from __future__ import annotations

import pytest

from traphy import provision
from traphy.provision import Generator, Nic


def nic(pci, name="eth1", driver="ice", **kw):
    return Nic(pci=pci, name=name, driver=driver,
               kernel_driver=kw.pop("kernel_driver", driver),
               mac=kw.pop("mac", "02:00:00:00:00:01"), **kw)


def generator(**kw):
    """Генератор, на котором всё в порядке. Тесты ломают по одному месту."""
    base = dict(
        ok=True, hostname="gen", trex_dir="/opt/trex", trex_version="3.04",
        has_trex_stl=True, devbind="/opt/trex/dpdk-devbind.py",
        hugepages_total=4096, hugepages_free=4096, hugepage_kb=2048,
        iommu="on", vfio_loaded=True, is_root=True,
        cfg_path="/etc/trex_cfg.yaml",
        nics=[nic("0000:3b:00.0", "eth1"),
              nic("0000:3b:00.1", "eth2", mac="02:00:00:00:00:02"),
              nic("0000:00:1f.6", "eno1", address="192.0.2.50",
                  carries_session=True, has_routes=True)],
    )
    base.update(kw)
    return Generator(**base)


PORTS = ["0000:3b:00.0", "0000:3b:00.1"]


# --- отказы: то, чего инструмент не сделает ------------------------------

def test_refuses_the_card_that_carries_the_session():
    """Самый дорогой способ ошибиться: отрезать себе доступ к машине."""
    plan = provision.build_plan(generator(), ["0000:00:1f.6"])
    assert not plan.possible
    assert any("текущий сеанс" in r for r in plan.refusals)


def test_refusal_names_the_card_and_what_to_do():
    plan = provision.build_plan(generator(), ["0000:00:1f.6"])
    said = " ".join(plan.refusals)
    assert "0000:00:1f.6" in said and "eno1" in said
    assert "другой порт" in said or "канал управления" in said


def test_refuses_when_there_is_no_release():
    plan = provision.build_plan(generator(trex_dir="", devbind=""), PORTS)
    assert not plan.possible
    assert any("нет релиза TRex" in r for r in plan.refusals)


def test_refuses_a_directory_without_control_plane():
    plan = provision.build_plan(generator(has_trex_stl=False), PORTS)
    assert any("control plane" in r for r in plan.refusals)


def test_refuses_without_the_bind_script():
    plan = provision.build_plan(generator(devbind=""), PORTS)
    assert any("dpdk-devbind" in r for r in plan.refusals)


def test_refuses_without_root_or_sudo():
    plan = provision.build_plan(generator(is_root=False, can_sudo=False), PORTS)
    assert any("sudo" in r for r in plan.refusals)


def test_refuses_an_unknown_card():
    plan = provision.build_plan(generator(), ["0000:99:00.0"])
    assert any("0000:99:00.0" in r for r in plan.refusals)


def test_every_refusal_is_reported_at_once():
    """Чинить по одному отказу за попытку - это пять заходов вместо одного."""
    plan = provision.build_plan(
        generator(trex_dir="", devbind="", is_root=False, can_sudo=False), [])
    assert len(plan.refusals) >= 3


# --- IOMMU: отказ, который снимается осознанно ---------------------------

def test_iommu_off_is_a_refusal_by_default():
    plan = provision.build_plan(generator(iommu="off"), PORTS)
    assert not plan.possible
    assert any("IOMMU" in r for r in plan.refusals)


def test_no_iommu_is_allowed_only_when_asked_and_says_what_it_costs():
    plan = provision.build_plan(generator(iommu="off"), PORTS, allow_noiommu=True)
    assert plan.possible
    step = next(s for s in plan.steps if s.key == "noiommu")
    assert "без защиты" in step.breaks


# --- шаги: только то, чего не хватает ------------------------------------

def test_hugepages_are_added_only_when_short():
    enough = provision.build_plan(generator(), PORTS)
    assert not any(s.key == "hugepages" for s in enough.steps)
    short = provision.build_plan(generator(hugepages_total=0), PORTS)
    assert any(s.key == "hugepages" for s in short.steps)


def test_hugepages_step_counts_pages_not_megabytes():
    plan = provision.build_plan(generator(hugepages_total=0), PORTS)
    step = next(s for s in plan.steps if s.key == "hugepages")
    # Два порта по 1024 МБ страницами по 2048 КБ - это 1024 страницы.
    assert "vm.nr_hugepages=1024" in step.command


def test_hugepages_step_says_it_will_not_survive_a_reboot():
    plan = provision.build_plan(generator(hugepages_total=0), PORTS)
    assert any("перезагрузк" in note for note in plan.notes)


def test_vfio_is_loaded_only_when_missing():
    assert not any(s.key == "vfio"
                   for s in provision.build_plan(generator(), PORTS).steps)
    plan = provision.build_plan(generator(vfio_loaded=False), PORTS)
    assert any(s.key == "vfio" for s in plan.steps)


def test_card_already_on_dpdk_is_not_bound_again():
    gen = generator(nics=[
        nic("0000:3b:00.0", "", driver="vfio-pci", kernel_driver="ice"),
        nic("0000:3b:00.1", "eth2"),
    ])
    plan = provision.build_plan(gen, PORTS)
    bound = [s.key for s in plan.steps if s.key.startswith("bind:")]
    assert bound == ["bind:0000:3b:00.1"]


def test_bind_step_says_what_it_breaks_and_how_to_undo_it():
    plan = provision.build_plan(generator(), PORTS)
    step = next(s for s in plan.steps if s.key == "bind:0000:3b:00.0")
    assert step.breaks
    assert "--bind=ice" in step.reversible


def test_daemon_is_started_only_when_it_is_not_running():
    assert any(s.key == "daemon"
               for s in provision.build_plan(generator(), PORTS).steps)
    running = provision.build_plan(generator(daemon_running=True, daemon_pid=42), PORTS)
    assert not any(s.key == "daemon" for s in running.steps)
    assert any("перезапуст" in note for note in running.notes)


# --- конфигурация --------------------------------------------------------

def test_config_keeps_the_order_it_was_given():
    """Порядок в файле и есть номера портов - перепутать его дорого."""
    text = provision.trex_cfg(generator(), PORTS)
    assert '"0000:3b:00.0", "0000:3b:00.1"' in text
    assert text.index("0000:3b:00.0") < text.index("0000:3b:00.1")


def test_config_points_each_port_at_its_neighbour():
    """Раскладка «порт в порт»: dest_mac одного - это src_mac другого."""
    text = provision.trex_cfg(generator(), PORTS)
    assert "src_mac:  '02:00:00:00:00:01'" in text
    assert "dest_mac: '02:00:00:00:00:02'" in text
    assert "src_mac:  '02:00:00:00:00:02'" in text
    assert "dest_mac: '02:00:00:00:00:01'" in text


def test_config_warns_that_a_box_in_between_changes_dest_mac():
    """Молчаливо неверный dest_mac выглядит как 100% потерь и ищется долго."""
    assert "коробку" in provision.trex_cfg(generator(), PORTS)


def test_changed_port_order_is_called_out():
    gen = generator(cfg_exists=True, cfg_ports=["0000:3b:00.1", "0000:3b:00.0"])
    plan = provision.build_plan(gen, PORTS)
    assert any("номера сдвинутся" in note for note in plan.notes)


def test_config_is_not_rewritten_when_it_already_matches():
    gen = generator(cfg_exists=True, cfg_ports=PORTS)
    plan = provision.build_plan(gen, PORTS)
    assert not any(s.key == "cfg" for s in plan.steps)


# --- два режима ----------------------------------------------------------

def test_plan_hands_out_bare_commands_for_doing_it_by_hand():
    plan = provision.build_plan(generator(vfio_loaded=False), PORTS)
    assert "modprobe vfio-pci" in plan.commands()


def test_breakage_is_collected_in_one_place():
    """Это читают до согласия, поэтому оно не должно быть размазано по шагам."""
    plan = provision.build_plan(generator(), PORTS)
    assert plan.breakage()
    assert all(": " in line for line in plan.breakage())


def test_nothing_to_do_is_not_the_same_as_cannot():
    gen = generator(daemon_running=True, cfg_exists=True, cfg_ports=PORTS,
                    nics=[nic("0000:3b:00.0", "", driver="vfio-pci"),
                          nic("0000:3b:00.1", "", driver="vfio-pci")])
    plan = provision.build_plan(gen, PORTS)
    assert plan.nothing_to_do and not plan.refusals


@pytest.mark.parametrize("field_name,value,wanted", [
    ("carries_session", True, "сеанс"),
    ("has_routes", True, "маршруты"),
])
def test_card_says_what_is_wrong_with_touching_it(field_name, value, wanted):
    card = nic("0000:3b:00.0", "eth1", **{field_name: value})
    assert wanted in card.warning()


# --- выполнение: что считается успехом и что попадает в журнал ------------

class FakeTransport:
    """Транспорт, который отдаёт заранее записанные события."""

    def __init__(self, lines, raise_with=None):
        self.lines = lines
        self.raise_with = raise_with
        self.sent_sudo = None
        self.payload = None

    def run_stream(self, script, args, on_line, timeout=0, sudo=False, secret=""):
        self.sent_sudo = sudo
        self.payload = args[0] if args else ""
        if self.raise_with:
            raise self.raise_with
        for line in self.lines:
            on_line(line)
        return None


def good_plan():
    return provision.build_plan(generator(vfio_loaded=False), PORTS)


def test_apply_refuses_a_plan_that_cannot_be_run():
    plan = provision.build_plan(generator(), ["0000:00:1f.6"])
    transport = FakeTransport([])
    ok, log = provision.apply(transport, plan, "/etc/trex_cfg.yaml")
    assert not ok
    assert transport.payload is None, "отказной план не должен никуда уезжать"
    assert any("текущий сеанс" in line for line in log)


def test_apply_runs_with_elevation():
    """Все шаги привилегированные - без sudo он просто не сработает."""
    transport = FakeTransport(['{"ev": "done", "ok": true}'])
    provision.apply(transport, good_plan(), "/etc/trex_cfg.yaml")
    assert transport.sent_sudo is True


def test_apply_sends_the_config_text_with_the_plan():
    """Текст конфигурации едет вместе с планом, а не собирается на той стороне."""
    import json as _json
    transport = FakeTransport(['{"ev": "done", "ok": true}'])
    plan = good_plan()
    provision.apply(transport, plan, "/etc/trex_cfg.yaml")
    sent = _json.loads(transport.payload)
    assert sent["cfg_path"] == "/etc/trex_cfg.yaml"
    assert "interfaces:" in sent["cfg_text"]
    assert [s["key"] for s in sent["steps"]] == [s.key for s in plan.steps]


def test_apply_reports_success_only_on_the_final_event():
    """Шаги прошли, а итога нет - это не успех, а оборванный прогон."""
    transport = FakeTransport(['{"ev": "step", "key": "vfio", "state": "ok"}'])
    ok, _ = provision.apply(transport, good_plan(), "/etc/trex_cfg.yaml")
    assert not ok


def test_apply_keeps_the_refusal_in_the_log():
    transport = FakeTransport([
        '{"ev": "step", "key": "vfio", "title": "Загрузить модуль", "state": "start"}',
        '{"ev": "step", "key": "vfio", "state": "fail", "error": "нет такого модуля"}',
        '{"ev": "done", "ok": false}',
    ])
    ok, log = provision.apply(transport, good_plan(), "/etc/trex_cfg.yaml")
    assert not ok
    assert any("нет такого модуля" in line for line in log)


def test_apply_survives_a_dead_transport():
    from traphy.transport import TransportError
    transport = FakeTransport([], raise_with=TransportError("связь оборвалась"))
    ok, log = provision.apply(transport, good_plan(), "/etc/trex_cfg.yaml")
    assert not ok and any("оборвалась" in line for line in log)


def test_events_reach_the_caller_as_they_come():
    seen = []
    transport = FakeTransport([
        '{"ev": "begin", "total": 2}',
        '{"ev": "step", "key": "vfio", "state": "ok"}',
        '{"ev": "done", "ok": true}',
    ])
    provision.apply(transport, good_plan(), "/etc/trex_cfg.yaml", on_event=seen.append)
    assert [e["ev"] for e in seen] == ["begin", "step", "done"]


def test_a_line_that_is_not_an_event_is_not_lost():
    """Чужой вывод в журнале нужнее, чем тишина: по нему и ищут причину."""
    transport = FakeTransport(["sudo: a password is required",
                               '{"ev": "done", "ok": false}'])
    _, log = provision.apply(transport, good_plan(), "/etc/trex_cfg.yaml")
    assert "sudo: a password is required" in log


# --- экран: что видно и чем это заперто ----------------------------------

def test_the_row_is_locked_for_scapy_and_says_why():
    """Строка, открывающая пустой экран, хуже отсутствующей."""
    from traphy import menu
    from traphy.session import Session

    session = Session()
    session.target.engine = "scapy"
    row = next(r for r in menu.ROWS if r.key == "provision")
    reason = menu.locked_reason(row, session)
    assert reason and "TRex" in reason
    assert menu.unlock_row(row, session).key == "setup"


def test_the_row_opens_for_trex():
    from traphy import menu
    from traphy.session import Session

    session = Session()
    session.target.engine = "trex"
    row = next(r for r in menu.ROWS if r.key == "provision")
    assert menu.locked_reason(row, session) == ""


def test_the_session_card_cannot_be_picked():
    """Отказ произносится в момент нажатия, а не прячется в плане."""
    from traphy.screens import provision as screen

    state = {"gen": generator(), "picked": [], "status": "", "role": "dim",
             "mode": provision.DPDK}
    card = next(n for n in state["gen"].nics if n.carries_session)
    screen._toggle(state, card)
    assert state["picked"] == []
    assert "текущий сеанс" in state["status"]


def test_order_of_picking_is_the_port_order():
    from traphy.screens import provision as screen

    gen = generator()
    state = {"gen": gen, "picked": [], "status": "", "role": "dim",
             "mode": provision.DPDK}
    screen._toggle(state, gen.nics[1])
    screen._toggle(state, gen.nics[0])
    assert state["picked"] == ["0000:3b:00.1", "0000:3b:00.0"]
    assert provision.trex_cfg(gen, state["picked"]).index("0000:3b:00.1") < \
        provision.trex_cfg(gen, state["picked"]).index("0000:3b:00.0")


def test_a_third_port_is_refused_with_a_reason():
    from traphy.screens import provision as screen

    gen = generator(nics=[nic(f"0000:3b:00.{i}", f"eth{i}") for i in range(3)])
    state = {"gen": gen, "picked": [], "status": "", "role": "dim",
             "mode": provision.DPDK}
    for card in gen.nics:
        screen._toggle(state, card)
    assert len(state["picked"]) == 2
    assert "двух портов достаточно" in state["status"]


def test_picking_the_same_card_twice_unpicks_it():
    from traphy.screens import provision as screen

    gen = generator()
    state = {"gen": gen, "picked": [], "status": "", "role": "dim",
             "mode": provision.DPDK}
    screen._toggle(state, gen.nics[0])
    screen._toggle(state, gen.nics[0])
    assert state["picked"] == []


# --- морда: экран говорит словами выбранного движка ----------------------

def _session(engine: str):
    from traphy.session import Session

    session = Session(version="0.1.0")
    session.target.engine = engine
    return session


def test_tagline_belongs_to_the_engine():
    """«Погнать скриптом» неверно для TRex: скрипт никуда не уезжает."""
    from traphy import menu

    assert "скрипт" in menu._tagline(_session("scapy"))
    assert "карт" in menu._tagline(_session("trex"))
    assert "скрипт" not in menu._tagline(_session("trex"))


def test_setup_hint_belongs_to_the_engine():
    """У TRex нет интерфейсов - есть индексы портов из trex_cfg.yaml."""
    from traphy import menu

    row = next(r for r in menu.ROWS if r.key == "setup")
    assert "интерфейс" in menu._row_line(row, _session("scapy"), selected=False)
    assert "интерфейс" not in menu._row_line(row, _session("trex"), selected=False)


def test_trex_prepares_the_generator_before_setting_the_target_up():
    """Номера портов берутся из конфигурации, а создаёт её подготовка."""
    from traphy import menu

    order = [r.key for r in menu.rows_for(_session("trex"))]
    assert order.index("provision") < order.index("setup")


def test_scapy_keeps_the_old_order():
    from traphy import menu

    order = [r.key for r in menu.rows_for(_session("scapy"))]
    assert order.index("setup") < order.index("provision")


def test_reordering_keeps_every_row():
    from traphy import menu

    for engine in ("scapy", "trex"):
        assert sorted(r.key for r in menu.rows_for(_session(engine))) == \
            sorted(r.key for r in menu.ROWS)


def test_no_generator_line_for_an_engine_that_needs_no_preparing():
    from traphy import menu

    assert menu._generator_line(_session("scapy"))[0] == ""


def test_generator_line_says_it_was_never_asked():
    from traphy import menu

    text, role = menu._generator_line(_session("trex"))
    assert "не опрашивался" in text and role == "dim"


def test_generator_line_is_green_only_when_a_run_could_actually_go():
    from traphy import menu

    session = _session("trex")
    ready = Generator(ok=True, trex_version="3.04", hugepages_total=1024,
                      daemon_running=True,
                      nics=[nic("a", driver="vfio-pci"), nic("b", driver="vfio-pci")])
    session.generator = ready
    assert menu._generator_line(session)[1] == "ok"
    # Демон поднят, но карты ядру не отдавали - прогон не пойдёт.
    session.generator = Generator(ok=True, hugepages_total=1024, daemon_running=True,
                                  nics=[nic("a", driver="ice")])
    assert menu._generator_line(session)[1] == "warn"
    # Карты отданы, страниц нет - TRex стартует и падает на буферах.
    session.generator = Generator(ok=True, hugepages_total=0, daemon_running=True,
                                  nics=[nic("a", driver="vfio-pci")])
    assert menu._generator_line(session)[1] == "warn"


def test_generator_line_fits_the_panel_even_when_everything_is_wrong():
    """Обрезанная строка про поломку - это строка, которой нельзя доверять."""
    from traphy import menu, ui

    session = _session("trex")
    session.generator = Generator(ok=True, trex_version="3.04.0-rc2",
                                  hugepages_total=0, daemon_running=False,
                                  nics=[nic("a", driver="ice")])
    text, _ = menu._generator_line(session)
    assert ui.width_of(text) <= ui.WIDTH - 4
    assert "…" not in text, "важное обрезали вместо версии"
    assert "страниц нет" in text and "демон не поднят" in text


def test_a_broken_survey_is_reported_not_hidden():
    from traphy import menu

    session = _session("trex")
    session.generator = Generator(ok=False, error="нет маршрута")
    text, role = menu._generator_line(session)
    assert "нет маршрута" in text and role == "warn"


# --- живой экран: условия замера видно во время прогона -------------------

def _live(engine="trex"):
    from traphy.models import Profile
    from traphy.runspec import RunSpec
    from traphy.screens import execute

    session = _session(engine)
    session.profile = Profile(name="l3_ip")
    return execute._Live(session, RunSpec(duration=5))


def test_both_receive_counters_are_shown_side_by_side():
    """Они расходятся на порядки, и выбирать за человека экран не должен."""
    run = _live()
    run.on_event({"ev": "tick", "t": 1.0, "tx": 25000, "rx": 84295606,
                  "rx_port": 84295606, "rx_groups": 85841255, "pps": 9892})
    panel = run._panel()
    assert "84 295 606" in panel and "85 841 255" in panel


def test_scapy_is_not_shown_counters_it_does_not_have():
    run = _live("scapy")
    run.on_event({"ev": "tick", "t": 1.0, "tx": 10, "rx": 10,
                  "rx_port": 10, "rx_groups": 0, "pps": 1})
    assert "принято портом" not in run._panel()


def test_a_dirty_segment_is_reported_before_the_run_not_after():
    """Сто миллионов принятых против четырёх тысяч отправленных объясняются
    именно этим - и объяснение нужно в момент прогона."""
    run = _live()
    run.on_event({"ev": "idle", "rx_port": 16494543, "rx_groups": 0})
    panel = run._panel()
    assert "сегмент залит" in panel and "16 494 543" in panel


def test_a_clean_idle_check_says_nothing():
    run = _live()
    run.on_event({"ev": "idle", "rx_port": 0, "rx_groups": 0})
    assert "сегмент залит" not in run._panel()


def test_growing_port_errors_are_named():
    """Без них «потерь нет» и «потери все» выглядят одинаково уверенно."""
    run = _live()
    run.on_event({"ev": "xstats", "grew": {"rx_missed_errors": 7168304}})
    panel = run._panel()
    assert "rx_missed_errors" in panel and "7 168 304" in panel


def test_a_dead_rx_link_is_called_out():
    run = _live()
    run.on_event({"ev": "tick", "t": 1.0, "tx": 100, "rx": 0,
                  "rx_port": 0, "rx_groups": 0, "pps": 10, "link_down": True})
    assert "линк" in run._panel()


def test_conditions_do_not_crowd_the_panel_when_everything_is_clean():
    run = _live()
    run.on_event({"ev": "tick", "t": 1.0, "tx": 100, "rx": 100,
                  "rx_port": 0, "rx_groups": 0, "pps": 10})
    panel = run._panel()
    for noise in ("сегмент залит", "линк", "rx_missed"):
        assert noise not in panel


# --- третий расклад: TRex поверх ядра ------------------------------------

def test_af_packet_needs_no_binding_and_no_vfio():
    """Карта остаётся в ядре - привязывать и выгружать нечего."""
    gen = generator(vfio_loaded=False, iommu="off", devbind="")
    plan = provision.build_plan(gen, PORTS, mode=provision.AF_PACKET)
    assert plan.possible
    keys = [s.key for s in plan.steps]
    assert not any(k.startswith("bind:") for k in keys)
    assert "vfio" not in keys and "noiommu" not in keys


def test_iommu_off_does_not_refuse_af_packet():
    """Отказ по IOMMU - про vfio, а vfio тут не участвует."""
    plan = provision.build_plan(generator(iommu="off"), PORTS,
                                mode=provision.AF_PACKET)
    assert plan.possible


def test_af_packet_starts_the_daemon_in_software_mode():
    plan = provision.build_plan(generator(), PORTS, mode=provision.AF_PACKET)
    daemon = next(s for s in plan.steps if s.key == "daemon")
    assert "--software" in daemon.command
    dpdk = provision.build_plan(generator(), PORTS, mode=provision.DPDK)
    assert "--software" not in next(s for s in dpdk.steps if s.key == "daemon").command


def test_af_packet_names_interfaces_not_pci():
    """TRex обращается к карте ядра по имени через виртуальное устройство."""
    text = provision.trex_cfg(generator(), PORTS, mode=provision.AF_PACKET)
    assert "--vdev=net_af_packet0,iface=eth1" in text
    assert "--vdev=net_af_packet1,iface=eth2" in text
    assert "0000:3b:00.0" not in text.split("interfaces:")[1].split("\n")[0]


def test_af_packet_config_says_what_it_is_not():
    """Его цифры легко принять за проверку data plane. Это не она."""
    text = provision.trex_cfg(generator(), PORTS, mode=provision.AF_PACKET)
    assert "1 Mpps" in text and "линейной скорости" in text


def test_the_session_card_is_allowed_in_af_packet_but_called_out():
    """Карта остаётся в ядре - связь не оборвётся. Но нагрузка пойдёт туда же."""
    plan = provision.build_plan(generator(), ["0000:00:1f.6"],
                                mode=provision.AF_PACKET)
    assert plan.possible, "в af_packet это не отказ"
    assert any("канал управления" in note or "собственным трафиком" in note
               for note in plan.notes)


def test_a_card_already_taken_by_dpdk_is_refused_in_af_packet():
    """Ядро её уже не видит - обращаться по имени не к чему."""
    gen = generator(nics=[nic("0000:3b:00.0", "", driver="vfio-pci",
                              kernel_driver="ice")])
    plan = provision.build_plan(gen, ["0000:3b:00.0"], mode=provision.AF_PACKET)
    assert not plan.possible
    assert any("верни её ядру" in why for why in plan.refusals)


def test_switching_mode_says_what_it_costs():
    from traphy.screens import provision as screen

    state = {"gen": generator(), "picked": [], "status": "", "role": "dim",
             "mode": provision.DPDK}
    screen._switch(state)
    assert state["mode"] == provision.AF_PACKET
    assert "1 Mpps" in state["status"]
    screen._switch(state)
    assert state["mode"] == provision.DPDK


def test_the_session_card_can_be_picked_in_af_packet():
    from traphy.screens import provision as screen

    gen = generator()
    card = next(n for n in gen.nics if n.carries_session)
    state = {"gen": gen, "picked": [], "status": "", "role": "dim",
             "mode": provision.AF_PACKET}
    screen._toggle(state, card)
    assert state["picked"] == [card.pci]
