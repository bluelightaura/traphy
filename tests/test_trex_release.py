"""Уровень 0: сгенерированный скрипт против настоящего релиза TRex.

Остальные тесты TRex гоняют скрипт против подделки, и у подделки есть предел,
который надо называть вслух: её и вызовы писал один человек. Если настоящий
метод зовётся иначе, подделка будет названа тем же неверным именем, и все тесты
останутся зелёными. Проверить имена может только сама библиотека.

Для этого не нужен ни стенд, ни DPDK, ни карты, ни демон, ни root - только
распакованный релиз. Поэтому этот файл молчит, пока ему не покажут, где он::

    TRAPHY_TREX_DIR=/opt/trex-3.08 pytest tests/test_trex_release.py -v

Ожидаемая поверхность не записана здесь руками, а вынимается из свежесобранного
скрипта разбором его же дерева. Список, который надо помнить и обновлять, - это
список, который разойдётся с кодом; этот расходиться не умеет.
"""

from __future__ import annotations

import ast
import inspect
import os
import sys

import pytest

from traphy import codegen_stl, presets

RELEASE = os.environ.get("TRAPHY_TREX_DIR", "")

pytestmark = pytest.mark.skipif(
    not RELEASE,
    reason="нет распакованного релиза TRex: задай TRAPHY_TREX_DIR")


# --------------------------------------------------------------------------- #
# Что скрипт вообще требует от библиотеки
# --------------------------------------------------------------------------- #
def _wanted(source: str, owner: str) -> dict[str, set[str]]:
    """Имена и именованные аргументы, которые скрипт зовёт у ``owner``."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        base = func.value
        if isinstance(base, ast.Name) and base.id == owner:
            out.setdefault(func.attr, set()).update(
                kw.arg for kw in node.keywords if kw.arg)
    return out


def _attributes(source: str, owner: str) -> set[str]:
    """Имена, которые скрипт берёт у ``owner`` - вызывает он их или нет."""
    out: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute):
            base = node.value
            if isinstance(base, ast.Name) and base.id == owner:
                out.add(node.attr)
    return out


def _accepts(func, names: set[str]) -> list[str]:
    """Какие из этих именованных аргументов функция не примет.

    Обёрнутый декоратором метод показывает ``**kwargs`` и принимает всё - тогда
    проверка ничего не докажет, но и не соврёт: пустой список значит «возражений
    нет», а не «сверено до конца».
    """
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return []
    params = sig.parameters
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return []
    return sorted(n for n in names if n not in params)


@pytest.fixture(scope="module")
def script() -> str:
    """Скрипт для профиля с перебором адресов - самый требовательный к VM."""
    return codegen_stl.generate(presets.build("ip_sweep"))


@pytest.fixture(scope="module")
def api(script):
    """Настоящая библиотека релиза, загруженная так же, как её грузит скрипт."""
    before = list(sys.path)
    namespace: dict = {"__name__": "generated"}
    exec(compile(script, "generated_stl.py", "exec"), namespace)
    try:
        loaded = namespace["load_api"](RELEASE)
    except Exception as exc:
        sys.path[:] = before
        pytest.fail(f"{RELEASE}: библиотека не загрузилась - {exc}")
    yield loaded
    sys.path[:] = before


# --------------------------------------------------------------------------- #
# Имена
# --------------------------------------------------------------------------- #
def test_the_release_has_every_name_the_script_takes_from_it(api, script):
    """0.2 из BENCH.md: сошлись ли имена классов."""
    missing = sorted(n for n in _attributes(script, "api")
                     if not hasattr(api, n))
    assert not missing, f"релиз не знает: {', '.join(missing)}"


def test_the_client_has_every_method_the_script_calls(api, script):
    """Та часть, которую подделка доказать не может: она знает те же имена,
    что и вызовы, потому что писались вместе."""
    client = api.STLClient
    missing = sorted(m for m in _wanted(script, "client")
                     if not hasattr(client, m))
    assert not missing, f"STLClient не знает: {', '.join(missing)}"


def test_the_client_has_every_method_the_probe_calls(api):
    """Опрос цели - такой же клиент демона, и его имена подделка доказать не
    может по той же причине: она знает ровно те имена, которые в неё вписали.

    Расхождение тут не роняет прогон, а делает хуже - порты показываются без
    подробностей, то есть «линк не сказан» на живом линке, и человек вбивает
    номер на память, как до всей этой диагностики.
    """
    from traphy import probe

    client = api.STLClient
    missing = sorted(m for m in _wanted(probe.PROBE_SCRIPT, "client")
                     if not hasattr(client, m))
    assert not missing, f"STLClient не знает: {', '.join(missing)}"


def test_the_client_accepts_the_keywords_the_probe_passes(api):
    """``get_port_attr(port=)`` - то, чем опрос спрашивает про каждый порт."""
    from traphy import probe

    client = api.STLClient
    wrong: list[str] = []
    for method, names in sorted(_wanted(probe.PROBE_SCRIPT, "client").items()):
        attr = getattr(client, method, None)
        if attr is None:
            continue
        refused = _accepts(attr, names)
        if refused:
            wrong.append(f"{method}: {', '.join(refused)}")
    assert not wrong, "релиз не примет: " + "; ".join(wrong)


def test_the_client_accepts_the_keywords_the_script_passes(api, script):
    """Владение портами целиком висит на этих подписях: `acquire(ports=,
    force=)`, `release(ports=)`, `remove_all_streams(ports=)`."""
    client = api.STLClient
    wrong: list[str] = []
    for method, names in sorted(_wanted(script, "client").items()):
        attr = getattr(client, method, None)
        if attr is None:
            continue
        bad = _accepts(attr, names)
        if bad:
            wrong.append(f"{method}({', '.join(bad)})")
    assert not wrong, "аргументы не приняты: " + "; ".join(wrong)


def test_the_stream_classes_accept_the_keywords_the_script_passes(api, script):
    """0.2 из BENCH.md: аргументы `STLVmFlowVar` и соседей."""
    wrong: list[str] = []
    for name, names in sorted(_wanted(script, "api").items()):
        cls = getattr(api, name, None)
        if cls is None or not names:
            continue
        bad = _accepts(cls.__init__, names)
        if bad:
            wrong.append(f"{name}({', '.join(bad)})")
    assert not wrong, "аргументы не приняты: " + "; ".join(wrong)


# --------------------------------------------------------------------------- #
# Сборка
# --------------------------------------------------------------------------- #
def test_a_profile_builds_against_the_real_library(api, script):
    """0.2: профиль собрался, и обход дал столько кадров, сколько просили."""
    namespace: dict = {"__name__": "generated"}
    exec(compile(script, "generated_stl.py", "exec"), namespace)
    streams, frames, pg_ids, uncounted = namespace["build_streams"](
        api, namespace["layers"](api), True)
    assert streams and frames
    assert namespace["VM_FRAMES"]["ip_sweep"] == 254
    assert pg_ids, "не выдано ни одной группы аппаратного счёта"
    assert not uncounted


def test_the_frame_is_built_by_the_scapy_inside_the_release(api):
    """0.3: смещения полей считались против той Scapy, что лежит в релизе.

    Системная Scapy другой версии разложит заголовки иначе, и field engine
    начнёт писать байты не туда - молча, потому что кадр останется валидным.
    """
    scapy = sys.modules.get("scapy.all") or sys.modules.get("scapy")
    assert scapy is not None, "релиз не притянул свою Scapy"
    where = os.path.realpath(getattr(scapy, "__file__", "") or "")
    assert where.startswith(os.path.realpath(RELEASE)), (
        f"Scapy взялась не из релиза, а из {where}")


def test_the_frame_is_packed_without_fcs(api, script):
    """Конвенция модели: `frame_size` - это байты без FCS. Классический тест
    «64-байтным кадром» в traphy задаётся как 60, и примеры TRex тут вычитают
    четвёрку из своего размера - сверять с ними в лоб нельзя."""
    namespace: dict = {"__name__": "generated"}
    exec(compile(script, "generated_stl.py", "exec"), namespace)
    _, frames, _, _ = namespace["build_streams"](
        api, namespace["layers"](api), True)
    wanted = presets.build("ip_sweep").streams[0].frame_size
    assert len(frames[0]) == wanted
