"""Постоянная проверка связи с целью, снятая с рисующего потока.

Экран цели раньше отвечал на вопрос «достаём ли мы её» один раз - по нажатию.
Между нажатиями он показывал прошлое: цель могла уехать, порт закрыться, VPN
отвалиться, а на экране всё ещё стояла галочка, снятая десять минут назад. Это
ровно тот случай, из-за которого потом ищут поломку не там.

Поэтому проверка идёт сама, в отдельном потоке, и индикатор показывает не «было
доступно», а **когда** это было проверено. Два следствия, оба важные:

* движение индикатора привязано к числу выполненных проверок, а не к отрисовке.
  Если поток умрёт, индикатор замрёт - и это видно. Крутилка, которую вертит
  рисующий цикл, врала бы бодро и ровно;
* показание старше нескольких интервалов помечается возрастом. Свежо
  выглядящая галочка над мёртвым потоком - обман того же рода, что ноль потерь
  без счётчика.

Проверка тут неглубокая нарочно: TCP-соединение до порта SSH, то есть «коробка
там и слушает». Годятся ли ключи - вопрос самого прогона, и задавать его раз в
две секунды было бы хамством по отношению к общему стенду.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

# Как часто спрашивать. Две секунды - это достаточно часто, чтобы обрыв заметить
# в пределах вздоха, и достаточно редко, чтобы не выглядеть сканером портов на
# машине, которой пользуются и другие.
EVERY_S = 2.0

# Во сколько интервалов показание считается устаревшим и начинает показывать
# свой возраст вместо того, чтобы выглядеть свежим.
STALE_AFTER = 3

# Кадры пульса. Двигает их выполненная проверка, а не отрисовка.
PULSE = ("●", "◉", "●", "○")

Check = Callable[[], tuple[bool, str]]


@dataclass(frozen=True)
class Reading:
    """Одна проверка: получилось ли, за сколько, и когда это было."""

    ok: bool
    ms: float = 0.0
    at: float = 0.0
    error: str = ""


class Watch:
    """Периодическая проверка достижимости в фоновом потоке.

    Проверка передаётся снаружи и берётся заново на каждом круге, поэтому
    правка адреса в форме подхватывается без перезапуска наблюдателя.
    """

    def __init__(self, check: Check, every: float = EVERY_S,
                 clock: Callable[[], float] = time.monotonic):
        self.check = check
        self.every = every
        self.clock = clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._latest: Reading | None = None
        self._count = 0

    # ---------------------------------------------------------------- жизнь
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        # Демон: наблюдатель не имеет права задержать выход из программы, и
        # его смерть вместе с процессом ничего не теряет.
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="traphy-link")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=1.0)

    def _loop(self) -> None:
        while True:
            self.measure()
            if self._stop.wait(self.every):
                return

    # --------------------------------------------------------------- работа
    def measure(self) -> Reading:
        """Одна проверка. Отдельным методом, чтобы её можно было позвать без
        потока - в тесте и при первом открытии экрана."""
        started = self.clock()
        try:
            ok, why = self.check()
        except Exception as exc:
            # Проверка связи, уронившая экран, - худший из возможных исходов:
            # человек лишается интерфейса из-за того, что сеть моргнула.
            ok, why = False, str(exc) or exc.__class__.__name__
        reading = Reading(ok=ok, ms=(self.clock() - started) * 1000.0,
                          at=self.clock(), error="" if ok else why)
        with self._lock:
            self._latest = reading
            self._count += 1
        return reading

    @property
    def latest(self) -> Reading | None:
        with self._lock:
            return self._latest

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    def line(self) -> tuple[str, str]:
        """(текст, роль цвета) для шапки экрана."""
        with self._lock:
            return describe(self._latest, self._count, self.every, self.clock())


def describe(reading: Reading | None, count: int = 0, every: float = EVERY_S,
             now: float = 0.0) -> tuple[str, str]:
    """Как показать последнее показание. Чистая функция - её и проверяют."""
    if reading is None:
        return "◌ проверяю связь…", "dim"
    pulse = PULSE[count % len(PULSE)]
    age = max(0.0, now - reading.at)
    stale = age > every * STALE_AFTER
    if reading.ok:
        text = f"{pulse} отвечает · {reading.ms:.0f} мс"
    else:
        text = f"○ не отвечает: {reading.error}"
    if stale:
        # Молчание наблюдателя не должно выглядеть как хорошая новость.
        text += f" · проверено {age:.0f} c назад"
        return text, "warn"
    return text, ("ok" if reading.ok else "bad")
