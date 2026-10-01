"""Живая индикация связи, и способы, которыми она могла бы соврать.

Главное здесь не «показывает ли она галочку», а обратное: не показывает ли она
её тогда, когда показывать нечего. Индикатор связи, выглядящий бодро над
умершим наблюдателем, - обман того же рода, что ноль потерь без счётчика, и
проверяется он так же придирчиво.
"""

from __future__ import annotations

import time

from traphy import link
from traphy.link import PULSE, Reading, Watch, describe


# --------------------------------------------------------------------------- #
# Как показано одно показание
# --------------------------------------------------------------------------- #
def test_before_the_first_check_nothing_is_claimed():
    text, role = describe(None)
    assert "проверяю" in text
    assert role == "dim"


def test_a_good_reading_shows_the_round_trip():
    text, role = describe(Reading(ok=True, ms=3.4, at=100.0), count=0,
                          every=2.0, now=100.1)
    assert "отвечает" in text
    assert "3 мс" in text
    assert role == "ok"


def test_a_bad_reading_carries_the_reason():
    text, role = describe(Reading(ok=False, at=100.0, error="порт не отвечает"),
                          count=0, every=2.0, now=100.1)
    assert "не отвечает" in text
    assert "порт не отвечает" in text
    assert role == "bad"


def test_a_stale_reading_stops_looking_like_good_news():
    """Наблюдатель замолчал - галочка обязана перестать выглядеть свежей."""
    text, role = describe(Reading(ok=True, ms=3.0, at=100.0), count=0,
                          every=2.0, now=100.0 + 2.0 * link.STALE_AFTER + 1)
    assert "назад" in text
    assert role == "warn", "устаревшее показание не должно быть зелёным"


def test_a_fresh_reading_says_nothing_about_age():
    text, _role = describe(Reading(ok=True, ms=3.0, at=100.0), count=0,
                           every=2.0, now=100.5)
    assert "назад" not in text


def test_the_pulse_is_driven_by_checks_and_not_by_redraws():
    """Крутилка, которую вертит отрисовка, крутилась бы ровно и врала бы: она
    показывала бы, что программа жива, а не что проверки идут."""
    frames = {describe(Reading(ok=True, ms=1.0, at=1.0), count=n, every=2.0,
                       now=1.0)[0][0]
              for n in range(len(PULSE))}
    assert len(frames) > 1, "пульс не двигается с числом проверок"

    # Та же отрисовка при том же числе проверок даёт тот же кадр.
    one = describe(Reading(ok=True, ms=1.0, at=1.0), count=7, every=2.0, now=1.0)
    two = describe(Reading(ok=True, ms=1.0, at=1.0), count=7, every=2.0, now=1.0)
    assert one == two


# --------------------------------------------------------------------------- #
# Наблюдатель
# --------------------------------------------------------------------------- #
def test_one_measurement_records_what_came_back():
    clock = iter([10.0, 10.25, 10.25, 10.25])
    watch = Watch(lambda: (True, ""), clock=lambda: next(clock))
    reading = watch.measure()
    assert reading.ok
    assert reading.ms == 250.0
    assert watch.count == 1
    assert watch.latest == reading


def test_a_check_that_raises_is_reported_rather_than_thrown():
    """Проверка связи, уронившая экран, - худший исход: человек лишается
    интерфейса из-за того, что сеть моргнула."""
    def boom() -> tuple[bool, str]:
        raise OSError("сеть недостижима")

    watch = Watch(boom)
    reading = watch.measure()
    assert reading.ok is False
    assert "сеть недостижима" in reading.error


def test_a_check_that_raises_without_a_message_still_names_something():
    def boom() -> tuple[bool, str]:
        raise TimeoutError

    assert Watch(boom).measure().error == "TimeoutError"


def test_the_watcher_keeps_checking_until_it_is_stopped():
    seen: list[int] = []
    watch = Watch(lambda: (bool(seen.append(1)) or True, ""), every=0.01)
    watch.start()
    deadline = time.monotonic() + 3.0
    while watch.count < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    watch.stop()
    after = watch.count
    assert after >= 3, "наблюдатель не сделал трёх проверок"

    # После остановки проверки прекращаются - иначе поток продолжал бы стучать
    # в общий стенд после того, как экран закрыли.
    time.sleep(0.05)
    assert watch.count == after


def test_starting_twice_does_not_double_the_checks():
    watch = Watch(lambda: (True, ""), every=0.01)
    watch.start()
    first = watch._thread
    watch.start()
    assert watch._thread is first
    watch.stop()


def test_stopping_one_that_never_started_is_harmless():
    Watch(lambda: (True, "")).stop()
