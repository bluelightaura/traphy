"""Form parsers: what a field accepts and how it explains a refusal."""

from __future__ import annotations

import pytest

from traphy import forms
from traphy.forms import Field, as_float, as_int, as_ip, as_mac
from traphy.strings import t


@pytest.mark.parametrize("text,ok", [("80", True), ("0", True), ("65535", True),
                                     ("65536", False), ("-1", False), ("", False),
                                     ("восемьдесят", False)])
def test_integers_are_bounded(text, ok):
    value, err = as_int(text, 0, 65535, "порт")
    assert (err == "") is ok
    if ok:
        assert value == int(text)


def test_a_refusal_names_the_field_and_the_range():
    _v, err = as_int("70000", 0, 65535, "порт назначения")
    assert "порт назначения" in err and "0..65535" in err


@pytest.mark.parametrize("text,expected", [
    ("00:11:22:33:44:55", "00:11:22:33:44:55"),
    ("00-11-22-33-44-55", "00:11:22:33:44:55"),
    ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
])
def test_mac_forms_that_are_accepted(text, expected):
    assert as_mac(text, "MAC") == (expected, "")


@pytest.mark.parametrize("text", ["00:11:22:33:44", "не мак", "0:1:2:3:4:5",
                                  "zz:11:22:33:44:55"])
def test_mac_forms_that_are_refused(text):
    _v, err = as_mac(text, "MAC")
    assert err.startswith("!")


def test_ip_parsing():
    assert as_ip(" 16.0.0.1 ", "IP") == ("16.0.0.1", "")
    assert as_ip("999.1.1.1", "IP")[1].startswith("!")
    assert as_ip("::1", "IP")[1].startswith("!")     # IPv4 only, deliberately


def test_a_comma_decimal_is_accepted():
    """A Russian keyboard produces commas; refusing them would be pedantry."""
    assert as_float("1,5", "скорость") == (1.5, "")


def test_zero_and_negative_rates_are_refused():
    assert as_float("0", "скорость")[1].startswith("!")
    assert as_float("-3", "скорость")[1].startswith("!")


def test_a_field_without_a_setter_is_read_only():
    assert Field("k", "метка", lambda: "значение").editable is False
    assert Field("k", "метка", lambda: "x", lambda v: "").editable is True


def test_visibility_is_evaluated_each_time():
    shown = {"yes": False}
    field = Field("k", "метка", lambda: "x", visible=lambda: shown["yes"])
    assert field.shown() is False
    shown["yes"] = True
    assert field.shown() is True


def test_a_hint_can_follow_the_value_it_explains():
    """Статическая подсказка под переключателем описывает одно его положение,
    а видна в обоих - и в одном прямо противоречит написанному рядом."""
    from traphy.forms import Field

    state = {"on": False}
    f = Field("ssh", "через SSH", lambda: "да" if state["on"] else "нет",
              lambda _v: "", hint=lambda: "включено" if state["on"] else "выключено")
    assert f.hint() == "выключено"
    state["on"] = True
    assert f.hint() == "включено"


def test_a_plain_string_hint_still_works():
    from traphy.forms import Field

    f = Field("x", "поле", lambda: "1", hint="просто пояснение")
    assert not callable(f.hint)
    assert f.hint == "просто пояснение"


# --------------------------------------------------------------------------- #
# Выборка значения: обычные, вводившиеся раньше, своё
# --------------------------------------------------------------------------- #
def test_a_field_shows_one_thing_and_is_another():
    """Интерфейс показан как «eno1  (up · 25G)», а значением остаётся «eno1».
    Без разделения в список прошлых значений легли бы подписи."""
    f = Field("tx", "TX", lambda: "eno1  (up · 25G)", lambda _v: "",
              raw=lambda: "eno1")
    assert f.get() != f.value()
    assert f.value() == "eno1"


def test_a_field_without_raw_is_its_own_value():
    f = Field("host", "Хост", lambda: "10.0.0.1", lambda _v: "")
    assert f.value() == "10.0.0.1"


def test_suggestions_may_be_plain_or_carry_their_own_note():
    plain = Field("a", "A", lambda: "", lambda _v: "", suggest=("python3",))
    assert forms._suggested(plain) == [("python3", t("v_standard"))]

    paired = Field("b", "B", lambda: "", lambda _v: "",
                   suggest=(("eno1", "up · 25G"),))
    assert forms._suggested(paired) == [("eno1", "up · 25G")]


def test_suggestions_can_be_computed_when_they_depend_on_state():
    """Интерфейсы известны только после опроса, поэтому список - функция."""
    live: list[str] = []
    f = Field("tx", "TX", lambda: "", lambda _v: "", suggest=lambda: list(live))
    assert forms._suggested(f) == []
    live.append("eno1")
    assert forms._suggested(f) == [("eno1", t("v_standard"))]


class Recalled:
    """Форма с памятью, собранная вокруг словаря настроек."""

    def __init__(self):
        self.prefs: dict = {}
        self.saves = 0
        forms.set_recall(forms.Recall(self.prefs, self._save))

    def _save(self) -> None:
        self.saves += 1

    def close(self) -> None:
        forms.set_recall(None)


@pytest.fixture
def recalled():
    store = Recalled()
    yield store
    store.close()


def test_an_accepted_value_is_remembered(recalled):
    seen: list[str] = []
    f = Field("host", "Хост", lambda: seen[-1] if seen else "",
              lambda v: (seen.append(v), "")[1])
    assert forms._accept(f, "10.0.0.1") == ""
    assert forms.recall().values("host") == ["10.0.0.1"]
    assert recalled.saves == 1


def test_a_refused_value_is_not_remembered(recalled):
    f = Field("port", "Порт", lambda: "22", lambda _v: "! так нельзя")
    assert forms._accept(f, "70000").startswith("!")
    assert forms.recall().values("port") == []


def test_what_is_remembered_is_what_the_field_kept(recalled):
    """Сеттер приводит MAC к нижнему регистру - в списке должно оказаться
    приведённое значение, иначе одно значение будет лежать в двух написаниях."""
    kept: list[str] = []
    f = Field("mac", "MAC", lambda: kept[-1] if kept else "",
              lambda v: (kept.append(v.lower()), "")[1])
    forms._accept(f, "AA:BB:CC:DD:EE:FF")
    assert forms.recall().values("mac") == ["aa:bb:cc:dd:ee:ff"]


def test_a_secret_field_is_never_remembered(recalled):
    f = Field("pw", "Пароль", lambda: "", lambda _v: "", secret=True)
    forms._accept(f, "hunter2")
    assert forms.recall().values("pw") == []
    assert recalled.saves == 0


def test_a_field_can_opt_out_of_being_remembered(recalled):
    f = Field("name", "Имя", lambda: "", lambda _v: "", remember=False)
    forms._accept(f, "стенд")
    assert forms.recall().values("name") == []


def test_without_a_store_the_field_still_accepts_values():
    """Память ставит сеанс. Без него формы работают как раньше."""
    forms.set_recall(None)
    seen: list[str] = []
    f = Field("host", "Хост", lambda: "", lambda v: (seen.append(v), "")[1])
    assert forms._accept(f, "10.0.0.1") == ""
    assert seen == ["10.0.0.1"]
    assert forms._remembered(f) == []


def test_a_group_heading_is_printed_once_before_its_first_field():
    rows = [
        Field("a", "Поле A", lambda: "1", lambda _v: "", section="ПЕРВАЯ"),
        Field("b", "Поле B", lambda: "2", lambda _v: "", section="ПЕРВАЯ"),
        Field("c", "Поле C", lambda: "3", lambda _v: "", section="ВТОРАЯ"),
    ]
    out = forms._render("Т", rows, 0, "", 70, None, "", 20)
    assert out.count("ПЕРВАЯ") == 1
    assert out.count("ВТОРАЯ") == 1
    assert out.index("ПЕРВАЯ") < out.index("Поле A") < out.index("ВТОРАЯ")


def test_a_group_heading_is_not_a_row_you_can_land_on():
    """Заголовок рисуется, но полем не является: курсор считает поля, и
    сдвинься он на заголовок - править было бы нечего."""
    rows = [
        Field("a", "Поле A", lambda: "1", lambda _v: "", section="ПЕРВАЯ"),
        Field("b", "Поле B", lambda: "2", lambda _v: "", section="ВТОРАЯ"),
    ]
    out = forms._render("Т", rows, 1, "", 70, None, "", 20)
    marked = [ln for ln in out.splitlines() if "▸" in ln]
    assert len(marked) == 1
    assert "Поле B" in marked[0]


def test_fields_without_a_group_print_no_heading():
    rows = [Field("a", "Поле A", lambda: "1", lambda _v: "")]
    out = forms._render("Т", rows, 0, "", 70, None, "", 20)
    assert "Поле A" in out
