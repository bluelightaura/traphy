"""Form parsers: what a field accepts and how it explains a refusal."""

from __future__ import annotations

import pytest

from traphy.forms import Field, as_float, as_int, as_ip, as_mac


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
