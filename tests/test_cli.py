"""The command line: the same work the menu does, without the menu."""

from __future__ import annotations

import json

import pytest

from traphy.cli import load_profile, load_target, main
from traphy.target import Target, TargetStore


def test_presets_are_listed(capsys):
    assert main(["presets"]) == 0
    out = capsys.readouterr().out
    assert "l3_ip" in out and "imix" in out


def test_gen_writes_a_runnable_script(tmp_path, capsys):
    out = tmp_path / "sweep.py"
    assert main(["gen", "ip_sweep", "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    compile(text, str(out), "exec")
    assert out.stat().st_mode & 0o111, "скрипт должен быть исполняемым"
    assert "254 кадров" in capsys.readouterr().out


def test_gen_to_stdout_by_default(capsys):
    assert main(["gen", "l2_ethernet"]) == 0
    assert capsys.readouterr().out.startswith("#!/usr/bin/env python3")


def test_gen_refuses_a_broken_profile(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "bad", "streams": [
        {"name": "s", "packet": {"frame_size": 12}}]}), encoding="utf-8")
    assert main(["gen", str(bad)]) == 2
    assert "!" in capsys.readouterr().err


def test_an_unknown_profile_lists_what_is_available():
    with pytest.raises(SystemExit) as caught:
        load_profile("нетакого", __import__("pathlib").Path("profiles"))
    assert "ip_sweep" in str(caught.value)


def test_a_profile_is_found_by_bare_name_inside_the_profiles_dir(tmp_path):
    from traphy import presets

    presets.build("l3_ip").save(tmp_path / "mine.json")
    assert load_profile("mine", tmp_path).name == "l3_ip"


def test_an_unknown_target_lists_the_saved_ones(tmp_path, monkeypatch):
    store = TargetStore()
    store.save(Target(name="стенд"))
    with pytest.raises(SystemExit) as caught:
        load_target("другой")
    assert "стенд" in str(caught.value)


def test_targets_are_listed(capsys):
    TargetStore().save(Target(name="bench", use_ssh=True, host="10.0.0.9",
                              ssh_user="root", tx_iface="ens1"))
    assert main(["targets"]) == 0
    out = capsys.readouterr().out
    assert "bench" in out and "root@10.0.0.9" in out


def test_history_is_empty_before_anything_ran(capsys):
    assert main(["history"]) == 0
    assert "прогонов ещё не было" in capsys.readouterr().out


def test_probe_reports_a_local_target(capsys, monkeypatch):
    import sys

    store = TargetStore()
    store.save(Target(name="here", python=sys.executable, tx_iface="lo"))
    assert main(["probe", "-t", "here", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] and data["ifaces"]


def test_dry_run_reports_without_sending(capsys, monkeypatch):
    import sys

    TargetStore().save(Target(name="here", python=sys.executable, tx_iface="lo"))
    rc = main(["run", "l3_ip", "-t", "here", "--dry-run", "--json"])
    captured = capsys.readouterr()
    if rc == 0:
        assert json.loads(captured.out)["tx_pkts"] == 0
    else:
        # A machine without Scapy cannot even build frames; that has to be the
        # reported reason rather than a silent zero.
        assert "scapy" in captured.err.lower() or "scapy" in captured.out.lower()
