"""verify / seal-prepare: pure evaluation over collected facts."""
import json
import os

import pytest

from boxbuilder.providers.base import RunResult
from boxbuilder.verify import (
    FAIL, PASS, SKIP, WARN,
    Expectations,
    collect_facts,
    evaluate,
    expectations_from,
    prepare_seal,
    summarise,
)


def _healthy_facts(**overrides):
    facts = {
        "os": "posix",
        "install_dir": "/opt/.huitzilopochtli",
        "files": ["agent.pyz", "manifest.signed.json",
                  "authoring_public_key.b64", "agent_config.json", ".score.dat"],
        "manifest_sha": "a" * 64,
        "key_sha": "b" * 64,
        "agent_config": {"mode": "honor", "rubric_path": "/opt/.huitzilopochtli/.score.dat",
                         "engine_url": None, "enrollment_token": None},
        "machine_id": "0123456789abcdef0123456789abcdef",
        "motd": True,
        "theme_files": ["abc123-wallpaper.png"],
        "legacy_dir": False,
        "init": {"active": "active", "enabled": "enabled",
                 "timer_active": "active", "timer_enabled": "enabled"},
        "journal": "Started huitzilopochtli-agent.service",
        "report": {"snapshot_version": 1, "mode": "honor",
                   "scenario_name": "Demo", "total": 0, "max_possible": 200},
        "report_error": None,
        "users": [{"name": "player", "home": "/home/player"}],
        "user_artifacts": {"player": {"desktop_entries": 2, "report_mirror": True,
                                      "readme_mirror": True}},
        "desktop_pixels": 4_100_000,
    }
    facts.update(overrides)
    return facts


class _Spec:
    """Just enough of BoxSpec for expectations/prepare_seal."""

    def __init__(self, mode="honor", theme=None, scenario=None):
        self.mode = mode
        self.theme = theme or {}
        self.scenario = scenario or {"scenario": {"name": "Demo"}}


def _exp(**overrides):
    exp = Expectations(mode="honor", expect_total=0, theme={
        "wallpaper": "assets/wallpaper.png",
        "readme": "assets/README.md",
        "desktop_shortcuts": [{"name": "Handbook", "exec": "xdg-open x"}],
    }, scenario_name="Demo", expected_manifest_sha="a" * 64,
        expected_key_sha="b" * 64)
    for key, value in overrides.items():
        setattr(exp, key, value)
    return exp


def _statuses(checks):
    return {c.id: c.status for c in checks}


def test_healthy_honor_box_passes_everything():
    report = summarise(evaluate(_healthy_facts(), _exp()))
    assert report["ok"], [c for c in report["checks"] if c["status"] == FAIL]
    assert report["counts"][FAIL] == 0


def test_missing_install_file_fails():
    facts = _healthy_facts(files=["agent.pyz"])
    checks = evaluate(facts, _exp())
    assert _statuses(checks)["install.files"] == FAIL


def test_ranked_box_must_not_carry_the_rubric():
    facts = _healthy_facts(files=["agent.pyz", "manifest.signed.json",
                                  "authoring_public_key.b64", "agent_config.json",
                                  ".score.dat"])
    exp = _exp(mode="ranked", expect_total=None)
    checks = evaluate(facts, exp)
    assert _statuses(checks)["install.no-rubric"] == FAIL


def test_ranked_box_without_rubric_passes_that_check():
    facts = _healthy_facts(
        files=["agent.pyz", "manifest.signed.json",
               "authoring_public_key.b64", "agent_config.json"],
        agent_config={"mode": "ranked", "engine_url": "https://engine.example.org",
                      "enrollment_token": "tok", "rubric_path": None},
        init={"active": "active", "enabled": "enabled",
              "timer_active": "inactive", "timer_enabled": "disabled"},
        report={"snapshot_version": 1, "mode": "ranked",
                "scenario_name": "Demo", "total": 0, "max_possible": 200},
    )
    checks = evaluate(facts, _exp(mode="ranked", expect_total=0))
    assert _statuses(checks)["install.no-rubric"] == PASS


def test_manifest_hash_mismatch_fails_lineage():
    checks = evaluate(_healthy_facts(manifest_sha="c" * 64), _exp())
    assert _statuses(checks)["lineage.manifest"] == FAIL


def test_missing_build_state_skips_lineage_instead_of_failing():
    checks = evaluate(_healthy_facts(), _exp(expected_manifest_sha=None,
                                             expected_key_sha=None))
    assert _statuses(checks)["lineage.manifest"] == SKIP
    assert _statuses(checks)["lineage.key"] == SKIP


def test_crash_in_journal_fails():
    facts = _healthy_facts(journal="Traceback (most recent call last):\n  ...")
    assert _statuses(evaluate(facts, _exp()))["agent.journal"] == FAIL


def test_report_total_must_match_expectation():
    facts = _healthy_facts(report={"snapshot_version": 1, "mode": "honor",
                                   "scenario_name": "Demo", "total": 40,
                                   "max_possible": 200})
    assert _statuses(evaluate(facts, _exp(expect_total=0)))["report.state"] == FAIL
    assert _statuses(evaluate(facts, _exp(expect_total=40)))["report.state"] == PASS


def test_competition_box_expects_a_stopped_unit_and_no_token():
    facts = _healthy_facts(
        files=["agent.pyz", "manifest.signed.json",
               "authoring_public_key.b64", "agent_config.json"],
        agent_config={"mode": "ranked", "engine_url": "https://engine.example.org",
                      "enrollment_token": None, "rubric_path": None},
        init={"active": "inactive", "enabled": "disabled",
              "timer_active": None, "timer_enabled": None},
        report=None,
    )
    checks = evaluate(facts, _exp(mode="ranked", competition=True, expect_total=None))
    statuses = _statuses(checks)
    assert statuses["init.state"] == PASS
    assert statuses["config.token"] == PASS
    assert statuses["report.state"] == SKIP


def test_competition_box_that_is_running_fails():
    facts = _healthy_facts(init={"active": "active", "enabled": "enabled",
                                 "timer_active": None, "timer_enabled": None})
    exp = _exp(mode="ranked", competition=True, expect_total=None)
    assert _statuses(evaluate(facts, exp))["init.state"] == FAIL


def test_theme_artifacts_are_checked_when_the_scenario_has_them():
    facts = _healthy_facts(theme_files=["other.txt"],
                           user_artifacts={"player": {"desktop_entries": 0,
                                                      "report_mirror": True,
                                                      "readme_mirror": False}})
    statuses = _statuses(evaluate(facts, _exp()))
    assert statuses["theme.wallpaper"] == FAIL
    assert statuses["theme.readme"] == FAIL
    assert statuses["theme.shortcuts"] == FAIL


def test_theme_checks_skip_without_a_theme():
    facts = _healthy_facts(theme_files=[], user_artifacts={})
    checks = evaluate(facts, _exp(theme={}))
    statuses = _statuses(checks)
    assert "theme.wallpaper" not in statuses
    assert statuses["theme.shortcuts"] == SKIP


def test_desktop_render_is_skipped_when_unmeasurable():
    checks = evaluate(_healthy_facts(desktop_pixels=None), _exp())
    assert _statuses(checks)["desktop.renders"] == SKIP


def test_desktop_render_fails_on_an_empty_framebuffer():
    checks = evaluate(_healthy_facts(desktop_pixels=200), _exp())
    assert _statuses(checks)["desktop.renders"] == FAIL


def test_seal_hygiene_flags_identity_legacy_dir_and_empty_machine_id():
    facts = _healthy_facts(
        files=["agent.pyz", "manifest.signed.json", "authoring_public_key.b64",
               "agent_config.json", "identity.json"],
        machine_id="", legacy_dir=True)
    statuses = _statuses(evaluate(facts, _exp(for_seal=True)))
    assert statuses["seal.machine-id"] == FAIL
    assert statuses["seal.legacy-dir"] == FAIL
    assert statuses["seal.identity"] == WARN


def test_expectations_come_from_build_state(tmp_path):
    (tmp_path / "build-state.json").write_text(json.dumps({
        "manifest_sha256": "d" * 64,
        "authoring_public_key_sha256": "e" * 64,
    }))
    exp = expectations_from(
        _Spec(mode="honor", theme={"wallpaper": "w.png"},
              scenario={"scenario": {"name": "Demo"}}), str(tmp_path))
    assert exp.expected_manifest_sha == "d" * 64
    assert exp.expected_key_sha == "e" * 64
    assert exp.expect_total == 0
    assert exp.scenario_name == "Demo"


# --- collection ------------------------------------------------------------

class FakeHandle:
    """Returns canned output per command marker; records commands run."""

    os_name = "posix"
    addr = "192.0.2.10"
    user = "player"
    password = "p"
    port = 22

    def __init__(self, responses, exit_codes=None):
        self.responses = responses
        self.exit_codes = exit_codes or {}
        self.commands = []

    def _match(self, cmd):
        for marker, output in self.responses.items():
            if marker in cmd:
                return output
        return ""

    def run(self, cmd, *, timeout=1800, sudo=True):
        self.commands.append(cmd)
        code = 0
        for marker, expected in self.exit_codes.items():
            if marker in cmd:
                code = expected
        return RunResult(exit_status=code, stdout=self._match(cmd))

    def put(self, local, remote, mode=None):
        pass

    def install_init(self, kind, mode="honor", start_agent=True):
        pass


def _state_output(files=("agent.pyz", "manifest.signed.json",
                         "authoring_public_key.b64", "agent_config.json",
                         ".score.dat"),
                  config=None, machine_id="0123456789abcdef0123456789abcdef",
                  legacy="no"):
    cfg = config if config is not None else {
        "mode": "honor", "rubric_path": "/opt/.huitzilopochtli/.score.dat"}
    return "\n".join([
        "##files", *files,
        "##manifest-sha", "a" * 64,
        "##key-sha", "b" * 64,
        "##config", json.dumps(cfg),
        "##machine-id", machine_id,
        "##motd", "yes",
        "##theme", "abc123-wallpaper.png",
        "##legacy", legacy,
    ])


def _collect(responses, id_response="active", report='{"snapshot_version": 1}'):
    defaults = {
        "ls -1A /opt/.huitzilopochtli": _state_output(),
        "systemctl is-active": "active",
        "systemctl is-enabled": "enabled",
        "journalctl": "Started huitzilopochtli-agent.service",
        "cat /opt/.huitzilopochtli/report.json": report,
        "awk -F:": "player|/home/player\n##artifacts\nplayer|/home/player|2|yes|yes\n",
        "xwd": "4100000",
    }
    defaults.update(responses)
    return collect_facts(FakeHandle(defaults), None, "artifacts")


def test_collect_parses_a_posix_box():
    facts = _collect({})
    assert facts["os"] == "posix"
    assert ".score.dat" in facts["files"]
    assert facts["agent_config"]["mode"] == "honor"
    assert facts["machine_id"].startswith("0123456789")
    assert facts["theme_files"] == ["abc123-wallpaper.png"]
    assert facts["user_artifacts"]["player"]["desktop_entries"] == 2
    assert facts["desktop_pixels"] == 4_100_000
    assert facts["report"]["snapshot_version"] == 1


def test_collect_reports_invalid_json_report():
    facts = _collect({"cat /opt/.huitzilopochtli/report.json": "{not json"})
    assert facts["report"] is None
    assert "not valid JSON" in facts["report_error"]


def test_collect_treats_missing_xwd_as_unmeasurable():
    facts = _collect({}, )
    facts["desktop_pixels"] = None  # xwd absent branch
    checks = evaluate(facts, _exp())
    assert _statuses(checks)["desktop.renders"] == SKIP


# --- seal ------------------------------------------------------------------

def test_seal_prepare_aborts_when_verification_fails():
    handle = FakeHandle({"ls -1A /opt/.huitzilopochtli": _state_output(files=())})
    result = prepare_seal(handle, _Spec(mode="ranked"), "artifacts",
                          skip_verify=False)
    assert result["ok"] is False
    assert result["reason"] == "verify failed"
    # verification only reads; the destructive seal script must not run
    assert not any("##stop" in cmd for cmd in handle.commands)


def test_seal_prepare_purges_state_and_wipes_machine_id():
    state = _state_output()
    seal = "\n".join([
        "##stop", "ok", "##purge", "ok", "##mirrors", "ok",
        "##machine-id", "ok", "##size", "0",
    ])

    class SealHandle(FakeHandle):
        def run(self, cmd, *, timeout=1800, sudo=True):
            self.commands.append(cmd)
            if "##machine-id" in cmd and "wc -c" in cmd:
                return RunResult(0, stdout=seal)
            if "##stop" in cmd:
                return RunResult(0, stdout=seal)
            return RunResult(0, stdout=state)

    result = prepare_seal(SealHandle({}), _Spec(mode="ranked"),
                          "artifacts", skip_verify=True)
    assert result["ok"] is True
    steps = {step["id"]: step["status"] for step in result["steps"]}
    assert steps["machine-id"] == "done"
    assert steps["state"] == "done"
    assert result["lineage"]["manifest_sha256"] is None


def test_seal_prepare_can_skip_verify():
    state = _state_output()
    seal = "##stop\nok\n##purge\nok\n##mirrors\nok\n##machine-id\nok\n##size\n0\n"

    class SealHandle(FakeHandle):
        def run(self, cmd, *, timeout=1800, sudo=True):
            return RunResult(0, stdout=seal if "##stop" in cmd else state)

    result = prepare_seal(SealHandle({}), _Spec(mode="honor"),
                          "artifacts", skip_verify=True)
    assert result["verify"] is None
    assert result["ok"] is True
