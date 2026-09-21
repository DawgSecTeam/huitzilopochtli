"""Unit coverage for the answer-key handout generator (boxbuilder/answerkey.py)
and the optional authored `solution` field it renders (authoring/validate.py)."""
import json
import os

import pytest
import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from boxbuilder import answerkey
from boxbuilder.cli import build_parser
from common.crypto import signing


# --- fixtures ---------------------------------------------------------------

def _scenario(solutions: bool = True):
    sol = "Run `ss -tlnp`.\n\nNotice the odd listener." if solutions else None
    checks = [
        {
            "id": "web_rule",
            "type": "command_json",
            "category": "vuln",
            "display": "EASY: Inbound web is accepted on port 80",
            "max_points": 5,
            "collect": {"script": "iptables -S INPUT"},
            "expect": {"equals": True, "field": "data", "points": 5},
            **({"solution": sol} if solutions else {}),
        },
        {
            "id": "key_private",
            "type": "permission",
            "category": "vuln",
            "display": "MODERATE: Deploy key is private",
            "max_points": 10,
            "collect": {"path": "/home/obs/.ssh/id_rsa"},
            "expect": {"mode_at_most": True, "field": "mode", "max_mode": "0600",
                       "points": 10},
            **({"solution": ["chmod 600 /home/obs/.ssh/id_rsa",
                             "Re-check with `stat -c %a`."]} if solutions else {}),
        },
        {
            "id": "rogue_gone",
            "type": "user_group",
            "category": "vuln",
            "display": "EASY: Rogue account removed",
            "max_points": 10,
            "collect": {},
            "expect": {"user_absent": True, "username": "rogue", "points": 10},
            **({"solution": "deluser --remove-home rogue"} if solutions else {}),
        },
        {
            "id": "ssh_reachable",
            "type": "db_query",
            "category": "penalty",
            "display": "PENALTY: SSH management path unreachable",
            "max_points": 10,
            "collect": {"host": "127.0.0.1", "port": 22},
            "expect": {"equals": True, "field": "ok", "points": -10},
            **({"solution": "Never add a firewall rule that drops port 22 "
                            "before testing an alternate way in."}
               if solutions else {}),
        },
    ]
    forensics = [{
        "id": "fq-port",
        "question": "Which port did the beacon listen on?",
        "answer": "4444",
        "answers": ["tcp/4444"],
        "points": 10,
        **({"solution": "Read `ss -tlnp` output."} if solutions else {}),
    }]
    return {
        "scenario": {"name": "Test Box", "version": 3, "mode": "honor",
                     "hosts": ["localhost"]},
        "checks": checks,
        "forensics": forensics,
    }


def _write_yaml(data, tmp_path, name="scenario.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


# --- validation -------------------------------------------------------------

def test_validate_accepts_solution_string_list_and_absent():
    data = _scenario(solutions=False)
    assert validate_scenario_yaml(data, "s.yaml") == []

    data["checks"][0]["solution"] = "one string"
    data["checks"][1]["solution"] = ["step one", "step two"]
    data["forensics"][0]["solution"] = "how to find it"
    assert validate_scenario_yaml(data, "s.yaml") == []


@pytest.mark.parametrize("bad", ["", "   ", [], ["", "x"], [42], 7, None])
def test_validate_rejects_junk_solution(bad):
    data = _scenario(solutions=False)
    data["checks"][0]["solution"] = bad
    assert len(validate_scenario_yaml(data, "s.yaml")) == 1


def test_forensics_solution_is_now_a_known_key():
    data = _scenario(solutions=False)
    data["forensics"][0]["solution"] = "steps"
    assert validate_scenario_yaml(data, "s.yaml") == []


# --- goal lines / scored-on -------------------------------------------------

def test_goal_lines_by_type_and_matcher():
    sc = _scenario(solutions=False)
    checks = {c["id"]: c for c in sc["checks"]}
    checks["key_private"]["collect"]["path"] = "/x"
    assert "0600" in answerkey.goal_line(checks["key_private"])
    assert "rogue" in answerkey.goal_line(checks["rogue_gone"])
    assert "firewall" in answerkey.goal_line(checks["web_rule"])
    assert "22" in answerkey.goal_line(checks["ssh_reachable"])

    svc = {"type": "service_state", "collect": {"service": "evil.service"},
           "expect": {"equals": False, "field": "enabled", "points": 10}}
    assert "evil.service" in answerkey.goal_line(svc)
    assert "disabled" in answerkey.goal_line(svc)

    proc = {"type": "process_state",
            "collect": {"pattern": "/opt/evil"}, "expect": {"equals": False}}
    assert "/opt/evil" in answerkey.goal_line(proc)

    grp = {"type": "user_group", "collect": {},
           "expect": {"group_members_subset_of": True, "group": "sudo",
                      "allowed": ["obsadmin"]}}
    assert "sudo" in answerkey.goal_line(grp) and "obsadmin" in answerkey.goal_line(grp)


def test_scored_on_prefers_collector_target():
    sc = _scenario(solutions=False)
    checks = {c["id"]: c for c in sc["checks"]}
    assert answerkey.scored_on(checks["key_private"]) == "`/home/obs/.ssh/id_rsa`"
    assert "22" in answerkey.scored_on(checks["ssh_reachable"])


# --- markdown rendering -----------------------------------------------------

def test_render_markdown_full_and_gaps():
    sc = _scenario(solutions=True)
    md, gaps = answerkey.render_markdown(sc, "boxes/x/scenario.yaml")
    assert gaps == []
    assert "post-event walkthrough & answer key" in md
    assert "Spoiler warning" in md
    assert "EASY: Inbound web is accepted on port 80 · 5 pts" in md
    assert "chmod 600 /home/obs/.ssh/id_rsa" in md  # list solution joined in
    assert "deluser --remove-home rogue" in md
    assert "`4444` or `tcp/4444`" in md
    assert "PENALTY: SSH management path unreachable · −10 pts when triggered" in md
    assert "Watch your step" in md
    assert "Generated" in md and "scenario v3" in md
    # Check ids never surface in the handout -- display titles only.
    assert "web_rule" not in md and "fq-port" not in md


def test_render_markdown_placeholder_and_gap_reporting():
    sc = _scenario(solutions=False)
    md, gaps = answerkey.render_markdown(sc, "s.yaml")
    assert md.count(answerkey._PLACEHOLDER) == 5  # 3 vuln + 1 penalty + 1 forensics
    assert len(gaps) == 5
    assert any("rogue account removed" in g.lower() for g in gaps)
    assert any("fq-port" in g for g in gaps)


# --- html rendering ---------------------------------------------------------

def test_render_html_themed_with_code_fences(tmp_path):
    sc = _scenario(solutions=True)
    sc["theme"] = {"title": "Test Box", "organization": "Test Org",
                   "accent": "#123456"}
    sc["checks"][1]["solution"] = "Fix it:\n\n```\nchmod 600 /x\n```"
    md, _ = answerkey.render_markdown(sc, "s.yaml")
    html = answerkey.render_html(md, sc, str(tmp_path))
    assert "<pre><code>chmod 600 /x</code></pre>" in html
    assert "<title>Test Box — Answer Key</title>" in html
    assert "Test Org" in html


# --- end-to-end generate() --------------------------------------------------

def test_generate_writes_markdown_and_html(tmp_path):
    path = _write_yaml(_scenario(solutions=True), tmp_path)
    result = answerkey.generate(path, out_path=str(tmp_path / "out" / "key.md"),
                                want_html=True)
    assert result["ok"] and result["missing_walkthroughs"] == []
    md = open(result["markdown"], encoding="utf-8").read()
    assert "post-event walkthrough" in md
    assert os.path.isfile(result["html"])


def test_generate_reports_missing_walkthroughs_without_failing(tmp_path):
    path = _write_yaml(_scenario(solutions=False), tmp_path)
    result = answerkey.generate(path, out_path=str(tmp_path / "key.md"))
    assert result["ok"]
    assert len(result["missing_walkthroughs"]) == 5
    assert "note" in result


def test_generate_rejects_invalid_scenario(tmp_path):
    data = _scenario(solutions=False)
    del data["scenario"]["name"]
    path = _write_yaml(data, tmp_path)
    with pytest.raises(ValueError, match="validation"):
        answerkey.generate(path, out_path=str(tmp_path / "key.md"))


# --- CLI wiring -------------------------------------------------------------

def test_cli_parses_answer_key_without_spec_or_nakon():
    args = build_parser().parse_args(["answer-key", "--scenario", "s.yaml", "--html"])
    assert args.scenario == "s.yaml" and args.html and args.out is None


# --- leak guard -------------------------------------------------------------

def test_solution_never_reaches_manifest_or_rubric(tmp_path):
    with_sol = _write_yaml(_scenario(solutions=True), tmp_path, "with.yaml")
    without = _scenario(solutions=False)
    without_path = _write_yaml(without, tmp_path, "without.yaml")

    private_key, _ = signing.keypair()
    out_with = compile_scenario(with_sol, str(tmp_path / "a"), private_key)
    out_without = compile_scenario(without_path, str(tmp_path / "b"), private_key)

    manifest_with = json.load(open(out_with["manifest"], encoding="utf-8"))
    manifest_without = json.load(open(out_without["manifest"], encoding="utf-8"))
    assert manifest_with == manifest_without
    assert "solution" not in json.dumps(manifest_with)

    rubric_with = json.load(open(out_with["rubric"], encoding="utf-8"))
    rubric_without = json.load(open(out_without["rubric"], encoding="utf-8"))
    assert rubric_with == rubric_without
