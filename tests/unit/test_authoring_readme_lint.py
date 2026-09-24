"""Unit coverage for the readme spoiler lint (authoring/readme_lint.py) and
its compile wiring, plus the all-boxes regression that keeps every handbook
in-repo lint-clean (HANDBOOK_GUIDE.md's mechanical half)."""
import glob
import os

import pytest
import yaml

from authoring.compile import compile_scenario
from authoring.readme_lint import lint_readme
from common.crypto import signing


# --- fixtures ---------------------------------------------------------------

def _parsed(readme="", forensics=None, checks=None, theme=None):
    return {
        "scenario": {"name": "x", "version": 1, "mode": "honor", "hosts": ["h"]},
        "checks": checks if checks is not None else [{
            "id": "c1", "type": "file_regex", "category": "vuln", "display": "d",
            "max_points": 5, "collect": {}, "expect": {"equals": "y", "points": 5},
        }],
        "forensics": forensics if forensics is not None else [{
            "id": "fq1", "question": "What is the name of the rogue account?",
            "answer": "svc_legacy", "points": 10,
        }],
        "theme": theme if theme is not None else {},
    }


def _lint(parsed, readme):
    return lint_readme(parsed, readme)


# --- tier 1: forensics answers block the compile -----------------------------

def test_answer_in_readme_is_an_error():
    errors, _ = _lint(_parsed(), "The rogue account svc_legacy should be disabled.")
    assert len(errors) == 1
    assert "svc_legacy" in errors[0]


def test_answers_list_members_are_checked_too():
    parsed = _parsed(forensics=[{
        "id": "fq1", "question": "q?", "answer": "nightcast@88.3",
        "answers": ["nightcast 88.3", "SpringDeploy2026!"], "points": 10,
    }])
    errors, _ = _lint(parsed, "The password was springdeploy2026!")
    assert len(errors) == 1 and "SpringDeploy2026!" in errors[0]


def test_answer_matching_ignores_case_wrapping_and_punctuation():
    parsed = _parsed(forensics=[{
        "id": "fq1", "question": "q?", "answer": "SpringDeploy2026!", "points": 10,
    }])
    errors, _ = _lint(parsed, "springdeploy2026 was\nthe planted password")
    assert errors


def test_short_and_generic_answers_are_skipped():
    parsed = _parsed(forensics=[{
        "id": "fq1", "question": "q?", "answer": "ssh",
        "answers": ["yes", "true"], "points": 10,
    }])
    errors, warnings = _lint(parsed, "ssh, yes and true appear right here")
    assert errors == [] and warnings == []


def test_answer_already_in_question_text_is_a_freebie():
    parsed = _parsed(forensics=[{
        "id": "fq1", "question": "Which account named svc_legacy ran the task?",
        "answer": "svc_legacy", "points": 10,
    }])
    errors, _ = _lint(parsed, "Handbook mentions svc_legacy freely.")
    assert errors == []


def test_readme_lint_allow_excuses_story_vocabulary():
    parsed = _parsed(theme={"readme_lint_allow": ["svc_legacy"]})
    errors, _ = _lint(parsed, "The rogue account svc_legacy should be disabled.")
    assert errors == []


def test_word_boundary_answer_does_not_fire_inside_longer_words():
    parsed = _parsed(forensics=[{
        "id": "fq1", "question": "q?", "answer": "intern", "points": 10,
    }])
    errors, _ = _lint(parsed, "We keep internal records on the server.")
    assert errors == []


# --- tier 2: solution: copy-paste --------------------------------------------

def _check_with_solution(solution):
    return {
        "id": "c1", "type": "file_regex", "category": "vuln", "display": "d",
        "max_points": 5, "collect": {}, "expect": {"equals": "y", "points": 5},
        "solution": solution,
    }


def test_verbatim_solution_line_in_readme_warns():
    parsed = _parsed(checks=[_check_with_solution(
        "Set the FollowRedirects registry value back to 0 and restart the service."
    )])
    _, warnings = _lint(parsed,
                        "Do this:\nSet the FollowRedirects registry value back to "
                        "0 and restart the service.")
    assert len(warnings) == 1 and "c1" in warnings[0]


def test_short_solution_lines_never_warn():
    parsed = _parsed(checks=[_check_with_solution(["Run `ss -tlnp`.", "Notice it."])])
    _, warnings = _lint(parsed, "Run `ss -tlnp` and notice it.")
    assert warnings == []


# --- tier 3: mutation commands -----------------------------------------------

def test_powershell_mutation_cmdlet_warns():
    _, warnings = _lint(_parsed(), "Run `Set-SmbServerConfiguration -EnableSMB1Protocol $false`.")
    assert len(warnings) == 1 and "Set-SmbServerConfiguration" in warnings[0]


def test_posix_mutations_warn():
    for fragment in ("sudo systemctl disable rogue.service",
                     "chmod 644 /etc/shadow",
                     "userdel -r rogue",
                     "sudo ufw allow 80/tcp"):
        _, warnings = _lint(_parsed(), f"Fix it with `{fragment}`.")
        assert warnings, fragment


def test_registry_and_windows_mutations_warn():
    for fragment in ("reg add HKLM\\SYSTEM\\... /v Start /t REG_DWORD /d 2",
                     "sc config Spooler start= disabled",
                     "net user rogue /active:no",
                     "auditpol /set /subcategory:\"Logon\" /success:enable"):
        _, warnings = _lint(_parsed(), f"Fix it with `{fragment}`.")
        assert warnings, fragment


def test_observation_commands_stay_legal():
    for fragment in ("Get-SmbServerConfiguration", "ss -tlnp", "sudo iptables -S",
                     "sudo iptables-save", "reg query HKLM\\SYSTEM\\CurrentControlSet",
                     "auditpol /get /subcategory:\"Logon\"", "cat /etc/passwd",
                     "systemctl cat UNIT", "systemctl list-units --type=service",
                     "net user", "net accounts", "icacls C:\\HospitalData",
                     "huitz watch", "-P", "ps aux", "sudo tcpdump -i any -nn"):
        errors, warnings = _lint(_parsed(), f"Inspect with `{fragment}`.")
        assert errors == [] and warnings == [], fragment


def test_fenced_blocks_are_checked_like_spans():
    _, warnings = _lint(_parsed(), "```\nchmod 644 /etc/shadow\n```")
    assert len(warnings) == 1


# --- tier 4: planted paths ----------------------------------------------------

def _check_with_collect(check_id, collect, solution):
    return {
        "id": check_id, "type": "permission", "category": "vuln", "display": "d",
        "max_points": 5, "collect": collect,
        "expect": {"mode_at_most": True, "field": "mode", "max_mode": "0600",
                   "points": 5},
        "solution": solution,
    }


def test_planted_path_in_readme_warns():
    parsed = _parsed(checks=[_check_with_collect(
        "payload_gone", {"path": "C:\\ProgramData\\Subsystems\\telemetry.ps1"},
        "Remove `C:\\ProgramData\\Subsystems\\telemetry.ps1` and everything else "
        "under C:\\ProgramData\\Subsystems.")])
    _, warnings = _lint(parsed, "Look in `C:\\ProgramData\\Subsystems`.")
    assert len(warnings) == 1 and "Subsystems" in warnings[0]


def test_collected_crown_jewel_path_is_fair_game():
    parsed = _parsed(checks=[_check_with_collect(
        "recipe_private", {"path": "/opt/cocoa/recipes/secret-recipe.txt"},
        "chmod 644 /opt/cocoa/recipes/secret-recipe.txt")])
    errors, warnings = _lint(parsed,
                             "Secret recipe: `/opt/cocoa/recipes/secret-recipe.txt`")
    assert errors == [] and warnings == []


def test_parent_dir_token_does_not_fire_on_deeper_briefed_path():
    parsed = _parsed(checks=[_check_with_collect(
        "key_private", {"path": "/home/cocoaadm/.ssh/id_rsa"},
        "The deploy key lives in /home/cocoaadm/.ssh; lock it down.")])
    errors, warnings = _lint(parsed, "Deploy key: `/home/cocoaadm/.ssh/id_rsa`")
    assert errors == [] and warnings == []


def test_shallow_and_generic_paths_do_not_warn():
    parsed = _parsed(checks=[_check_with_collect(
        "c1", {}, "Payloads pile up under C:\\ProgramData; audit /etc/passwd too. "
                  "GPOs live in C:\\Windows\\SYSVOL\\domain\\Policies.")])
    errors, warnings = _lint(parsed,
                             "Check `C:\\ProgramData`, `/etc/passwd`, and "
                             "`C:\\Windows\\SYSVOL\\domain\\Policies`.")
    assert errors == [] and warnings == []


# --- compile wiring ------------------------------------------------------------

def _write_yaml(data, tmp_path, name="s.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


def _readme_theme(tmp_path, text, **extra):
    readme = tmp_path / "README.md"
    readme.write_text(text, encoding="utf-8")
    return {"title": "t", "readme": "README.md", **extra}


def test_compile_blocks_on_forensics_answer_in_readme(tmp_path):
    data = _parsed()
    data["theme"] = _readme_theme(tmp_path, "The answer is svc_legacy.")
    with pytest.raises(ValueError, match="svc_legacy"):
        compile_scenario(_write_yaml(data, tmp_path), str(tmp_path / "out"),
                         signing.keypair()[0])


def test_compile_carries_readme_warnings(tmp_path):
    data = _parsed(checks=[_check_with_collect(
        "payload_gone", {"path": "C:\\ProgramData\\Subsystems\\payload.ps1"},
        "Delete `C:\\ProgramData\\Subsystems\\payload.ps1`; the whole "
        "C:\\ProgramData\\Subsystems directory is planted.")])
    data["theme"] = _readme_theme(tmp_path, "Look in `C:\\ProgramData\\Subsystems`.")
    outputs = compile_scenario(_write_yaml(data, tmp_path), str(tmp_path / "out"),
                               signing.keypair()[0])
    assert len(outputs["readme_warnings"]) == 1
    assert "Subsystems" in outputs["readme_warnings"][0]


def test_compile_clean_readme_has_empty_warnings(tmp_path):
    data = _parsed()
    data["theme"] = _readme_theme(tmp_path, "A perfectly innocent handbook.")
    outputs = compile_scenario(_write_yaml(data, tmp_path), str(tmp_path / "out"),
                               signing.keypair()[0])
    assert outputs["readme_warnings"] == []


def test_invalid_readme_lint_allow_fails_validation(tmp_path):
    data = _parsed()
    data["theme"] = _readme_theme(tmp_path, "Innocent.", readme_lint_allow="svc_legacy")
    with pytest.raises(ValueError, match="readme_lint_allow"):
        compile_scenario(_write_yaml(data, tmp_path), str(tmp_path / "out"),
                         signing.keypair()[0])


# --- all-boxes regression -------------------------------------------------------

def test_every_box_in_repo_is_lint_clean():
    repo_root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    scenario_paths = sorted(
        glob.glob(os.path.join(repo_root, "boxes", "*", "scenario*.yaml")))
    assert scenario_paths, "no boxes found — run from a repo checkout"
    leaks = []
    for scenario_path in scenario_paths:
        parsed = yaml.safe_load(open(scenario_path, encoding="utf-8"))
        theme = parsed.get("theme") or {}
        readme_rel = theme.get("readme")
        if not readme_rel:
            continue
        readme_path = os.path.join(os.path.dirname(scenario_path), readme_rel)
        text = open(readme_path, encoding="utf-8").read()
        errors, warnings = lint_readme(parsed, text)
        box = os.path.basename(os.path.dirname(scenario_path))
        leaks.extend(f"{box}: {m}" for m in errors + warnings)
    assert leaks == [], "\n".join(leaks)
