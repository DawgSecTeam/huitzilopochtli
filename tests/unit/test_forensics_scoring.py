"""Unit tests for scored forensics questions (CyberPatriot-style).

Covers the full in-process pipeline without network or box installs:
matcher normalization, the forensics_answer collector, compile output shapes
(public question in the manifest, answer key only in the rubric), manifest
validation leak guards, the agent's write-if-missing answers template, and
the reporter's forensics card.
"""
import json
import os

import pytest
import yaml

from agent.__main__ import _prepare_forensics
from agent.checks.forensics import ForensicsAnswerCheck
from agent.checks.base import CHECKS
from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from common.crypto.signing import keypair
from common.matchers import evaluate_matcher
from common.schema import (
    CheckResult, Category, CheckSpec, CollectorStatus, Evidence,
    ForensicsQuestion, Manifest, Mode, validate_manifest,
)


# --- answer_equals matcher ---------------------------------------------------

def _match(matcher, answer):
    return evaluate_matcher(matcher, {"answer": answer})


def test_answer_equals_exact_and_normalized():
    matcher = {"tag": "answer_equals", "value": "cocoa-hidden-sync"}
    assert _match(matcher, "cocoa-hidden-sync")[0] is True
    assert _match(matcher, "  Cocoa-Hidden-Sync  ")[0] is True
    assert _match(matcher, "/etc/cron.d/cocoa-hidden-sync")[0] is False


def test_answer_equals_punctuation_and_whitespace_tolerant():
    matcher = {"tag": "answer_equals", "value": "Port 587"}
    assert _match(matcher, "port  587.")[0] is True
    assert _match(matcher, '"port 587"')[0] is True


def test_answer_equals_accept_list():
    matcher = {"tag": "answer_equals", "accept": ["find", "/usr/bin/find"]}
    assert _match(matcher, "find")[0] is True
    assert _match(matcher, "/usr/bin/find")[0] is True
    assert _match(matcher, "grep")[0] is False


def test_answer_equals_never_matches_blank():
    matcher = {"tag": "answer_equals", "value": "x"}
    assert _match(matcher, "")[0] is False
    assert _match(matcher, "   ")[0] is False
    assert _match(matcher, "____")[0] is False          # untouched placeholder
    assert _match(matcher, "____ some guess ____")[0] is False
    assert evaluate_matcher(matcher, {})[0] is False     # no answer field


# --- forensics_answer collector ----------------------------------------------

def _spec(tmp_path, content, ordinal=1, path="answers.txt"):
    p = tmp_path / path
    if content is not None:
        p.write_text(content, encoding="utf-8")
    return CheckSpec(
        id="fq1", type="forensics_answer", category=Category.VULN,
        host_id="localhost", collect_params={"path": str(p), "ordinal": ordinal},
        display_title="q", display_max_points=5,
    )


def _collect(spec):
    return ForensicsAnswerCheck().collect(spec, ctx=None)


def test_collector_extracts_answer(tmp_path):
    content = "header\n\nQ1: Which file?\nAnswer: cocoa-sync\n\nQ2: other\nAnswer: ____\n"
    ev = _collect(_spec(tmp_path, content, ordinal=1))
    assert ev.status == CollectorStatus.OK
    assert ev.raw["answer"] == "cocoa-sync"

    ev2 = _collect(_spec(tmp_path, content, ordinal=2))
    assert ev2.status == CollectorStatus.OK
    assert ev2.raw["answer"] == "____"


def test_collector_blank_is_empty_string(tmp_path):
    content = "Q1: Which file?\nAnswer:\n"
    ev = _collect(_spec(tmp_path, content))
    assert ev.status == CollectorStatus.OK
    assert ev.raw["answer"] == ""


def test_collector_missing_block_is_error(tmp_path):
    ev = _collect(_spec(tmp_path, "Q2: other\nAnswer: x\n", ordinal=1))
    assert ev.status == CollectorStatus.ERROR

    ev2 = _collect(_spec(tmp_path, None))  # file missing entirely
    assert ev2.status == CollectorStatus.ERROR


def test_forensics_answer_registered():
    assert "forensics_answer" in CHECKS


# --- compile: public questions, keyed rubric ---------------------------------

def _compile(tmp_path, forensics_yaml):
    scenario = f"""
scenario:
  name: t
  version: 1
  mode: honor
  hosts: ["localhost"]

checks:
  - id: c1
    type: file_regex
    category: vuln
    display: d
    max_points: 5
    collect: {{}}
    expect:
      equals: y
      points: 5

{forensics_yaml}
"""
    (tmp_path / "s.yaml").write_text(scenario, encoding="utf-8")
    priv, _ = keypair()
    return compile_scenario(str(tmp_path / "s.yaml"), str(tmp_path / "out"), priv)


def test_compile_ships_questions_not_keys(tmp_path):
    outputs = _compile(tmp_path, """
forensics:
  - id: fq1
    question: "Which file?"
    answer: "cocoa-sync"
    points: 10
""")
    manifest = json.load(open(outputs["manifest"]))
    [fq] = manifest["forensics"]
    assert fq == {"id": "fq1", "question": "Which file?", "max_points": 10}
    rubric = json.load(open(outputs["rubric"]))
    [entry] = [e for e in rubric["entries"] if e["check_id"] == "fq1"]
    assert entry["matcher"] == {"tag": "answer_equals", "value": "cocoa-sync"}
    assert entry["points"] == 10
    # The forensics check spec exists and carries no rubric data.
    [spec] = [c for c in manifest["checks"] if c["id"] == "fq1"]
    assert spec["type"] == "forensics_answer"
    assert "answer" not in spec["collect_params"]


def test_scenario_yaml_forensics_validation_errors():
    parsed = {
        "scenario": {"name": "x", "version": 1, "mode": "honor", "hosts": ["h"]},
        "checks": [],
        "forensics": [{"id": "fq1", "question": "q?", "points": 10}],  # no answer
    }
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("missing required key 'answer'" in e for e in errors)

    parsed["forensics"] = [{"id": "fq1", "question": "q?", "answer": "a", "points": -1}]
    errors = validate_scenario_yaml(parsed, "x.yaml")
    assert any("points must be a positive integer" in e for e in errors)


def test_validate_manifest_rejects_answer_keys_in_forensics():
    manifest = {
        "schema_version": 1, "scenario_name": "t", "scenario_version": 1,
        "mode": "honor", "hosts": ["localhost"], "checks": [],
        "forensics": [{"id": "fq1", "question": "q", "max_points": 5, "answer": "a"}],
    }
    errors = validate_manifest(manifest)
    assert any("must never ship in the manifest" in e for e in errors)


def test_validate_manifest_forensics_id_collision():
    manifest = {
        "schema_version": 1, "scenario_name": "t", "scenario_version": 1,
        "mode": "honor", "hosts": ["localhost"],
        "checks": [{
            "id": "c1", "type": "file_regex", "category": "vuln", "host_id": "h",
            "collect_params": {}, "display_title": "d", "display_max_points": 5,
        }],
        "forensics": [{"id": "c1", "question": "q", "max_points": 5}],
    }
    assert any("collides" in e for e in validate_manifest(manifest))

    # A forensics_answer check sharing the question id is by design, not a collision.
    manifest["checks"].append({
        "id": "fq1", "type": "forensics_answer", "category": "vuln", "host_id": "h",
        "collect_params": {}, "display_title": "q", "display_max_points": 5,
    })
    manifest["forensics"] = [{"id": "fq1", "question": "q", "max_points": 5}]
    errors = validate_manifest(manifest)
    assert not [e for e in errors if "collides" in e]


# --- agent template write-if-missing ----------------------------------------

def _manifest_with_forensics(tmp_path):
    spec = CheckSpec(
        id="fq1", type="forensics_answer", category=Category.VULN,
        host_id="localhost",
        collect_params={"path": "Forensics-Questions.txt", "ordinal": 1},
        display_title="Which file?", display_max_points=10,
    )
    return Manifest(
        schema_version=1, scenario_name="t", scenario_version=1, mode=Mode.HONOR,
        engine_url=None, hosts=["localhost"], checks=[spec], theme=None,
        forensics=[ForensicsQuestion(id="fq1", question="Which file?", max_points=10)],
    )


def test_prepare_forensics_writes_template_only_if_missing(tmp_path, monkeypatch):
    # Force the "default dir" resolution to the tmp dir (no real Desktop lookup).
    monkeypatch.setattr("agent.__main__._primary_desktop_dir", lambda: str(tmp_path))
    manifest = _manifest_with_forensics(tmp_path)

    _prepare_forensics(manifest, str(tmp_path))
    answers_path = tmp_path / "Forensics-Questions.txt"
    assert answers_path.exists()
    text = answers_path.read_text(encoding="utf-8")
    assert "Q1: Which file?" in text
    assert "Answer: " + "_" * 44 in text
    assert manifest.checks[0].collect_params["path"] == str(answers_path)

    # Team edits survive a re-run: the template is never overwritten.
    answers_path.write_text("Q1: Which file?\nAnswer: my-answer\n", encoding="utf-8")
    _prepare_forensics(manifest, str(tmp_path))
    assert "my-answer" in answers_path.read_text(encoding="utf-8")


def test_prepare_forensics_noop_without_forensics(tmp_path):
    manifest = _manifest_with_forensics(tmp_path)
    manifest.forensics = None
    _prepare_forensics(manifest, str(tmp_path))
    assert not (tmp_path / "Forensics-Questions.txt").exists()


# --- reporter forensics card -------------------------------------------------

def test_honor_board_renders_forensics_card():
    from agent.reporter import render_report
    from common.schema import ScoreBreakdown
    import time

    manifest = _manifest_with_forensics("/tmp")
    results = [
        CheckResult(check_id="fq1", category=Category.VULN,
                    awarded_points=10, passed=True, reason="ok"),
        CheckResult(check_id="c1", category=Category.VULN,
                    awarded_points=5, passed=True, reason="ok"),
    ]
    score = ScoreBreakdown(
        scenario_name="t", scenario_version=1, total=15, results=results,
        sla_status=[], computed_at=time.time(),
    )
    page = render_report(score, Mode.HONOR, None, manifest=manifest)
    assert "Forensics" in page
    assert "1 of 1 correct" in page
    assert "Which file?" in page
