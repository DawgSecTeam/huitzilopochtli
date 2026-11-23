"""Regression tests: a compiled RANKED manifest must not be a local answer
oracle. The manifest is world-readable on the box and players may have root,
so it may not carry verdict-computing collector scripts, boolean-on-data
expects, authored check ids (they name planted artifacts), or end-state
display titles. The real wording lives only in the engine-side rubric, which
sends titles back for passed checks only (engine/checkin.py).

See architecture.md §2.4 and the issue "ranked-mode answer reconstruction via
player-facing artifacts".
"""
import glob
import json
import os
import re
import tempfile

import pytest
import yaml

from authoring.compile import compile_scenario
from common.crypto import signing
from common.scenario_record import merge_effective

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))

_GENERIC_TITLES = {"Hardening finding", "Protective constraint", "Prohibited item"}
_OPAQUE_ID_RE = re.compile(r"^chk-\d{3}$")
_VERDICT_ECHO_RE = re.compile(r"\becho\s+(?:true|false|yes|no)\b", re.I)


def _ranked_boxes():
    out = []
    for path in sorted(glob.glob(os.path.join(_REPO_ROOT, "boxes", "*", "scenario*.yaml"))):
        parsed = yaml.safe_load(open(path, encoding="utf-8"))
        try:
            merge_effective(parsed, "ranked")
        except Exception:
            continue
        out.append(path)
    return out


def _compile_ranked(scenario_path):
    key = signing.keypair()[0]
    with tempfile.TemporaryDirectory() as d:
        out = compile_scenario(scenario_path, d, key, mode="ranked")
        manifest = json.load(open(out["manifest"], encoding="utf-8"))
        record = json.load(open(out["engine_record"], encoding="utf-8"))
    return manifest, record


def _hardening_checks(manifest):
    """Non-service, non-forensics checks: the ones whose ids/titles must be opaque."""
    return [
        c for c in manifest["checks"]
        if c["type"] != "forensics_answer" and not c["id"].startswith("svc_")
    ]


@pytest.mark.parametrize("scenario_path", _ranked_boxes(),
                         ids=[os.path.basename(os.path.dirname(p)) for p in _ranked_boxes()])
def test_ranked_manifest_ships_no_verdict_collectors(scenario_path):
    manifest, record = _compile_ranked(scenario_path)
    for check in manifest["checks"]:
        if check["type"] not in ("command_json", "powershell_json"):
            continue
        params = json.dumps(check.get("collect_params") or {})
        assert not _VERDICT_ECHO_RE.search(params), (
            f"{check['id']}: shipped collect script computes a boolean verdict")
    # The rubric must not keep the old boolean-on-data matcher either.
    for entry in record["rubric"]["entries"]:
        matcher = entry.get("matcher") or {}
        assert not (matcher.get("field") == "data"
                    and isinstance(matcher.get("equals", matcher.get("not_equals")), bool)), (
            f"{entry['check_id']}: rubric still scores a bare boolean on raw data")


@pytest.mark.parametrize("scenario_path", _ranked_boxes(),
                         ids=[os.path.basename(os.path.dirname(p)) for p in _ranked_boxes()])
def test_ranked_manifest_ids_and_titles_are_opaque(scenario_path):
    manifest, record = _compile_ranked(scenario_path)
    titles = {e["check_id"]: e.get("display_title", "")
              for e in record["rubric"]["entries"]}
    for check in _hardening_checks(manifest):
        assert _OPAQUE_ID_RE.match(check["id"]), (
            f"authored check id {check['id']!r} ships in the ranked manifest")
        assert check["display_title"] in _GENERIC_TITLES, (
            f"{check['id']}: end-state title {check['display_title']!r} ships in the "
            "ranked manifest")
        # The real wording survives engine-side so the engine can name passed
        # checks back to the box as progressive hints.
        real = titles.get(check["id"], "")
        assert real and real not in _GENERIC_TITLES


def test_honor_manifest_is_unchanged():
    """Honor boxes hold the rubric on-box and trust the player: ids and titles
    stay authored there."""
    path = os.path.join(_REPO_ROOT, "boxes", "vermilion-relay", "scenario.yaml")
    key = signing.keypair()[0]
    with tempfile.TemporaryDirectory() as d:
        out = compile_scenario(path, d, key, mode="honor")
        manifest = json.load(open(out["manifest"], encoding="utf-8"))
    ids = [c["id"] for c in manifest["checks"]]
    assert "no_blank_password" in ids
    titles = {c["id"]: c["display_title"] for c in manifest["checks"]}
    assert titles["no_blank_password"].startswith("MODERATE:")
