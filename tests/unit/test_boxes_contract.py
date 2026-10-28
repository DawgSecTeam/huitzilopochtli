"""Cross-box contracts.

Everything here is derived from whatever exists under ``boxes/*/box.yaml``:
no box is named, and adding or deleting a box needs no test edit. The point is
that a box cannot be added without inheriting the invariants that matter:

* the layout and the spec are minimal and deployment-free,
* every authored target compiles, deterministically, into a valid
  manifest/rubric/engine record,
* the rubric's arithmetic agrees with the manifest,
* the manifest never carries the answer key,
* ranked records carry services and a rewritten adversary schedule.

Box-specific data lives in ``boxes/``; box-specific *behaviour* is lint's job
(planted artefact <-> scored check) and the per-check-type unit tests' job
(matchers). This module is the shared floor beneath both.
"""
import glob
import json
import os

import pytest
import yaml

from authoring.compile import compile_scenario
from common.scenario_record import base_mode, merge_effective
from boxbuilder.os_family import KNOWN_OS, family
from boxbuilder.spec import load_spec
from common.crypto import signing

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_SPECS = sorted(glob.glob(os.path.join(REPO, "boxes", "*", "box.yaml")))
BOXES = [os.path.basename(os.path.dirname(path)) for path in BOX_SPECS]

# pool values are deployment inputs, not authored ones; a ranked compile
# expands them from the environment. A box may author the generic trio or
# scenario-specific names (HUITZILOPOCHTLI_<SLUG>_POOL_TEMPLATE_*), so both
# are seeded for every box and a new box inherits the floor without edits.
POOL_ENV = {
    "HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID": "4242",
    "HUITZILOPOCHTLI_POOL_TEMPLATE_USER": "template-user",
    "HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD": "template-password",
}


def _per_slug_pool_env(box: str) -> dict:
    prefix = "HUITZILOPOCHTLI_" + box.upper().replace("-", "_") + "_POOL_TEMPLATE"
    return {f"{prefix}_VM_ID": "4242",
            f"{prefix}_USER": "template-user",
            f"{prefix}_PASSWORD": "template-password"}


def _box_dir(box: str) -> str:
    return os.path.join(REPO, "boxes", box)


def _parsed(box: str) -> dict:
    return yaml.safe_load(open(os.path.join(_box_dir(box), "scenario.yaml"),
                               encoding="utf-8"))


def _targets(box: str) -> list:
    """Build targets the file authorises, in a stable order."""
    parsed = _parsed(box)
    declared = base_mode(parsed)
    targets = ["honor"] if declared == "honor" else []
    if declared == "ranked" or parsed.get("ranked"):
        targets.append("ranked")
    return targets


CASES = [(box, target) for box in BOXES for target in _targets(box)]


@pytest.fixture(scope="session")
def authoring_key():
    """One Ed25519 keypair for the whole module (signing is the slow part)."""
    private, _public = signing.keypair()
    return private


@pytest.fixture(autouse=True)
def _pool_env(monkeypatch):
    for name, value in POOL_ENV.items():
        monkeypatch.setenv(name, value)
    for box in BOXES:
        for name, value in _per_slug_pool_env(box).items():
            monkeypatch.setenv(name, value)


def test_the_corpus_is_not_empty():
    assert BOXES, "no boxes/*/box.yaml found"
    assert CASES, "no box authors a build target"


@pytest.mark.parametrize("box", BOXES)
def test_box_layout_is_minimal(box):
    directory = _box_dir(box)
    for name in ("scenario.yaml", "box.yaml", "nakon.json"):
        assert os.path.isfile(os.path.join(directory, name)), f"{box}: {name}"

    spec = yaml.safe_load(open(os.path.join(directory, "box.yaml"), encoding="utf-8"))
    assert spec.get("scenario") == "scenario.yaml", box
    assert spec.get("nakon_config") == "nakon.json", box
    provider = spec.get("provider") or {}
    # Deployment facts belong to the invocation, never the committed spec.
    for forbidden in ("host", "password"):
        assert forbidden not in provider, f"{box}: provider.{forbidden} is committed"
    assert "mode" not in spec, f"{box}: the build target is a CLI argument"


@pytest.mark.parametrize("box", BOXES)
def test_nakon_config_is_deployable(box):
    config = json.load(open(os.path.join(_box_dir(box), "nakon.json"),
                            encoding="utf-8"))
    machines = config.get("machines") or []
    assert len(machines) == 1, f"{box}: boxbuilder targets exactly one machine"
    machine = machines[0]
    assert machine.get("name"), box
    assert machine.get("os") in KNOWN_OS, f"{box}: unknown os {machine.get('os')!r}"
    entries = machine.get("configurations") or []
    assert entries, f"{box}: no vulnerabilities selected"
    for entry in entries:
        name = entry if isinstance(entry, str) else entry.get("name")
        assert isinstance(name, str) and name.strip(), f"{box}: bad configuration entry"
        if isinstance(entry, dict):
            assert isinstance(entry.get("vars") or {}, dict), box


@pytest.mark.parametrize("box", BOXES)
def test_theme_assets_exist_and_match_the_target(box):
    parsed = _parsed(box)
    theme = parsed.get("theme") or {}
    for key in ("wallpaper", "readme", "logo"):
        rel = theme.get(key)
        if rel:
            assert os.path.isfile(os.path.join(_box_dir(box), rel)), f"{box}: {key}"
    nakon = json.load(open(os.path.join(_box_dir(box), "nakon.json"),
                           encoding="utf-8"))
    if family(nakon["machines"][0]["os"]) == "windows":
        assert not theme.get("motd"), f"{box}: Windows has no motd mechanism"


@pytest.mark.parametrize("box,target", CASES, ids=[f"{b}-{t}" for b, t in CASES])
def test_compile_contract(box, target, tmp_path, authoring_key):
    spec = load_spec(os.path.join(_box_dir(box), "box.yaml"), mode=target)
    out = compile_scenario(spec.scenario_path, str(tmp_path), authoring_key,
                           mode=target)
    manifest = json.load(open(out["manifest"], encoding="utf-8"))
    record = json.load(open(out["engine_record"], encoding="utf-8"))
    rubric = record["rubric"]

    assert manifest["mode"] == target
    assert record["mode"] == target
    assert manifest["scenario_name"] == _parsed(box)["scenario"]["name"]
    if target == "honor":
        assert os.path.isfile(out["rubric"]), "honor ships a rubric"
    else:
        assert "rubric" not in {os.path.basename(p) for p in out.values()
                                if isinstance(p, str)}

    checks = manifest["checks"]
    entries = {entry["check_id"]: entry for entry in rubric["entries"]}
    ids = [check["id"] for check in checks]
    assert len(ids) == len(set(ids)), f"{box}: duplicate check ids"
    assert set(ids) == set(entries), f"{box}: manifest and rubric disagree"

    for check in checks:
        entry = entries[check["id"]]
        # The manifest may carry what to collect, never what to expect.
        assert "expect" not in check and "matcher" not in check, check["id"]
        assert "solution" not in check, check["id"]
        if check["is_sla"]:
            assert entry["points"] == 0, f"{check['id']}: SLA scores by drip"
            assert entry.get("sla"), f"{check['id']}: SLA entry needs parameters"
        else:
            assert entry.get("sla") is None, check["id"]
            assert abs(entry["points"]) == check["display_max_points"], (
                f"{check['id']}: points {entry['points']} != "
                f"max {check['display_max_points']}")

    # forensics: the question is public, the answer key is rubric-only.
    # An answer may legitimately equal an artefact name that a hardening check
    # also inspects, so the invariant is about the *shape*: a manifest question
    # carries only id/question/max_points, and the accepted answers live in the
    # rubric's matcher.
    for question in manifest.get("forensics") or []:
        entry = entries[question["id"]]
        assert set(question) <= {"id", "question", "max_points"}, question["id"]
        assert entry["matcher"].get("tag") == "answer_equals", question["id"]
        assert entry["points"] == question["max_points"], question["id"]
        assert entry["matcher"].get("value") or entry["matcher"].get("values"), (
            f"{question['id']}: rubric entry carries no accepted answer")
    for fq in _parsed(box).get("forensics") or []:
        assert fq["id"] in ids, f"{box}: forensics question missing a check"

    # ranked records carry services and rewrite service ids to check ids
    if target == "ranked":
        effective = merge_effective(_parsed(box), "ranked")
        service_ids = {svc["id"] for svc in effective["services"]}
        assert len(record["services"]) == len(service_ids), box
        for service in record["services"]:
            assert service["check_id"] in ids, service
        for event in (record.get("adversary") or {}).get("events") or []:
            affects = event.get("affects_check")
            if isinstance(affects, str):
                assert affects not in service_ids, (
                    f"{box}: adversary affects_check must be rewritten to svc_*")
    else:
        assert not manifest.get("services"), f"{box}: honor manifest has services"


@pytest.mark.parametrize("box", [b for b, t in CASES if t == "ranked"],
                         ids=[b for b, t in CASES if t == "ranked"])
def test_engine_parses_the_record_compile_writes(box, tmp_path, authoring_key):
    """Engine/authoring parity, pinned per committed ranked box.

    The engine parses boxes/<box>/scenario.yaml itself (sync_box_scenarios);
    boxbuilder compile writes engine_record.json. Both go through
    common.scenario_record, so the served record must equal the compiled one
    exactly -- and validate under the engine's own validator.
    """
    from common.scenario_record import build_scenario_parts
    from engine.scenario import validate_scenario_record

    spec = load_spec(os.path.join(_box_dir(box), "box.yaml"), mode="ranked")
    out = compile_scenario(spec.scenario_path, str(tmp_path), authoring_key,
                           mode="ranked")
    compiled = json.load(open(out["engine_record"], encoding="utf-8"))

    parsed = yaml.safe_load(open(spec.scenario_path, encoding="utf-8"))
    built = build_scenario_parts(parsed, "ranked",
                                 source=spec.scenario_path)["engine_record"]

    assert built == compiled
    assert validate_scenario_record(
        built["rubric"], built["adversary"], built["services"],
        built.get("pool")) == []


@pytest.mark.parametrize("box,target", CASES[:2],
                         ids=[f"{b}-{t}" for b, t in CASES[:2]])
def test_compilation_is_deterministic(box, target, tmp_path, authoring_key):
    """Same inputs, same bytes: a rebuilt template must match its lineage."""
    spec = load_spec(os.path.join(_box_dir(box), "box.yaml"), mode=target)
    first = compile_scenario(spec.scenario_path, str(tmp_path / "a"), authoring_key,
                             mode=target)
    second = compile_scenario(spec.scenario_path, str(tmp_path / "b"), authoring_key,
                              mode=target)
    for key in ("manifest", "engine_record"):
        assert open(first[key], "rb").read() == open(second[key], "rb").read(), key
