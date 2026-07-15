"""YAML -> (manifest, rubric, engine scenario record) build pipeline.
See architecture.md §8.

PHASE 1 TASK: implement. May use PyYAML (author-machine only — never
shipped to the box or bundled into the zipapp).
"""
import base64
import dataclasses
import json
import os

import yaml

from authoring.sign_scenario import sign_manifest
from authoring.validate import validate_scenario_yaml
from common.crypto.signing import public_key_from_private
from common.schema import (
    Category,
    CheckSpec,
    Manifest,
    Mode,
    Rubric,
    RubricEntry,
    SCHEMA_VERSION,
    SlaParams,
    validate_manifest,
    validate_rubric,
)

_DEFAULT_TIMEOUT_S = 5.0
_DEFAULT_HOST_ID = "localhost"


def _build_check_spec(check: dict) -> CheckSpec:
    expect = check.get("expect", {}) or {}
    return CheckSpec(
        id=check["id"],
        type=check["type"],
        category=Category(check["category"]),
        host_id=check.get("host_id", _DEFAULT_HOST_ID),
        collect_params=check.get("collect", {}),
        display_title=check["display"],
        display_max_points=check["max_points"],
        timeout_s=check.get("timeout_s", _DEFAULT_TIMEOUT_S),
        is_sla=bool(check.get("is_sla") or ("sla" in expect)),
    )


def _build_rubric_entry(check: dict) -> RubricEntry:
    expect = dict(check.get("expect", {}) or {})
    category = check["category"]

    points = expect.pop("points", 0)
    sla_raw = expect.pop("sla", None)

    # Validate the type here, before `-abs(points)` below: a non-int (e.g. the
    # author wrote `points: "5"`) would otherwise raise a bare TypeError deep in
    # abs() rather than the clean, actionable message validate_rubric produces.
    # bool is a subclass of int, so reject it explicitly.
    if isinstance(points, bool) or not isinstance(points, int):
        raise ValueError(
            f"check {check.get('id')!r}: expect.points must be an integer, "
            f"got {points!r}"
        )

    # Whatever remains in `expect` after stripping `points`/`sla` is the
    # matcher dict passed to common.matchers.evaluate_matcher (§8 example:
    # expect: {equals: "no", points: 5} -> matcher {"equals": "no"}).
    matcher = expect

    if category in ("penalty", "prohibited"):
        # RubricEntry.points is SIGNED (common/schema.py). Authors write a
        # positive number in expect.points; penalty/prohibited categories
        # must be stored as negative regardless of the sign the author used.
        points = -abs(points)

    sla = None
    if sla_raw is not None:
        sla = SlaParams(
            interval_s=sla_raw["interval_s"],
            points_per_interval=sla_raw["points_per_interval"],
            hysteresis_fail_n=sla_raw.get("hysteresis_fail_n", 2),
            hysteresis_ok_n=sla_raw.get("hysteresis_ok_n", 2),
            max_intervals_per_checkin=sla_raw.get("max_intervals_per_checkin", 3),
        )

    return RubricEntry(
        check_id=check["id"],
        category=Category(category),
        matcher=matcher,
        points=points,
        sla=sla,
    )


def compile_scenario(yaml_path: str, out_dir: str, authoring_private_key: bytes) -> dict:
    """Pipeline (§8):
      1. Parse scenario YAML.
      2. authoring.validate.validate_scenario_yaml(...) — fail loudly with
         line-referenced errors.
      3. Split into: Manifest (public collection instructions + display
         metadata), Rubric (expected values + points + SLA params), and the
         engine scenario record (rubric + adversary event pool + RNG seed
         source) — engine-only, never distributed to boxes.
      4. Sign the manifest with the authoring private key
         (authoring.sign_scenario.sign_manifest).
      5. Emit manifest.signed.json always; for honor mode also emit the
         rubric to bundle into the box image; for ranked, emit the rubric +
         engine record for out-of-band upload to the engine.

    `authoring_private_key` is a required parameter (not in the original
    stub signature): signing (step 4) needs a real key supplied by the
    caller — compile_scenario must not generate or hold key material of its
    own, since key custody belongs to the author/CI environment, not to the
    build tool.

    Returns a dict of output file paths written under out_dir.
    """
    with open(yaml_path, "r") as f:
        parsed = yaml.safe_load(f.read())

    errors = validate_scenario_yaml(parsed, yaml_path)
    if errors:
        raise ValueError("\n".join(errors))

    scenario = parsed["scenario"]
    # NOTE: per the §8 YAML example, `checks` and `adversary` are TOP-LEVEL
    # keys (siblings of `scenario`), not nested under `scenario`.
    checks = parsed["checks"]

    check_specs = [_build_check_spec(c) for c in checks]
    rubric_entries = [_build_rubric_entry(c) for c in checks]

    manifest = Manifest(
        schema_version=SCHEMA_VERSION,
        scenario_name=scenario["name"],
        scenario_version=scenario["version"],
        mode=Mode(scenario["mode"]),
        engine_url=scenario.get("engine_url"),
        hosts=scenario["hosts"],
        checks=check_specs,
    )

    rubric = Rubric(
        schema_version=SCHEMA_VERSION,
        scenario_name=scenario["name"],
        scenario_version=scenario["version"],
        entries=rubric_entries,
    )

    # The adversary event pool + seed source live ONLY in the engine scenario
    # record, never anywhere near the Manifest object (§8, §12).
    engine_record = {
        "rubric": dataclasses.asdict(rubric),
        "adversary": parsed.get("adversary", {}),
    }

    manifest_dict = dataclasses.asdict(manifest)
    rubric_dict = dataclasses.asdict(rubric)

    # Structural validation of the compiled artifacts (fail the build loudly).
    schema_errors = validate_manifest(manifest_dict)
    if schema_errors:
        raise ValueError("\n".join(schema_errors))

    schema_errors = validate_rubric(rubric_dict)
    if schema_errors:
        raise ValueError("\n".join(schema_errors))

    signed_manifest = sign_manifest(manifest_dict, authoring_private_key)

    os.makedirs(out_dir, exist_ok=True)

    outputs = {}

    manifest_path = os.path.join(out_dir, "manifest.signed.json")
    with open(manifest_path, "w") as f:
        json.dump(signed_manifest, f)
    outputs["manifest"] = manifest_path

    if manifest.mode == Mode.HONOR:
        rubric_path = os.path.join(out_dir, "rubric.json")
        with open(rubric_path, "w") as f:
            json.dump(rubric_dict, f)
        outputs["rubric"] = rubric_path

    # Emitted for both modes: ranked needs it out-of-band uploaded to the
    # engine, and it's harmless (not distributed to boxes either way) for
    # honor mode too.
    engine_record_path = os.path.join(out_dir, "engine_record.json")
    with open(engine_record_path, "w") as f:
        json.dump(engine_record, f)
    outputs["engine_record"] = engine_record_path

    # Distributable verification artifact: the box needs the authoring
    # PUBLIC key to verify manifest.signed.json's signature (§7, §16). The
    # public key is always re-derivable from the private key, so no separate
    # key material needs to be tracked -- just export it here, always.
    public_key = public_key_from_private(authoring_private_key)
    public_key_path = os.path.join(out_dir, "authoring_public_key.b64")
    with open(public_key_path, "w") as f:
        f.write(base64.b64encode(public_key).decode("ascii"))
    outputs["authoring_public_key"] = public_key_path

    return outputs
