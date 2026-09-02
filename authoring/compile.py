"""YAML -> (manifest, rubric, engine scenario record) build pipeline. See architecture.md §8."""
import base64
import dataclasses
import json
import os
from typing import Optional

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

_MAX_LOGO_BYTES = 150 * 1024  # Keep signed manifest small (logo is data: URI).


def _build_manifest_theme(theme_raw: Optional[dict], yaml_path: str) -> Optional[dict]:
    """Build the small cosmetic theme subset that ships in the Manifest."""
    if not theme_raw:
        return None

    manifest_theme = {
        "title": theme_raw.get("title"),
        "organization": theme_raw.get("organization"),
        "accent": theme_raw.get("accent"),
        "logo_b64": None,
    }

    logo = theme_raw.get("logo")
    if logo:
        logo_path = logo if os.path.isabs(logo) else os.path.join(os.path.dirname(yaml_path), logo)
        if not os.path.isfile(logo_path):
            raise ValueError(f"theme.logo not found: {logo_path}")
        with open(logo_path, "rb") as f:
            data = f.read()
        if len(data) > _MAX_LOGO_BYTES:
            raise ValueError(
                f"theme.logo is {len(data)} bytes, over the {_MAX_LOGO_BYTES}-byte cap "
                f"for embedding in the signed manifest: {logo_path}"
            )
        manifest_theme["logo_b64"] = base64.b64encode(data).decode("ascii")

    return manifest_theme


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

    if isinstance(points, bool) or not isinstance(points, int):
        raise ValueError(
            f"check {check.get('id')!r}: expect.points must be an integer, "
            f"got {points!r}"
        )

    matcher = expect

    if category in ("penalty", "prohibited"):
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
    """Compile scenario YAML into signed manifest, rubric, and engine record."""
    with open(yaml_path, "r") as f:
        parsed = yaml.safe_load(f.read())

    errors = validate_scenario_yaml(parsed, yaml_path)
    if errors:
        raise ValueError("\n".join(errors))

    scenario = parsed["scenario"]
    checks = parsed["checks"]

    check_specs = [_build_check_spec(c) for c in checks]
    rubric_entries = [_build_rubric_entry(c) for c in checks]
    manifest_theme = _build_manifest_theme(parsed.get("theme"), yaml_path)

    manifest = Manifest(
        schema_version=SCHEMA_VERSION,
        scenario_name=scenario["name"],
        scenario_version=scenario["version"],
        mode=Mode(scenario["mode"]),
        engine_url=scenario.get("engine_url"),
        hosts=scenario["hosts"],
        checks=check_specs,
        theme=manifest_theme,
    )

    rubric = Rubric(
        schema_version=SCHEMA_VERSION,
        scenario_name=scenario["name"],
        scenario_version=scenario["version"],
        entries=rubric_entries,
    )

    engine_record = {
        "rubric": dataclasses.asdict(rubric),
        "adversary": parsed.get("adversary", {}),
    }

    manifest_dict = dataclasses.asdict(manifest)
    rubric_dict = dataclasses.asdict(rubric)

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

    engine_record_path = os.path.join(out_dir, "engine_record.json")
    with open(engine_record_path, "w") as f:
        json.dump(engine_record, f)
    outputs["engine_record"] = engine_record_path

    public_key = public_key_from_private(authoring_private_key)
    public_key_path = os.path.join(out_dir, "authoring_public_key.b64")
    with open(public_key_path, "w") as f:
        f.write(base64.b64encode(public_key).decode("ascii"))
    outputs["authoring_public_key"] = public_key_path

    return outputs
