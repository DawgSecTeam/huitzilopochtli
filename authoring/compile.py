"""YAML -> (manifest, rubric, engine scenario record) build pipeline. See architecture.md §8."""
import base64
import dataclasses
import json
import os
from typing import Optional

import yaml

from authoring.readme_lint import lint_readme
from authoring.sign_scenario import sign_manifest
from authoring.validate import validate_scenario_yaml
from common.crypto.signing import public_key_from_private
from common.scenario_record import build_scenario_parts, base_mode
from common.schema import (
    Manifest,
    Mode,
    SCHEMA_VERSION,
    validate_manifest,
    validate_rubric,
)

_MAX_LOGO_BYTES = 150 * 1024  # Keep signed manifest small (logo is data: URI).
_MAX_README_BYTES = 64 * 1024  # Handbook text for `huitz readme` (plain UTF-8).


def _build_manifest_theme(theme_raw: Optional[dict], yaml_path: str) -> tuple:
    """Build the small cosmetic theme subset that ships in the Manifest.

    `readme` (the player-facing handbook) is embedded as TEXT: it is what
    lets `huitz readme` render the handbook from the report snapshot as any
    user, in both modes, without a desktop or a theme attachment. The
    desktop-asset side of the theme (wallpaper, shortcuts, the rendered
    README.html) still flows through the vulndb theme attachments at plant
    time and is untouched by this.

    Returns (manifest_theme, readme_text); readme_text is what the spoiler
    lint (authoring/readme_lint.py) runs against.
    """
    if not theme_raw:
        return None, None

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

    readme = theme_raw.get("readme")
    text = None  # a theme may brand without a handbook; None just skips the lint
    if readme:
        readme_path = readme if os.path.isabs(readme) else os.path.join(os.path.dirname(yaml_path), readme)
        if not os.path.isfile(readme_path):
            raise ValueError(f"theme.readme not found: {readme_path}")
        with open(readme_path, "r", encoding="utf-8") as f:
            text = f.read()
        if len(text.encode("utf-8")) > _MAX_README_BYTES:
            raise ValueError(
                f"theme.readme is over the {_MAX_README_BYTES}-byte cap "
                f"for embedding in the signed manifest: {readme_path}"
            )
        manifest_theme["readme_text"] = text

    return manifest_theme, text


def compile_scenario(yaml_path: str, out_dir: str, authoring_private_key: bytes,
                     mode: Optional[str] = None, engine_url: Optional[str] = None) -> dict:
    """Compile scenario YAML into signed manifest, rubric, and engine record.

    ``mode`` selects the build target (default: the file's ``scenario.mode``).
    ``ranked`` merges the file's ``ranked:`` block over the base content;
    ``honor`` never reads it. ``engine_url`` overrides the authored address.
    """
    with open(yaml_path, "r") as f:
        parsed = yaml.safe_load(f.read())

    errors = validate_scenario_yaml(parsed, yaml_path)
    if errors:
        raise ValueError("\n".join(errors))

    parts = build_scenario_parts(parsed, mode, engine_url=engine_url,
                                 source=yaml_path)
    effective = parts["effective"]
    scenario = effective["scenario"]

    manifest_theme, readme_text = _build_manifest_theme(effective["theme"], yaml_path)

    # Spoiler lint (HANDBOOK_GUIDE.md): a forensics answer in the handbook
    # blocks the compile; lesser leaks surface as warnings on the outputs.
    readme_errors, readme_warnings = [], []
    if readme_text:
        readme_errors, readme_warnings = lint_readme(parsed, readme_text)
        if readme_errors:
            raise ValueError("\n".join(readme_errors))

    manifest = Manifest(
        schema_version=SCHEMA_VERSION,
        scenario_name=scenario["name"],
        scenario_version=scenario["version"],
        mode=Mode(scenario["mode"]),
        engine_url=scenario.get("engine_url"),
        hosts=scenario["hosts"],
        checks=parts["check_specs"],
        theme=manifest_theme,
        forensics=parts["forensics_questions"] or None,
        services=[dataclasses.asdict(s) for s in parts["service_specs"]] or None,
    )

    rubric = parts["rubric"]
    engine_record = parts["engine_record"]

    manifest_dict = dataclasses.asdict(manifest)
    rubric_dict = dataclasses.asdict(rubric)

    schema_errors = validate_manifest(manifest_dict)
    if schema_errors:
        raise ValueError("\n".join(schema_errors))

    schema_errors = validate_rubric(rubric_dict)
    if schema_errors:
        raise ValueError("\n".join(schema_errors))

    signed_manifest = sign_manifest(manifest_dict, authoring_private_key)

    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass

    outputs = {}

    def _write_json(path: str, value, private: bool) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     0o600 if private else 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(path, 0o600 if private else 0o644)
        except OSError:
            pass

    manifest_path = os.path.join(out_dir, "manifest.signed.json")
    _write_json(manifest_path, signed_manifest, private=False)
    outputs["manifest"] = manifest_path

    if manifest.mode == Mode.HONOR:
        rubric_path = os.path.join(out_dir, "rubric.json")
        _write_json(rubric_path, rubric_dict, private=True)
        outputs["rubric"] = rubric_path

    engine_record_path = os.path.join(out_dir, "engine_record.json")
    _write_json(engine_record_path, engine_record, private=True)
    outputs["engine_record"] = engine_record_path

    public_key = public_key_from_private(authoring_private_key)
    public_key_path = os.path.join(out_dir, "authoring_public_key.b64")
    with open(public_key_path, "w", encoding="ascii") as f:
        f.write(base64.b64encode(public_key).decode("ascii"))
    outputs["authoring_public_key"] = public_key_path

    outputs["readme_warnings"] = readme_warnings

    return outputs
