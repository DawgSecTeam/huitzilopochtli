"""Integration tests for packaging/build_zipapp.py.

LOCAL DISTRIBUTION verification priority: these tests confirm the actual
`.pyz` artifact a student receives -- not just the source tree -- builds
correctly, ships only agent/+common/ (never engine/ or authoring/), and
produces byte-identical output to running `python3 -m agent` directly out
of the repo. Any future change to agent/ or common/ that accidentally pulls
in something outside those two packages (breaking zipapp bundling) should
fail test 3 below.
"""
import json
import os
import subprocess
import sys
import zipfile

import pytest

from common.crypto.signing import keypair

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUILD_SCRIPT = os.path.join(REPO_ROOT, "packaging", "build_zipapp.py")


def _build(output_path: str) -> None:
    result = subprocess.run(
        [sys.executable, BUILD_SCRIPT, output_path],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"build_zipapp.py failed (rc={result.returncode})\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_build_succeeds_and_is_valid_zip(tmp_path):
    output_path = str(tmp_path / "agent.pyz")

    _build(output_path)

    assert os.path.isfile(output_path), "build_zipapp.py did not create the .pyz file"
    assert zipfile.is_zipfile(output_path), ".pyz output is not a valid zip archive"


def test_no_engine_or_authoring_code_leaks_in(tmp_path):
    output_path = str(tmp_path / "agent.pyz")
    _build(output_path)

    with zipfile.ZipFile(output_path) as zf:
        names = zf.namelist()

    assert names, "zipapp archive is empty"

    leaked = [
        n for n in names
        if n.startswith("engine/") or n.startswith("authoring/")
    ]
    assert not leaked, (
        f"zipapp must never bundle engine/ or authoring/ code, but found: {leaked}"
    )

    # Sanity: the packages that SHOULD be there actually are.
    assert any(n.startswith("agent/") for n in names), "agent/ missing from zipapp"
    assert any(n.startswith("common/") for n in names), "common/ missing from zipapp"


def _write_honor_scenario(tmp_path):
    """Compile a trivial honor-mode scenario, returning the compile.py
    output dict of file paths (all absolute, under tmp_path)."""
    from authoring.compile import compile_scenario

    target_file = tmp_path / "target.txt"
    target_file.write_text("flag_status: safe\n", encoding="utf-8")

    scenario_yaml = tmp_path / "scenario.yaml"
    scenario_yaml.write_text(
        f"""
scenario:
  name: zipapp-parity-check
  version: 1
  mode: honor
  hosts:
    - localhost

checks:
  - id: flag-check
    type: file_regex
    category: vuln
    host_id: localhost
    display: "Flag is safe"
    max_points: 10
    collect:
      path: {target_file}
      extract: "flag_status: (\\\\w+)"
    expect:
      equals: safe
      points: 10
""",
        encoding="utf-8",
    )

    out_dir = tmp_path / "compiled"
    private_key, _public_key = keypair()
    outputs = compile_scenario(str(scenario_yaml), str(out_dir), private_key)
    return outputs


def _write_agent_config(config_path, outputs, report_path):
    config = {
        "mode": "honor",
        "manifest_path": outputs["manifest"],
        "rubric_path": outputs["rubric"],
        "identity_path": None,
        "report_path": str(report_path),
        "checkin_interval_s": None,
        "authoring_public_key_path": outputs["authoring_public_key"],
        "enrollment_token": None,
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f)


def test_zipapp_matches_source_tree_run(tmp_path):
    """Core regression guard: running the same honor-mode scenario through
    `python3 -m agent` (source tree) and through the built `.pyz` must
    produce byte-for-byte identical report.html output."""
    outputs = _write_honor_scenario(tmp_path)

    pyz_path = str(tmp_path / "agent.pyz")
    _build(pyz_path)

    report_a_dir = tmp_path / "run_a"
    report_b_dir = tmp_path / "run_b"
    report_a_dir.mkdir()
    report_b_dir.mkdir()
    report_a = report_a_dir / "report.html"
    report_b = report_b_dir / "report.html"

    config_a = tmp_path / "agent_config_a.json"
    config_b = tmp_path / "agent_config_b.json"
    _write_agent_config(config_a, outputs, report_a)
    _write_agent_config(config_b, outputs, report_b)

    result_a = subprocess.run(
        [sys.executable, "-m", "agent", str(config_a)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result_a.returncode == 0, (
        f"python3 -m agent failed (rc={result_a.returncode})\n"
        f"stdout: {result_a.stdout}\nstderr: {result_a.stderr}"
    )

    result_b = subprocess.run(
        [sys.executable, pyz_path, str(config_b)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result_b.returncode == 0, (
        f"built .pyz run failed (rc={result_b.returncode})\n"
        f"stdout: {result_b.stdout}\nstderr: {result_b.stderr}"
    )

    assert report_a.exists(), "python3 -m agent did not write a report"
    assert report_b.exists(), ".pyz run did not write a report"

    content_a = report_a.read_bytes()
    content_b = report_b.read_bytes()
    assert content_a == content_b, (
        "report.html from `python3 -m agent` and the built .pyz differ -- "
        "the zipapp is not functionally equivalent to the source tree run"
    )
    # Also sanity-check the report actually reflects the scenario, so an
    # empty-but-matching report on both sides wouldn't slip through unnoticed.
    assert b"Total: 10" in content_a
