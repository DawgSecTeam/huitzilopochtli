"""End-to-end integration tests for the honor-mode (local distribution)
pipeline: authoring/compile.py -> `python3 -m agent` (as a real subprocess)
-> report.html, plus packaging/rearm.py.

These are deliberately NOT unit tests against internal functions: they
exercise the actual CLI surface a box runs, using real subprocesses and
real files under `tmp_path`, mirroring the manual verification steps used
during the build. This is the CyberPatriot-style honor-mode / local
distribution path, which is the top-priority path to keep verified.
"""
import json
import os
import subprocess

from authoring.compile import compile_scenario
from common.crypto.signing import keypair

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SUBPROCESS_TIMEOUT_S = 30


# --- helpers ----------------------------------------------------------------


def _write_scenario_yaml(path, checks_yaml_snippet, name="honor-test-scenario"):
    yaml_text = f"""
scenario:
  name: {name}
  version: 1
  mode: honor
  hosts:
    - localhost

checks:
{checks_yaml_snippet}
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(yaml_text)
    return path


def _run_agent(config_path, timeout=_SUBPROCESS_TIMEOUT_S):
    return subprocess.run(
        ["python3", "-m", "agent", str(config_path)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _write_agent_config(
    tmp_path,
    manifest_path,
    rubric_path,
    report_path,
    authoring_public_key_path=None,
):
    config = {
        "mode": "honor",
        "manifest_path": str(manifest_path),
        "rubric_path": str(rubric_path),
        "identity_path": None,
        "report_path": str(report_path),
        "checkin_interval_s": None,
    }
    if authoring_public_key_path is not None:
        config["authoring_public_key_path"] = str(authoring_public_key_path)
    config_path = tmp_path / "agent_config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f)
    return config_path


# --- fixtures-as-setup -------------------------------------------------------


def _compile_basic_scenario(tmp_path):
    """Compile a scenario with one vuln (file_regex, matched) and one
    penalty (permission, intact) check. Returns
    (outputs, target_file, perm_file, priv_key)."""
    target_file = tmp_path / "motd.txt"
    target_file.write_text("flag=FOUND\n", encoding="utf-8")

    perm_file = tmp_path / "shadow_like_file"
    perm_file.write_text("secret\n", encoding="utf-8")
    os.chmod(perm_file, 0o644)

    checks_yaml = f"""
  - id: vuln-flag-present
    type: file_regex
    category: vuln
    display: "Flag file contains FOUND marker"
    max_points: 10
    collect:
      path: "{target_file}"
      extract: "flag=(\\\\w+)"
    expect:
      equals: "FOUND"
      points: 10

  - id: penalty-perm-intact
    type: permission
    category: penalty
    display: "Sensitive file is not world-writable"
    max_points: 5
    collect:
      path: "{perm_file}"
    expect:
      mode_at_most: true
      field: mode
      max_mode: "0644"
      points: 5
"""
    yaml_path = tmp_path / "scenario.yaml"
    _write_scenario_yaml(yaml_path, checks_yaml)

    priv_key, _pub_key = keypair()
    out_dir = tmp_path / "compiled"
    outputs = compile_scenario(str(yaml_path), str(out_dir), priv_key)
    return outputs, priv_key


# --- 1. happy path -----------------------------------------------------------


def test_happy_path_end_to_end_report(tmp_path):
    outputs, _priv_key = _compile_basic_scenario(tmp_path)

    report_path = tmp_path / "report.html"
    config_path = _write_agent_config(
        tmp_path,
        manifest_path=outputs["manifest"],
        rubric_path=outputs["rubric"],
        report_path=report_path,
        authoring_public_key_path=outputs["authoring_public_key"],
    )

    result = _run_agent(config_path)

    assert result.returncode == 0, (
        f"agent failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert report_path.exists(), "report.html was not written"

    html = report_path.read_text(encoding="utf-8")
    # vuln (+10, matched) + penalty (0, intact) = 10
    assert "Total: 10" in html
    assert "vuln-flag-present" in html
    assert "penalty-perm-intact" in html


# --- 2. manifest signature verification: valid -------------------------------


def test_manifest_signature_valid_no_verification_error(tmp_path):
    outputs, _priv_key = _compile_basic_scenario(tmp_path)

    report_path = tmp_path / "report.html"
    config_path = _write_agent_config(
        tmp_path,
        manifest_path=outputs["manifest"],
        rubric_path=outputs["rubric"],
        report_path=report_path,
        authoring_public_key_path=outputs["authoring_public_key"],
    )

    result = _run_agent(config_path)

    assert result.returncode == 0
    assert "signature" not in result.stderr.lower()
    assert "FAILED" not in result.stderr
    assert report_path.exists()
    assert "Total: 10" in report_path.read_text(encoding="utf-8")


# --- 3. manifest signature verification: tampered ----------------------------


def test_manifest_signature_tampered_rejected(tmp_path):
    outputs, _priv_key = _compile_basic_scenario(tmp_path)

    manifest_path = outputs["manifest"]
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_dict = json.load(f)

    # Mutate a field that is part of the signed payload without re-signing.
    manifest_dict["scenario_version"] = manifest_dict["scenario_version"] + 1

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_dict, f)

    report_path = tmp_path / "report.html"
    config_path = _write_agent_config(
        tmp_path,
        manifest_path=manifest_path,
        rubric_path=outputs["rubric"],
        report_path=report_path,
        authoring_public_key_path=outputs["authoring_public_key"],
    )

    result = _run_agent(config_path)

    assert result.returncode != 0, (
        f"agent should have refused to run on a tampered manifest; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert not report_path.exists(), (
        "report.html must not be (re)written when signature verification fails"
    )
    assert "signature verification" in result.stderr.lower()


# --- 4. manifest signature verification: back-compat fallback ---------------


def test_manifest_signature_backcompat_no_public_key_configured(tmp_path):
    outputs, _priv_key = _compile_basic_scenario(tmp_path)

    report_path = tmp_path / "report.html"
    # Deliberately omit authoring_public_key_path entirely.
    config_path = _write_agent_config(
        tmp_path,
        manifest_path=outputs["manifest"],
        rubric_path=outputs["rubric"],
        report_path=report_path,
        authoring_public_key_path=None,
    )

    result = _run_agent(config_path)

    assert result.returncode == 0, (
        f"agent failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "WARNING" in result.stderr
    assert "skip" in result.stderr.lower() or "SKIPPED" in result.stderr
    assert report_path.exists()
    assert "Total: 10" in report_path.read_text(encoding="utf-8")


# --- 5. multiple check categories in one scenario ----------------------------


def test_multiple_categories_total_is_correct_sum(tmp_path):
    vuln_file = tmp_path / "vuln_marker.txt"
    vuln_file.write_text("flag=FOUND\n", encoding="utf-8")

    perm_file = tmp_path / "sensitive_file"
    perm_file.write_text("secret\n", encoding="utf-8")
    os.chmod(perm_file, 0o644)

    prohibited_file = tmp_path / "backdoor_marker.txt"
    prohibited_file.write_text("flag2=BACKDOOR\n", encoding="utf-8")

    checks_yaml = f"""
  - id: vuln-check
    type: file_regex
    category: vuln
    display: "Vuln marker present"
    max_points: 10
    collect:
      path: "{vuln_file}"
      extract: "flag=(\\\\w+)"
    expect:
      equals: "FOUND"
      points: 10

  - id: penalty-check
    type: permission
    category: penalty
    display: "Sensitive file permission intact"
    max_points: 5
    collect:
      path: "{perm_file}"
    expect:
      mode_at_most: true
      field: mode
      max_mode: "0644"
      points: 5

  - id: prohibited-check
    type: file_regex
    category: prohibited
    display: "Backdoor marker absent"
    max_points: 7
    collect:
      path: "{prohibited_file}"
      extract: "flag2=(\\\\w+)"
    expect:
      equals: "BACKDOOR"
      points: 7
"""
    yaml_path = tmp_path / "scenario_multi.yaml"
    _write_scenario_yaml(yaml_path, checks_yaml, name="honor-multi-category")

    priv_key, _pub_key = keypair()
    out_dir = tmp_path / "compiled"
    outputs = compile_scenario(str(yaml_path), str(out_dir), priv_key)

    report_path = tmp_path / "report.html"
    config_path = _write_agent_config(
        tmp_path,
        manifest_path=outputs["manifest"],
        rubric_path=outputs["rubric"],
        report_path=report_path,
        authoring_public_key_path=outputs["authoring_public_key"],
    )

    result = _run_agent(config_path)

    assert result.returncode == 0, (
        f"agent failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert report_path.exists()

    html = report_path.read_text(encoding="utf-8")
    # vuln: matched -> +10
    # penalty: intact (matcher passes) -> 0 (no penalty applied)
    # prohibited: forbidden state matched/present -> -7
    # total = 10 + 0 - 7 = 3
    assert "Total: 3" in html
    assert "vuln-check" in html
    assert "penalty-check" in html
    assert "prohibited-check" in html


# --- 6. re-arm ---------------------------------------------------------------


def test_rearm_removes_report(tmp_path):
    outputs, _priv_key = _compile_basic_scenario(tmp_path)

    report_path = tmp_path / "report.html"
    config_path = _write_agent_config(
        tmp_path,
        manifest_path=outputs["manifest"],
        rubric_path=outputs["rubric"],
        report_path=report_path,
        authoring_public_key_path=outputs["authoring_public_key"],
    )

    run_result = _run_agent(config_path)
    assert run_result.returncode == 0
    assert report_path.exists(), "precondition: report must exist before rearm"

    rearm_script = os.path.join(_REPO_ROOT, "packaging", "rearm.py")
    rearm_result = subprocess.run(
        ["python3", rearm_script, "--config", str(config_path)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT_S,
    )

    assert rearm_result.returncode == 0, (
        f"rearm.py failed: stdout={rearm_result.stdout!r} "
        f"stderr={rearm_result.stderr!r}"
    )
    assert not report_path.exists(), "rearm.py must delete the cached report"
