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
import re
import subprocess
import sys
import time
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
    # The honor stamp embeds wall-clock time ("Last checked: ..." plus the
    # countdown's render-anchored deadline), which necessarily differs between
    # two sequential runs; compare everything except those volatile values.
    stamp = re.compile(
        rb"Last checked: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC"
        rb"|endMs=\d+\+\d+\*1000"
    )
    content_a, content_b = stamp.sub(b"<ts>", content_a), stamp.sub(b"<ts>", content_b)
    assert content_a == content_b, (
        "report.html from `python3 -m agent` and the built .pyz differ -- "
        "the zipapp is not functionally equivalent to the source tree run"
    )
    # Also sanity-check the report actually reflects the scenario, so an
    # empty-but-matching report on both sides wouldn't slip through unnoticed.
    assert b"Total: 10" in content_a


def test_huitz_cli_verbs_through_zipapp(tmp_path):
    """The built .pyz doubles as the `huitz` console: verb dispatch works
    from the artifact a box actually runs, and the reading verbs render a
    snapshot without needing anything else on disk."""
    pyz_path = str(tmp_path / "agent.pyz")
    _build(pyz_path)

    # A minimal, hand-written v1 snapshot — the format the CLI reads.
    snap = {
        "snapshot_version": 1, "agent_version": "test", "mode": "honor",
        "scenario_name": "smoke", "scenario_version": 1,
        "title": "Smoke Box", "organization": None, "accent": None,
        "awaiting_engine": False, "total": 12, "max_possible": 20,
        "progress_pct": 60,
        "fixed": [{"title": "Harden a thing", "points": 12}],
        "vulns_fixed": 1, "vulns_total": 1, "remaining": 0, "all_fixed": True,
        "penalties": [], "forensics": [], "forensics_earned": 0,
        "delta": 12, "computed_at": 1700000000.0,
        "next_event_at": 1700000060.0, "last_confirmed_at": None,
        "next_checkin_s": None, "sla_status": [],
    }
    report_json = tmp_path / "report.json"
    report_json.write_text(json.dumps(snap), encoding="utf-8")

    def _cli(*args):
        return subprocess.run(
            [sys.executable, pyz_path, *args],
            cwd=str(tmp_path), capture_output=True, text=True, timeout=30,
        )

    # score renders the board (piped -> plain text, hints shown)
    r = _cli("score", "--report", str(report_json))
    assert r.returncode == 0, r.stderr
    assert "Smoke Box" in r.stdout
    assert "12 pts" in r.stdout
    assert "VULNERABILITIES FIXED — 1 of 1" in r.stdout
    assert "\x1b" not in r.stdout, "piped output must be plain"

    # score --json round-trips the snapshot
    r = _cli("score", "--json", "--report", str(report_json))
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == snap

    # help succeeds; unknown verb is a usage error (exit 2)
    assert _cli("help").returncode == 0
    r = _cli("frobnicate")
    assert r.returncode == 2

    # Installed under the shim name (what boxbuilder puts on PATH), a bare
    # invocation is help — not a hunt for agent_config.json. The classic
    # bare-pyz behavior (default config lookup) is unchanged.
    import shutil
    shim = tmp_path / "huitz"
    shutil.copy(pyz_path, shim)
    shim.chmod(0o755)
    r = subprocess.run([str(shim)], cwd=str(tmp_path),
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "scoring console" in r.stdout

    # a missing snapshot is a clean runtime error (exit 1), not a traceback
    r = _cli("score", "--report", str(tmp_path / "nope.json"))
    assert r.returncode == 1
    assert "no grade found" in r.stderr


def test_zipapp_ranked_smoke(tmp_path):
    """The .pyz a box actually runs enrolls and checks in against a real
    engine, using a real compiled + SIGNED manifest (the fidelity the
    loopback tier's unsigned fixtures skip)."""
    import test_ranked_loopback as lb
    from authoring.compile import compile_scenario

    engine = lb._EngineProc(
        tmp_path, env_extra={"HUITZILOPOCHTLI_CHECKIN_INTERVAL_S": "2"})
    try:
        name = "zipapp-ranked"
        target_file = tmp_path / "sshd_config"
        target_file.write_text("PermitRootLogin no\n", encoding="utf-8")

        engine.upload_scenario(lb._base_rubric(name, [
            {"check_id": "backdoor-absent", "category": "vuln",
             "matcher": {"tag": "equals", "field": "matched", "value": "no"},
             "points": 10},
        ]))
        token = engine.mint_token(name)

        scenario_yaml = tmp_path / "scenario.yaml"
        scenario_yaml.write_text(
            f"""
scenario:
  name: {name}
  version: 1
  mode: ranked
  engine_url: "{engine.base_url}"
  hosts:
    - localhost

checks:
  - id: backdoor-absent
    type: file_regex
    category: vuln
    host_id: localhost
    display: "no root login backdoor"
    max_points: 10
    collect:
      path: {target_file}
      extract: "PermitRootLogin (\\\\w+)"
    expect:
      equals: no
      points: 10
""",
            encoding="utf-8",
        )
        out_dir = tmp_path / "compiled"
        priv, _pub = keypair()
        outputs = compile_scenario(str(scenario_yaml), str(out_dir), priv)

        identity_path = tmp_path / "identity.json"
        config = {
            "mode": "ranked",
            "manifest_path": outputs["manifest"],
            "rubric_path": None,
            "identity_path": str(identity_path),
            "report_path": str(tmp_path / "report.html"),
            "checkin_interval_s": 1,
            "authoring_public_key_path": outputs["authoring_public_key"],
            "enrollment_token": token,
        }
        config_path = tmp_path / "agent_config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f)

        pyz_path = str(tmp_path / "agent.pyz")
        _build(pyz_path)

        # The ranked agent loops forever; give it ~3 crypto-bound cycles at
        # the 2s engine cadence, then stop it and inspect engine state.
        proc = subprocess.Popen(
            [sys.executable, pyz_path, str(config_path)],
            cwd=str(tmp_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(14.0)
        finally:
            proc.terminate()
            try:
                out, err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate(timeout=5)
        assert "Traceback" not in err, f".pyz ranked run crashed:\n{err}"

        assert identity_path.exists(), ".pyz never wrote an identity file"
        with open(identity_path) as f:
            box_id = json.load(f)["box_id"]
        assert os.path.exists(str(identity_path) + ".enrolled"), (
            ".pyz never confirmed enrollment with a signed check-in"
        )

        row = lb._query_box(engine.db_path, box_id)
        assert row is not None, ".pyz never enrolled with the engine"
        assert row["last_seq"] >= 2, (
            f"expected multiple check-ins at the 2s cadence, got "
            f"last_seq={row['last_seq']}"
        )

        rows = engine.leaderboard(name)
        assert len(rows) == 1 and rows[0]["total"] == 10, rows

        # The report the player sees reflects the engine's authoritative
        # score, not a box-local evaluation.
        report = (tmp_path / "report.html").read_text(encoding="utf-8")
        assert "Total: 10" in report
    finally:
        engine.stop()
