"""Unit tests for boxbuilder.nakon (subprocess wrappers + address reconciliation).

The build/deploy wrappers are tested by putting a fake `nakon` on PATH that
emits the documented --json shapes. We never hit a real vulndb or SSH target.
"""
import json
import os
import sys
import textwrap

import pytest

from boxbuilder import nakon


# --- resolve_nakon_dir ----------------------------------------------------
def test_resolve_nakon_dir_explicit(tmp_path):
    fake = tmp_path / "nakon"
    (fake / "nakon").mkdir(parents=True)
    (fake / "nakon" / "cli.py").write_text("# stub\n")
    assert nakon.resolve_nakon_dir(str(fake)) == str(fake)


def test_resolve_nakon_dir_env(tmp_path, monkeypatch):
    fake = tmp_path / "envnakon"
    (fake / "nakon").mkdir(parents=True)
    (fake / "nakon" / "cli.py").write_text("# stub\n")
    monkeypatch.setenv("NAKON_DIR", str(fake))
    assert nakon.resolve_nakon_dir() == str(fake)


def test_resolve_nakon_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("NAKON_DIR", str(tmp_path / "nope"))
    with pytest.raises(nakon.NakonError, match="nakon repo not found"):
        nakon.resolve_nakon_dir()


# --- build_bundle / deploy_bundle via a fake nakon ------------------------
def _install_fake_nakon(tmp_path, monkeypatch, *, build_json=None, deploy_json=None,
                        exit_code=0):
    """Create a fake `python3 -m nakon` by pointing NAKON_DIR at a dir whose
    `nakon/__main__.py` prints the canned JSON. The wrappers invoke
    `sys.executable -m nakon` with cwd=NAKON_DIR, so this is exactly what they
    run."""
    ndir = tmp_path / "nakon"
    pkg = ndir / "nakon"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "cli.py").write_text("# marker for resolve_nakon_dir\n")
    main = pkg / "__main__.py"
    build_blob = json.dumps(build_json) if build_json is not None else "null"
    deploy_blob = json.dumps(deploy_json) if deploy_json is not None else "null"
    main.write_text(textwrap.dedent(f"""\
        import sys, json
        cmd = sys.argv[1] if len(sys.argv) > 1 else ""
        # log to stderr, result to stdout (one JSON line), like real nakon
        if cmd == "build":
            sys.stderr.write("[nakon] building...\\n")
            print({build_blob!r})
        elif cmd == "deploy":
            sys.stderr.write("[nakon] deploying...\\n")
            print({deploy_blob!r})
        sys.exit({exit_code})
    """))
    monkeypatch.setenv("NAKON_DIR", str(ndir))
    return str(ndir)


def test_build_bundle_parses_summary(tmp_path, monkeypatch):
    ndir = _install_fake_nakon(
        tmp_path, monkeypatch,
        build_json={"bundle_id": "abc123", "path": "bundles/abc123",
                    "cached": False, "plans": 1, "machines": 1},
    )
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}")
    info = nakon.build_bundle(ndir, str(cfg))
    assert info["bundle_id"] == "abc123"
    # path is made absolute (relative to nakon_dir).
    assert os.path.isabs(info["path"])
    assert info["path"].endswith("bundles/abc123")


def test_build_bundle_handles_log_lines_before_json(tmp_path, monkeypatch):
    """Real nakon prints log lines on stdout BEFORE the final --json line when
    not perfectly disciplined; we take splitlines()[-1]. Confirm robustness."""
    pkg = tmp_path / "nakon" / "nakon"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "cli.py").write_text("# marker\n")
    # Note: this fake prints TWO lines on stdout, JSON last.
    (pkg / "__main__.py").write_text(
        'import sys,json; '
        'print("stray log line"); '
        'print(json.dumps({"bundle_id":"z","path":"b/z","cached":True,"plans":0,"machines":0}))'
    )
    monkeypatch.setenv("NAKON_DIR", str(tmp_path / "nakon"))
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}")
    info = nakon.build_bundle(str(tmp_path / "nakon"), str(cfg))
    assert info["bundle_id"] == "z"


def test_build_bundle_nonzero_exit_raises(tmp_path, monkeypatch):
    ndir = _install_fake_nakon(tmp_path, monkeypatch, build_json={}, exit_code=1)
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}")
    with pytest.raises(nakon.NakonError) as ei:
        nakon.build_bundle(ndir, str(cfg))
    assert ei.value.returncode == 1


def test_deploy_bundle_parses_outcome(tmp_path, monkeypatch):
    ndir = _install_fake_nakon(
        tmp_path, monkeypatch,
        deploy_json={"bundle_id": "b", "machines": [
            {"name": "web01", "ip": "1.2.3.4", "plan_id": "p", "error": None,
             "exit_status": 0, "steps": [], "failures": []}],
            "failures": 0, "ok": True, "log_dir": None},
    )
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}")
    out = nakon.deploy_bundle(ndir, "/bundle", str(cfg))
    assert out["ok"] is True
    assert out["failures"] == 0


def test_deploy_bundle_strict_failure_raises(tmp_path, monkeypatch):
    ndir = _install_fake_nakon(
        tmp_path, monkeypatch,
        deploy_json={"ok": False, "failures": 1, "machines": [], "log_dir": None},
        exit_code=1,  # nakon exits 1 under --strict on failure
    )
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}")
    with pytest.raises(nakon.NakonError):
        nakon.deploy_bundle(ndir, "/bundle", str(cfg), strict=True)


# --- address reconciliation -----------------------------------------------
AGENT_CONFIG = {
    "machines": [
        {"id": 1, "name": "web01", "ip": "10.0.0.5", "os": "linux",
         "user": "agentuser", "password": "agentpass",
         "configurations": ["nginx", "ssh-root-login"]},
    ]
}


def test_derive_deploy_config_uses_provider_address(tmp_path):
    derived = nakon.derive_deploy_config(
        AGENT_CONFIG, "web01", host="192.168.99.99",
        user="provideruser", password="providerpass", port=2222,
    )
    m = derived["machines"][0]
    # Address comes from the PROVIDER, not the agent config.
    assert m["ip"] == "192.168.99.99"
    assert m["user"] == "provideruser"
    assert m["password"] == "providerpass"
    assert m["port"] == 2222
    # Vulns come from the AGENT config.
    assert m["configurations"] == ["nginx", "ssh-root-login"]
    assert m["name"] == "web01"
    assert m["os"] == "linux"


def test_derive_deploy_config_unknown_machine(tmp_path):
    with pytest.raises(KeyError, match="not found"):
        nakon.derive_deploy_config(AGENT_CONFIG, "nope", "h", "u", "p")


def test_first_machine_name():
    assert nakon.first_machine_name(AGENT_CONFIG) == "web01"


def test_first_machine_name_empty():
    with pytest.raises(ValueError, match="no machines"):
        nakon.first_machine_name({"machines": []})
