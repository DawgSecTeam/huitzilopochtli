"""Regression coverage for the themed Opochtli Landing Port Authority example.

This box introduces two firsts for the series:
- DIFFICULTY-WEIGHTED scoring: display tier prefix must agree with the point
  value (EASY=5, MODERATE=10, HARD=20) and with expect.points/max_points.
- the command_json check type: every authored script must emit exactly one
  JSON document; these tests actually run each script (unprivileged, on the
  dev machine) and assert parseable output.
"""
import base64
import json
import os
import re
import subprocess

import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from boxbuilder.spec import load_spec
from common.crypto import signing
from common.matchers import evaluate_matcher


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "opochtli-landing")
SCENARIO = os.path.join(BOX_DIR, "scenario.yaml")
BOX = os.path.join(BOX_DIR, "box.yaml")
NAKON = os.path.join(BOX_DIR, "nakon.json")
BEACON_SEED = os.path.join(
    REPO_ROOT, "boxbuilder", "vulndb_vuln_configs", "raw-socket-beacon.json")
BEACON_SOURCE = os.path.join(
    REPO_ROOT, "boxbuilder", "vulndb_vuln_configs", "raw-socket-beacon.c")

CHECK_COUNT = 26
CHECK_POINTS = 280
FORENSICS_POINTS = 50
TOTAL_POINTS = CHECK_POINTS + FORENSICS_POINTS

TIER_POINTS = {"EASY": 5, "MODERATE": 10, "HARD": 20}


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _matcher(check):
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_opochtli_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, SCENARIO) == []
    checks = parsed["checks"]
    assert len(checks) == CHECK_COUNT
    assert len({check["id"] for check in checks}) == CHECK_COUNT
    assert sum(check["max_points"] for check in checks) == CHECK_POINTS
    assert sum(fq["points"] for fq in parsed["forensics"]) == FORENSICS_POINTS
    assert sum(check["max_points"] for check in checks) + sum(
        fq["points"] for fq in parsed["forensics"]) == TOTAL_POINTS

    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Opochtli Landing Port Authority"
    assert manifest["theme"]["logo_b64"]


def test_opochtli_difficulty_tiers_match_points():
    """The box's signature change: display tier prefix, max_points, and
    expect.points must all agree (EASY=5, MODERATE=10, HARD=20)."""
    for check in _load_scenario()["checks"]:
        if check["category"] != "vuln":
            # penalty/prohibited checks don't carry a positive tier
            assert check["display"].startswith("PENALTY:"), (
                f"{check['id']}: non-vuln check must say PENALTY"
            )
            assert check["expect"]["points"] < 0, (
                f"{check['id']}: penalty points must be negative"
            )
            continue
        match = re.match(r"^(EASY|MODERATE|HARD):", check["display"])
        assert match, f"{check['id']}: display must start with a tier prefix"
        tier = match.group(1)
        assert check["max_points"] == TIER_POINTS[tier], (
            f"{check['id']}: {tier} display but max_points={check['max_points']}"
        )
        assert check["expect"]["points"] == TIER_POINTS[tier], (
            f"{check['id']}: {tier} display but expect.points="
            f"{check['expect']['points']}"
        )

    forensics_points = {
        "fq-key-comment": 5,
        "fq-docking-unit": 5,
        "fq-docking-port": 10,
        "fq-c2-destination": 10,
        "fq-backdoor-source": 20,
    }
    for fq in _load_scenario()["forensics"]:
        assert fq["points"] == forensics_points[fq["id"]]


def test_opochtli_command_json_scripts_emit_valid_json():
    """Every command_json script is read-only and emits exactly one JSON
    document. Run each one unprivileged: iptables/nft probes degrade to the
    fallback branch without root, which is exactly the fail-closed shape we
    want to see -- parseable JSON either way."""
    for check in _load_scenario()["checks"]:
        if check["type"] != "command_json":
            continue
        proc = subprocess.run(
            ["/bin/sh", "-c", check["collect"]["script"]],
            capture_output=True, text=True, timeout=30,
        )
        out = proc.stdout.strip()
        assert out, f"{check['id']}: script produced no output"
        assert not proc.stderr.strip().startswith("/bin/sh:"), (
            f"{check['id']}: script has a shell syntax problem: {proc.stderr}"
        )
        parsed = json.loads(out)  # raises if the script broke its contract
        assert parsed in (True, False, "DROP", "ACCEPT"), (
            f"{check['id']}: unexpected emitted value {parsed!r}"
        )


def test_opochtli_box_and_nakon_inputs_resolve():
    spec = load_spec(BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Opochtli Landing Port Authority"

    with open(NAKON, encoding="utf-8") as f:
        machines = json.load(f)["machines"]
    assert len(machines) == 1
    requested = machines[0]["configurations"]
    names = [item if isinstance(item, str) else item["name"] for item in requested]
    assert names.count("insecure-file-mode") == 3
    assert names.count("local-user") == 2
    for name in (
        "user-login-shell", "user-sudo-nopasswd", "systemd-service",
        "raw-socket-beacon", "backdoor-firewall-rule", "ssh-root-login",
        "ufw-removed",
    ):
        assert name in names

    # Raw-socket beacon seed: embedded binary decodes to an ELF, source
    # provenance file present next to it.
    seed = json.load(open(BEACON_SEED, encoding="utf-8"))
    assert seed["name"] == "raw-socket-beacon"
    embedded = re.search(r"_B64='([A-Za-z0-9+/=]+)'", seed["script"])
    assert embedded, "beacon seed script must embed the binary as _B64"
    blob = base64.b64decode(embedded.group(1))
    assert blob.startswith(b"\x7fELF"), "embedded beacon must be an ELF binary"
    assert os.path.isfile(BEACON_SOURCE), (
        "raw-socket-beacon.c (patched source + provenance) must ship next to the seed"
    )


def test_opochtli_plant_vars_match_paired_checks():
    """The pairing discipline: FILE_PATH/SERVICE_NAME/USERNAME in nakon.json
    must byte-match the scenario's collect params (nothing cross-checks)."""
    checks = {c["id"]: c for c in _load_scenario()["checks"]}
    nakon = json.load(open(NAKON, encoding="utf-8"))
    vars_list = [
        item["vars"]
        for item in nakon["machines"][0]["configurations"]
        if isinstance(item, dict)
    ]

    def paths_with(key):
        return {v[key] for v in vars_list if key in v}

    assert paths_with("FILE_PATH") == {
        checks["manifest_private"]["collect"]["path"],
        checks["pilot_key_private"]["collect"]["path"],
        checks["no_planted_pilot_key"]["collect"]["path"],
    }
    services = {v["SERVICE_NAME"] for v in vars_list if "SERVICE_NAME" in v}
    assert services == {
        checks["docking_agent_disabled"]["collect"]["service"].removesuffix(".service"),
        checks["beacon_disabled"]["collect"]["service"].removesuffix(".service"),
    }
    users = {v["USERNAME"] for v in vars_list if "USERNAME" in v}
    assert "stevedore" in users and "nightwatch" in users and "cranelift" in users

    # process_state patterns match the planted payload paths
    payload_paths = {v["PAYLOAD_PATH"] for v in vars_list if "PAYLOAD_PATH" in v}
    assert "/usr/local/libexec/docking-agent" in payload_paths
    planted_binaries = payload_paths | {"/usr/local/libexec/.cache-refresh"}
    for cid in ("docking_agent_killed", "beacon_killed"):
        pattern = checks[cid]["collect"]["pattern"]
        assert any(re.search(pattern, p) for p in planted_binaries), (
            f"{cid}: pattern {pattern!r} matches nothing planted"
        )


def test_opochtli_file_regex_extracts_have_capturing_groups():
    """The file_regex collector REQUIRES a capturing group in `extract`
    (solar-observatory shipped one ungrouped and the check was unpassable)."""
    for check in _load_scenario()["checks"]:
        if check["type"] != "file_regex":
            continue
        pattern = check["collect"]["extract"]
        compiled = re.compile(pattern)  # raises on an invalid pattern
        assert compiled.groups >= 1, (
            f"{check['id']}: file_regex extract {pattern!r} has no capturing "
            "group; the collector would error on every run"
        )


def test_opochtli_pairings_score_secure_states_and_reject_planted_states():
    checks = {check["id"]: check for check in _load_scenario()["checks"]}

    # command_json, boolean emission (firewall enforcing)
    secure, reason = evaluate_matcher(_matcher(checks["firewall_enforcing"]), {"data": True, "text": "true"})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["firewall_enforcing"]), {"data": False, "text": "false"})
    assert not planted, reason

    # command_json, string emission (default-deny)
    secure, reason = evaluate_matcher(_matcher(checks["default_deny_incoming"]), {"data": "DROP"})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["default_deny_incoming"]), {"data": "ACCEPT"})
    assert not planted, reason

    # command_json, backdoor-rule absence is the hardened state
    secure, reason = evaluate_matcher(_matcher(checks["backdoor_rule_removed"]), {"data": True})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["backdoor_rule_removed"]), {"data": False})
    assert not planted, reason

    # package
    secure, reason = evaluate_matcher(_matcher(checks["ufw_installed"]), {"installed": True, "version": "0.36"})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["ufw_installed"]), {"installed": False, "version": None})
    assert not planted, reason

    # db_query (pilot house still reachable)
    secure, reason = evaluate_matcher(_matcher(checks["pilot_house_reachable"]), {"ok": True, "error": None})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["pilot_house_reachable"]), {"ok": False, "error": "refused"})
    assert not planted, reason

    # permission, file absent (passwordless-sudo drop-in removed)
    secure, reason = evaluate_matcher(_matcher(checks["no_passwordless_sudo"]), {"exists": False, "mode": None})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["no_passwordless_sudo"]), {"exists": True, "mode": "0440"})
    assert not planted, reason

    # permission, mode_at_most
    secure, reason = evaluate_matcher(_matcher(checks["manifest_private"]), {"mode": "0640", "exists": True})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["manifest_private"]), {"mode": "0666", "exists": True})
    assert not planted, reason

    # file_regex, hardened == no match (planted key removed)
    secure, reason = evaluate_matcher(_matcher(checks["no_planted_pilot_key"]), {"matched": None})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["no_planted_pilot_key"]), {"matched": "harbor-pilot-key"})
    assert not planted, reason

    # file_regex, hardened == nologin shell
    secure, reason = evaluate_matcher(_matcher(checks["cranelift_no_shell"]), {"matched": "/usr/sbin/nologin"})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["cranelift_no_shell"]), {"matched": "/bin/bash"})
    assert not planted, reason

    # file_regex, sshd root login
    secure, reason = evaluate_matcher(_matcher(checks["ssh_no_root"]), {"matched": "no"})
    assert secure, reason
    planted, reason = evaluate_matcher(_matcher(checks["ssh_no_root"]), {"matched": "yes"})
    assert not planted, reason

    # user_group
    secure, reason = evaluate_matcher(
        _matcher(checks["no_stevedore"]),
        {"users": ["root", "harbormaster"], "group_members": {}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_stevedore"]),
        {"users": ["root", "harbormaster", "stevedore"], "group_members": {}},
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["harbormaster_sole_admin"]),
        {"users": ["root", "harbormaster"], "group_members": {"sudo": ["harbormaster"]}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["harbormaster_sole_admin"]),
        {"users": ["root", "harbormaster", "stevedore"],
         "group_members": {"sudo": ["harbormaster", "stevedore"]}},
    )
    assert not planted, reason

    # service_state / process_state pairs (rogue listener AND silent beacon)
    for disabled, killed in (
        ("docking_agent_disabled", "docking_agent_killed"),
        ("beacon_disabled", "beacon_killed"),
    ):
        secure, reason = evaluate_matcher(
            _matcher(checks[disabled]), {"active": False, "enabled": False}
        )
        assert secure, reason
        planted, reason = evaluate_matcher(
            _matcher(checks[disabled]), {"active": True, "enabled": True}
        )
        assert not planted, reason

        secure, reason = evaluate_matcher(
            _matcher(checks[killed]), {"running": False, "count": 0, "pids": [], "sample_cmdline": None}
        )
        assert secure, reason
        planted, reason = evaluate_matcher(
            _matcher(checks[killed]),
            {"running": True, "count": 1, "pids": [4321],
             "sample_cmdline": "/usr/local/libexec/.cache-refresh"},
        )
        assert not planted, reason
