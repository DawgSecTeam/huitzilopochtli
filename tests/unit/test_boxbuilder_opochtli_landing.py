"""Regression coverage for the Opochtli Landing Port Authority example, v2.

The v2 rebuild is the series' first CLI-era box: headless Debian 13 running
the huitz terminal console, raw-iptables-only firewall scoring, and a
difficulty-weighted ledger (EASY=5, MODERATE=10, HARD=20) carried over from
v1. What these tests pin down:

- the ledger itself (check count, tier/points agreement, penalty floor,
  forensics split) — the ledger IS the contract with the students;
- every command_json script actually runs and emits exactly one JSON scalar
  even where iptables is missing or unprivileged (fail-closed shape);
- the plant<->check pairing discipline (beacon path/unit/C2 target must
  byte-match between nakon.json vars, scenario collect params, and the
  forensics answers — nothing cross-checks them at build time);
- matcher pass/reject pairs for every check's hardened vs planted state.
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
REALM_SEED = os.path.join(
    REPO_ROOT, "boxbuilder", "vulndb_vuln_configs", "realm-beacon.json")
COCKPIT_SEED = os.path.join(
    REPO_ROOT, "boxbuilder", "vulndb_vuln_configs", "cockpit-installed.json")

CHECK_COUNT = 9          # 8 vuln + 1 penalty
VULN_POINTS = 100        # penalty floor (-10) excluded from attainable
FORENSICS_POINTS = 40
TOTAL_POINTS = VULN_POINTS + FORENSICS_POINTS

TIER_POINTS = {"EASY": 5, "MODERATE": 10, "HARD": 20}

# The DISASTEROUS_PHARMACY plant (realm-beacon seed defaults, mirrored in
# nakon.json vars) — the single source of truth for the beacon coupling.
BEACON_UNIT = "tide-sync.service"
BEACON_PATH = "/opt/tide-sync/tide-syncd"
BEACON_C2 = "10.233.0.66:8443"
BIND_UNIT = "system-update.service"


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
    vuln = [c for c in checks if c["category"] == "vuln"]
    penalty = [c for c in checks if c["category"] != "vuln"]
    assert sum(c["max_points"] for c in vuln) == VULN_POINTS
    assert len(penalty) == 1 and penalty[0]["max_points"] == 10
    assert sum(fq["points"] for fq in parsed["forensics"]) == FORENSICS_POINTS
    assert sum(c["max_points"] for c in vuln) + sum(
        fq["points"] for fq in parsed["forensics"]) == TOTAL_POINTS

    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Opochtli Landing Port Authority"
    # headless CLI box: the handbook rides the manifest, there is no logo
    assert manifest["theme"]["readme_text"].startswith("# Opochtli Landing")
    assert manifest["theme"]["logo_b64"] is None
    # the answers must ride the rubric only, never the signed manifest
    assert not any(c.get("answer") for c in manifest["checks"])


def test_opochtli_difficulty_tiers_match_points():
    """Display tier prefix, max_points, and expect.points must all agree
    (EASY=5, MODERATE=10, HARD=20); non-vuln checks are penalties."""
    for check in _load_scenario()["checks"]:
        if check["category"] != "vuln":
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
        "fq-beacon-destination": 20,
        "fq-bind-shell": 20,
    }
    for fq in _load_scenario()["forensics"]:
        assert fq["points"] == forensics_points[fq["id"]]


def test_opochtli_command_json_scripts_emit_valid_json():
    """Every command_json script is read-only and emits exactly one JSON
    document. Run each one unprivileged: iptables/ss probes degrade to the
    fail-closed branch without root, which is exactly the shape we want --
    parseable JSON either way, never a traceback and never two documents."""
    for check in _load_scenario()["checks"]:
        if check["type"] != "command_json":
            continue
        proc = subprocess.run(
            ["/bin/sh", "-c", check["collect"]["script"]],
            capture_output=True, text=True, timeout=60,
        )
        out = proc.stdout.strip()
        assert out, f"{check['id']}: script produced no output"
        assert not proc.stderr.strip().startswith("/bin/sh:"), (
            f"{check['id']}: script has a shell syntax problem: {proc.stderr}"
        )
        parsed = json.loads(out)  # raises if the script broke its contract
        assert parsed in (True, False), (
            f"{check['id']}: unexpected emitted value {parsed!r}"
        )


def test_opochtli_command_json_scripts_detect_persisted_rules(tmp_path):
    """The firewall scripts key off iptables-save signatures; feed one a
    hardened ruleset through a stub and each must flip to its secure value."""
    scenario = _load_scenario()
    checks = {c["id"]: c for c in scenario["checks"]}

    hardened = "\n".join([
        "-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT DROP",
        "-A INPUT -i lo -j ACCEPT",
        "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT",
        "-A OUTPUT -p tcp -m tcp --dport 3306 -j ACCEPT",
        "",
    ])

    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "iptables-save").write_text("#!/bin/sh\ncat <<'RULES'\n" + hardened + "RULES\n")
    (stub / "iptables-save").chmod(0o755)

    for cid, want in (("web_input_80_allowed", True),
                      ("db_output_3306_allowed", True)):
        proc = subprocess.run(
            ["/bin/sh", "-c",
             f'PATH={stub}:$PATH {checks[cid]["collect"]["script"]}'],
            capture_output=True, text=True, timeout=30,
        )
        assert json.loads(proc.stdout.strip()) is want, (
            f"{cid}: hardened ruleset should emit {want}, got {proc.stdout!r}"
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
    for name in ("cockpit-installed", "ncat-listener-autostart", "realm-beacon"):
        assert name in names

    # realm-beacon seed: embedded binary decodes to an ELF; the documented
    # defaults are the DISASTEROUS_PHARMACY story (path, C2, codename).
    seed = json.load(open(REALM_SEED, encoding="utf-8"))
    assert seed["name"] == "realm-beacon"
    assert seed["run_as"] == "root"
    embedded = re.search(r"_B64='([A-Za-z0-9+/=]+)'", seed["script"])
    assert embedded, "realm-beacon seed script must embed the binary as _B64"
    blob = base64.b64decode(embedded.group(1))
    assert blob.startswith(b"\x7fELF"), "embedded beacon must be an ELF binary"
    assert 'BEACON_PATH="${BEACON_PATH:-' + BEACON_PATH + '}"' in seed["script"]
    assert 'TARGET_IP="${TARGET_IP:-' + BEACON_C2.rsplit(":", 1)[0] + '}"' in seed["script"]
    assert 'DISASTEROUS_PHARMACY' in seed["script"]

    # cockpit seed: enables the socket (the thing the check scores)
    cockpit = json.load(open(COCKPIT_SEED, encoding="utf-8"))
    assert "cockpit.socket" in cockpit["script"]


def test_opochtli_plant_vars_match_paired_checks():
    """The pairing discipline: realm-beacon's vars must byte-match the
    scenario's collect params and the forensics answers (nothing
    cross-checks them at build time)."""
    checks = {c["id"]: c for c in _load_scenario()["checks"]}
    forensics = {f["id"]: f for f in _load_scenario()["forensics"]}
    nakon = json.load(open(NAKON, encoding="utf-8"))
    realm = next(
        item for item in nakon["machines"][0]["configurations"]
        if isinstance(item, dict) and item["name"] == "realm-beacon"
    )["vars"]

    assert realm["SERVICE_NAME"] + ".service" == BEACON_UNIT
    assert checks["beacon_service_removed"]["collect"]["service"] == BEACON_UNIT
    assert realm["BEACON_PATH"] == BEACON_PATH
    assert checks["beacon_binary_removed"]["collect"]["path"] == BEACON_PATH
    assert realm["BEACON_PATH"] == checks["beacon_process_gone"]["collect"]["pattern"]
    c2 = f"{realm['TARGET_IP']}:{realm['TARGET_PORT']}"
    assert c2 == BEACON_C2
    answers = {forensics["fq-beacon-destination"]["answer"], *forensics["fq-beacon-destination"].get("answers", [])}
    assert c2 in answers

    # the bind-shell check must target the unit the catalog row installs
    assert BIND_UNIT in checks["bind_shell_removed"]["collect"]["script"]
    # ...and the cockpit check must target the socket the seed enables
    assert "cockpit.socket" in checks["cockpit_removed"]["collect"]["script"]


def test_opochtli_pairings_score_secure_states_and_reject_planted_states():
    checks = {check["id"]: check for check in _load_scenario()["checks"]}

    # command_json, boolean emission (rules present / quiet ports)
    for cid in ("web_input_80_allowed", "db_output_3306_allowed",
                "default_deny_all", "cockpit_removed", "bind_shell_removed"):
        secure, reason = evaluate_matcher(
            _matcher(checks[cid]), {"data": True, "text": "true"})
        assert secure, f"{cid}: {reason}"
        planted, reason = evaluate_matcher(
            _matcher(checks[cid]), {"data": False, "text": "false"})
        assert not planted, f"{cid}: {reason}"

    # permission, binary deleted is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(checks["beacon_binary_removed"]), {"exists": False, "mode": None})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["beacon_binary_removed"]), {"exists": True, "mode": "0755"})
    assert not planted, reason

    # process_state, beacon dead is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(checks["beacon_process_gone"]),
        {"running": False, "count": 0, "pids": [], "sample_cmdline": None})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["beacon_process_gone"]),
        {"running": True, "count": 1, "pids": [4321],
         "sample_cmdline": BEACON_PATH + " -t 10.233.0.66 -p 8443"})
    assert not planted, reason

    # service_state, launcher disabled is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(checks["beacon_service_removed"]), {"active": False, "enabled": False})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["beacon_service_removed"]), {"active": True, "enabled": True})
    assert not planted, reason

    # db_query penalty: sshd answering keeps the management path alive
    secure, reason = evaluate_matcher(
        _matcher(checks["console_reachable"]), {"ok": True, "error": None})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["console_reachable"]), {"ok": False, "error": "refused"})
    assert not planted, reason
