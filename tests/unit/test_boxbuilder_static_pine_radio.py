"""Regression coverage for the Static Pine Community Radio box.

The persistence-workshop challenge: headless Debian 13 CLI box (huitz
terminal console), SIXTEEN planted persistence artifacts — one scored
finding each, compressed weighting (EASY=5 x8, MODERATE=10 x5, HARD=20 x3
= 150 attainable) — plus two daemon-health penalties (cron, atd) and NO
forensics block. What these tests pin down:

- the ledger itself (check count, tier/points agreement, penalty floor,
  no forensics) — the ledger IS the contract with the students;
- every command_json script actually runs and emits exactly one JSON
  scalar, and the hardened branch is the natural outcome on a clean host
  (nothing planted here);
- the plant<->check pairing discipline (every planted path/name must
  byte-match between nakon.json vars and the scenario collect params —
  nothing cross-checks them at build time);
- matcher pass/reject pairs for every check's hardened vs planted state;
- the twelve new "-persistence" nakon seeds: shell-syntax-clean,
  var-driven, and the embedded ld.so.preload object decodes to a real ELF
  DSO (a text blob there would make every dynamic binary print errors).
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
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "static-pine-radio")
SCENARIO = os.path.join(BOX_DIR, "scenario.yaml")
BOX = os.path.join(BOX_DIR, "box.yaml")
NAKON = os.path.join(BOX_DIR, "nakon.json")
SEEDS = os.path.join(REPO_ROOT, "boxbuilder", "vulndb_vuln_configs")

CHECK_COUNT = 18          # 16 vuln + 2 penalties
VULN_POINTS = 150         # penalty floor (-20 total) excluded from attainable
TIER_POINTS = {"EASY": 5, "MODERATE": 10, "HARD": 20}
TIER_COUNTS = {"EASY": 8, "MODERATE": 5, "HARD": 3}

NEW_SEEDS = [
    "cron-d-persistence", "crontab-persistence", "systemd-timer-persistence",
    "systemd-user-unit-persistence", "at-job-persistence", "initd-persistence",
    "rc-local-persistence", "profiled-persistence", "bashrc-persistence",
    "motd-persistence", "authorized-keys-persistence", "ld-preload-persistence",
]

# Planted artifact <-> check couplings: every (substring, where it must
# appear) pair, taken from nakon.json vars and mirrored in scenario.yaml.
COUPLINGS = {
    "cron_sync_removed": ["/etc/cron.d/nightcast-sync",
                          "/opt/nightcast/nightcast-sync"],
    "root_crontab_clean": [],  # grades spool emptiness; path coupling asserted via vars below
    "tapeops_crontab_cleared": ["tapeops"],
    "profile_d_gone": ["/etc/profile.d/nightcast-greeting.sh"],
    "stationlead_bashrc_clean": ["/home/stationlead/.bashrc"],
    "system_bashrc_clean": ["/etc/bash.bashrc"],
    "motd_script_gone": ["/etc/update-motd.d/99nightcast"],
    "rogue_account_removed": ["wireman"],
    "authorized_keys_clean": ["nightcast@88.3"],
    "nightcast_service_removed": ["nightcast.service",
                                  "/opt/nightcast/carrier-daemon"],
    "timer_neutralized": ["nightcast-rebroadcast.timer",
                          "/opt/nightcast/rebroadcast"],
    "at_queue_emptied": ["atq"],
    "initd_boot_script_gone": ["/etc/init.d/nightcast-agent"],
    "rc_local_clean": ["/opt/nightcast/sign-on"],
    "ld_preload_removed": ["/usr/local/lib/libnightcast.so"],
    "tapeops_unit_linger_gone": ["/home/tapeops/.config/systemd/user/"
                                 "tape-scan.service",
                                 "/var/lib/systemd/linger/tapeops"],
}


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_nakon():
    with open(NAKON, encoding="utf-8") as f:
        return json.load(f)


def _matcher(check):
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_static_pine_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, SCENARIO) == []
    checks = parsed["checks"]
    assert len(checks) == CHECK_COUNT
    assert len({check["id"] for check in checks}) == CHECK_COUNT
    vuln = [c for c in checks if c["category"] == "vuln"]
    penalty = [c for c in checks if c["category"] != "vuln"]
    assert sum(c["max_points"] for c in vuln) == VULN_POINTS
    assert len(penalty) == 2
    assert all(p["max_points"] == 10 for p in penalty)
    # persistence box: the discovery hunt IS the forensics test
    assert "forensics" not in parsed or not parsed["forensics"]

    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Static Pine Community Radio"
    assert manifest["theme"]["readme_text"].startswith("# Static Pine")
    assert manifest["theme"]["logo_b64"] is None
    # neither the signed manifest nor the rubric may carry authored solutions
    assert not any(c.get("solution") for c in manifest["checks"])
    rubric = json.load(open(outputs["rubric"], encoding="utf-8"))
    assert not any("solution" in json.dumps(e) for e in rubric.get("entries", []))


def test_static_pine_difficulty_tiers_match_points():
    """Display tier prefix, max_points, and expect.points must all agree;
    tier counts pin the compressed 8/5/3 ledger; penalties are negative."""
    tier_seen = {"EASY": 0, "MODERATE": 0, "HARD": 0}
    for check in _load_scenario()["checks"]:
        if check["category"] != "vuln":
            assert check["display"].startswith("PENALTY:"), (
                f"{check['id']}: non-vuln check must say PENALTY"
            )
            assert check["expect"]["points"] < 0
            assert check["type"] == "service_state", (
                f"{check['id']}: daemon-health penalties watch service_state"
            )
            continue
        match = re.match(r"^(EASY|MODERATE|HARD):", check["display"])
        assert match, f"{check['id']}: display must start with a tier prefix"
        tier = match.group(1)
        tier_seen[tier] += 1
        assert check["max_points"] == TIER_POINTS[tier], (
            f"{check['id']}: {tier} display but max_points={check['max_points']}"
        )
        assert check["expect"]["points"] == TIER_POINTS[tier]
    assert tier_seen == TIER_COUNTS, (
        f"tier distribution drifted: {tier_seen} != {TIER_COUNTS}"
    )


def test_static_pine_command_json_scripts_emit_valid_json():
    """Every command_json script is read-only and emits exactly one JSON
    scalar. Run each on a clean (unplanted) host: nothing this box plants
    exists here, so the hardened branch must be the natural outcome —
    every script should emit `true` without touching anything."""
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
        if check["category"] == "vuln":
            assert parsed is True, (
                f"{check['id']}: unplanted host should already be hardened"
            )


def test_static_pine_plant_vars_match_paired_checks():
    """The pairing discipline: every planted path/name in nakon.json vars
    must appear byte-identical in the paired check's collect params."""
    checks = {c["id"]: c for c in _load_scenario()["checks"]}
    nakon = _load_nakon()
    machines = nakon["machines"]
    assert len(machines) == 1
    cfgs = machines[0]["configurations"]
    assert len(cfgs) == 17  # 16 scored artifacts + tapeops the decoy account

    def var_entries(name):
        return [c["vars"] for c in cfgs
                if isinstance(c, dict) and c["name"] == name]

    cron_d = var_entries("cron-d-persistence")[0]
    crontabs = var_entries("crontab-persistence")
    bashrcs = var_entries("bashrc-persistence")
    users = var_entries("local-user")
    assert len(crontabs) == 2 and len(bashrcs) == 2 and len(users) == 2
    assert {v["USERNAME"] for v in crontabs} == {"root", "tapeops"}
    assert {v["TARGET_FILE"] for v in bashrcs} == {
        "/home/stationlead/.bashrc", "/etc/bash.bashrc"}
    assert {v["USERNAME"] for v in users} == {"wireman", "tapeops"}

    # payload paths: the cron.d entry pairs with its payload in the same vars
    assert cron_d["PAYLOAD_PATH"] in (
        checks["cron_sync_removed"]["collect"]["script"])

    # string couplings: substring must live in both nakon vars and the check
    # (collect for planted paths/commands, expect for planted accounts)
    blob_by_check = {}
    for cid, needles in COUPLINGS.items():
        check = checks[cid]
        blob_by_check[cid] = yaml.safe_dump(
            {"collect": check["collect"],
             "expect": {k: v for k, v in check["expect"].items()
                        if k != "points"}})
        for needle in needles:
            assert needle in blob_by_check[cid], (
                f"{cid}: scenario must reference {needle!r}"
            )

    def vars_blob(name):
        return json.dumps(var_entries(name))

    assert "/etc/cron.d/" + cron_d["CRON_FILE"] in blob_by_check["cron_sync_removed"]
    # root's crontab line: the job command IS the planted payload path
    root_cron = next(v for v in crontabs if v["USERNAME"] == "root")
    assert root_cron["JOB_COMMAND"] == root_cron["PAYLOAD_PATH"]
    assert root_cron["SCHEDULE"] == "@reboot"
    assert any(u["USERNAME"] == "wireman" for u in users)
    assert checks["rogue_account_removed"]["expect"]["username"] == "wireman"
    svc = var_entries("systemd-service")[0]
    assert svc["SERVICE_NAME"] + ".service" in blob_by_check["nightcast_service_removed"]
    assert svc["PAYLOAD_PATH"] in blob_by_check["nightcast_service_removed"]
    timer = var_entries("systemd-timer-persistence")[0]
    assert timer["TIMER_NAME"] + ".timer" in blob_by_check["timer_neutralized"]
    assert timer["PAYLOAD_PATH"] in blob_by_check["timer_neutralized"]
    initd = var_entries("initd-persistence")[0]
    assert initd["SCRIPT_NAME"] in blob_by_check["initd_boot_script_gone"]
    rcl = var_entries("rc-local-persistence")[0]
    assert rcl["RC_LINE"] in blob_by_check["rc_local_clean"]
    ld = var_entries("ld-preload-persistence")[0]
    assert ld["LIB_PATH"] in blob_by_check["ld_preload_removed"]
    tape_cron = next(v for v in crontabs if v["USERNAME"] == "tapeops")
    assert "tapeops" in blob_by_check["tapeops_crontab_cleared"]
    uunit = var_entries("systemd-user-unit-persistence")[0]
    assert uunit["UNIT_NAME"] + ".service" in blob_by_check["tapeops_unit_linger_gone"]
    assert uunit["USERNAME"] == "tapeops"
    keys = var_entries("authorized-keys-persistence")[0]
    assert keys["PUBLIC_KEY"].split()[-1] == "nightcast@88.3"
    assert "nightcast@88.3" in blob_by_check["authorized_keys_clean"]


def test_static_pine_pairings_score_secure_states_and_reject_planted_states():
    checks = {check["id"] for check in _load_scenario()["checks"]}
    assert checks == set(COUPLINGS) | {"cron_service_healthy",
                                       "atd_service_healthy"}

    by_id = {c["id"]: c for c in _load_scenario()["checks"]}

    # command_json boolean emission: true = hardened, false = planted
    for cid in COUPLINGS:
        check = by_id[cid]
        if check["type"] != "command_json":
            continue
        secure, reason = evaluate_matcher(
            _matcher(check), {"data": True, "text": "true"})
        assert secure, f"{cid}: {reason}"
        planted, reason = evaluate_matcher(
            _matcher(check), {"data": False, "text": "false"})
        assert not planted, f"{cid}: {reason}"

    # permission: gone from disk is the hardened state
    for cid in ("profile_d_gone", "motd_script_gone"):
        check = by_id[cid]
        assert check["type"] == "permission"
        secure, reason = evaluate_matcher(
            _matcher(check), {"exists": False, "mode": None})
        assert secure, reason
        planted, reason = evaluate_matcher(
            _matcher(check), {"exists": True, "mode": "0644"})
        assert not planted, reason

    # user_group: wireman absent is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(by_id["rogue_account_removed"]), {"users": ["stationlead"]})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(by_id["rogue_account_removed"]),
        {"users": ["stationlead", "wireman"]})
    assert not planted, reason

    # service_state penalties: daemon running keeps the board intact
    for cid in ("cron_service_healthy", "atd_service_healthy"):
        secure, reason = evaluate_matcher(
            _matcher(by_id[cid]), {"active": True, "enabled": True})
        assert secure, reason
        planted, reason = evaluate_matcher(
            _matcher(by_id[cid]), {"active": False, "enabled": False})
        assert not planted, reason


def test_static_pine_box_and_nakon_inputs_resolve():
    spec = load_spec(BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Static Pine Community Radio"

    nakon = _load_nakon()
    requested = nakon["machines"][0]["configurations"]
    names = [item if isinstance(item, str) else item["name"]
             for item in requested]
    for name in NEW_SEEDS + ["systemd-service", "local-user"]:
        assert name in names, f"{name} missing from nakon.json"


def test_static_pine_new_seeds_are_clean_and_generic():
    """Every new seed: required fields, shell-syntax-clean script, documented
    vars in the description, and (where present) a real ELF DSO embedded."""
    for name in NEW_SEEDS:
        seed = json.load(open(os.path.join(SEEDS, f"{name}.json"),
                              encoding="utf-8"))
        assert seed["name"] == name
        assert seed["platform"] == "linux"
        assert seed["category"] == "misconfiguration"
        assert seed["type"] == "command"
        assert seed["run_as"] == "root"
        assert "Vars:" in seed["description"], (
            f"{name}: seed must document its vars in the description"
        )
        # generic: no box-specific theme words baked into the seed itself
        assert "nightcast" not in seed["script"].lower()
        proc = subprocess.run(["sh", "-n", "-c", seed["script"]],
                              capture_output=True, text=True)
        assert proc.returncode == 0, (
            f"{name}: seed script fails sh -n: {proc.stderr}"
        )

    ld = json.load(open(os.path.join(SEEDS, "ld-preload-persistence.json"),
                        encoding="utf-8"))
    nakon_ld = next(c for c in _load_nakon()["machines"][0]["configurations"]
                    if isinstance(c, dict) and c["name"] == "ld-preload-persistence")
    blob = base64.b64decode(nakon_ld["vars"]["SO_B64"])
    assert blob.startswith(b"\x7fELF"), (
        "the planted preload object must be a real ELF DSO (a text file here "
        "would make every dynamic binary print ld.so errors on the box)"
    )
    # seed decodes whatever base64 it is given: exercise the round trip
    probe = base64.b64encode(blob).decode()
    assert probe == nakon_ld["vars"]["SO_B64"]
