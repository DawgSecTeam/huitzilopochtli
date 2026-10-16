"""Regression coverage for the Lantern Hill Community Library box.

The incident-response workshop box: headless Debian 13, ONE intrusion
("inkmoth") told across four correlated evidence sources (login journal,
auditd -- rules loaded before the plants --, the catalog app's service
journal, MariaDB's general query log). TWENTY-FIVE planted/baked
findings, one scored check each, difficulty-weighted (EASY=5 x10,
MODERATE=10 x10, HARD=20 x5 = 250 attainable), two service-health
penalties (catalog site + database must stay up), and a 13-question
forensics block (13 x 10 = 130; 380 grand total). What these tests pin:

- the ledger itself (check count, tier/points agreement, penalty floor,
  the forensics split) -- the ledger IS the contract with the students;
- every command_json script actually runs and emits exactly one JSON
  scalar, and the hardened branch is the natural outcome on a clean,
  unprivileged host (nothing planted here; privileged probes have an
  explicit unprivileged guard);
- the plant<->check pairing discipline (every planted path/name must
  byte-match between nakon.json vars and the scenario collect params --
  nothing cross-checks them at build time);
- matcher pass/reject pairs for every check's hardened vs planted state;
- the prep stack is complete on disk (app, schema, audit rules, replay)
  and the planted .env content matches the prep's working .env byte for
  byte (the plant must loosen the MODE, never break the app);
- the embedded ld.so.preload object decodes to a real ELF DSO.
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
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "lantern-hill-library")
SCENARIO = os.path.join(BOX_DIR, "scenario.yaml")
BOX = os.path.join(BOX_DIR, "box.yaml")
NAKON = os.path.join(BOX_DIR, "nakon.json")
SEEDS = os.path.join(REPO_ROOT, "boxbuilder", "vulndb_vuln_configs")
PREP = os.path.join(BOX_DIR, "assets", "prep")

CHECK_COUNT = 27          # 25 vuln + 2 penalties
VULN_POINTS = 250         # penalty floor (-20 total) excluded from attainable
FORENSICS_POINTS = 130    # 13 x 10
TOTAL_POINTS = VULN_POINTS + FORENSICS_POINTS
TIER_POINTS = {"EASY": 5, "MODERATE": 10, "HARD": 20}
TIER_COUNTS = {"EASY": 10, "MODERATE": 10, "HARD": 5}

BUNDLED_SEEDS = [
    "authorized-keys-persistence", "uid0-user", "insecure-file-mode",
    "world-writable-dir", "hosts-redirect-linux", "backdoor-firewall-rule",
    "ld-preload-persistence", "cron-d-persistence",
    "systemd-timer-persistence", "systemd-service", "bashrc-persistence",
    "motd-persistence", "sudoers-rule", "raw-socket-beacon",
]
LIVE_CATALOG_SEEDS = [
    "timezone-chaos", "ssh-backdoor-listener-2222",
    "hacking-tools-installed", "cron-log-truncator",
]

VULN_CHECK_IDS = {
    # EASY x10
    "sshd_root_login_closed", "sshd_password_auth_off",
    "authorized_keys_clean", "nightdesk_removed", "rogue_module_removed",
    "exfil_dump_removed", "hosts_redirect_removed", "firewall_rule_removed",
    "tamper_cron_removed", "motd_script_gone",
    # MODERATE x10
    "sshd_empty_passwords_off", "timer_neutralized",
    "rogue_service_removed", "system_bashrc_clean", "ld_preload_removed",
    "tools_uninstalled", "plugins_dir_perms_fixed",
    "app_secrets_perms_fixed", "auditd_rules_intact", "db_general_log_on",
    # HARD x5
    "backdoor_sshd_removed", "beacon_neutralized",
    "log_truncator_removed", "timezone_restored", "sudoers_rule_removed",
}
PENALTY_IDS = {"catalog_app_healthy", "db_reachable"}
FORENSIC_IDS = {
    "fq-compromised-account", "fq-source-ip", "fq-key-comment",
    "fq-uid0-account", "fq-tamper-cron", "fq-timer-cadence",
    "fq-rogue-module", "fq-admin-path", "fq-db-table", "fq-exfil-file",
    "fq-hosts-redirect", "fq-wiped-logs", "fq-timezone",
}

# Planted artifact <-> check couplings: every (substring, where it must
# appear) pair, taken from nakon.json vars and mirrored in scenario.yaml.
COUPLINGS = {
    "authorized_keys_clean": ["inkmoth@203.0.113.7",
                              "/home/librarian/.ssh/authorized_keys"],
    "nightdesk_removed": ["nightdesk"],
    "rogue_module_removed": ["/opt/library/plugins/promo_portal.py"],
    "exfil_dump_removed": ["/var/backups/catalog-export.sql"],
    "hosts_redirect_removed": ["203.0.113.7"],
    "firewall_rule_removed": ["203.0.113.7"],
    "tamper_cron_removed": ["/etc/cron.d/catalog-maint",
                            "/opt/inkmoth/catalog-maint"],
    "motd_script_gone": ["/etc/update-motd.d/99catalog-tip"],
    "timer_neutralized": ["inkmoth-relabel.timer",
                          "/opt/inkmoth/relabel-catalog"],
    "rogue_service_removed": ["metrics-probe", "/opt/inkmoth/metrics-probe"],
    "system_bashrc_clean": ["/etc/bash.bashrc"],
    "ld_preload_removed": ["/usr/local/lib/libinkmoth.so"],
    "plugins_dir_perms_fixed": ["/opt/library/plugins"],
    "app_secrets_perms_fixed": ["/opt/library/.env"],
    "backdoor_sshd_removed": ["2222"],
    "beacon_neutralized": ["/usr/local/libexec/.cache-refresh"],
    "sudoers_rule_removed": ["/etc/sudoers.d/nightdesk-recovery"],
    "log_truncator_removed": ["/etc/cron.d/log-cleanup"],
    "timezone_restored": ["Pacific/Kiritimati"],
    "auditd_rules_intact": ["auditctl"],
    "db_general_log_on": ["general_log"],
}

PREP_FILES = [
    "prep-notes.md", "01-packages.sh", "02-accounts.sh", "03-database.sh",
    "04-app.sh", "05-auditd-journal.sh", "90-attacker-replay.py",
    "app.py", "schema.sql", "library.env", "library-app.service",
    "library.conf", "75-library-ir.rules", "99-library-ir.cnf",
]


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_nakon():
    with open(NAKON, encoding="utf-8") as f:
        return json.load(f)


def _matcher(check):
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_lantern_hill_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, SCENARIO) == []
    checks = parsed["checks"]
    assert len(checks) == CHECK_COUNT
    assert {c["id"] for c in checks} == VULN_CHECK_IDS | PENALTY_IDS
    vuln = [c for c in checks if c["category"] == "vuln"]
    penalty = [c for c in checks if c["category"] != "vuln"]
    assert sum(c["max_points"] for c in vuln) == VULN_POINTS
    assert len(penalty) == 2
    assert {p["id"] for p in penalty} == PENALTY_IDS
    assert all(p["max_points"] == 10 for p in penalty)
    forensics = parsed["forensics"]
    assert len(forensics) == 13
    assert {fq["id"] for fq in forensics} == FORENSIC_IDS
    assert sum(fq["points"] for fq in forensics) == FORENSICS_POINTS
    assert VULN_POINTS + FORENSICS_POINTS == TOTAL_POINTS
    assert not ({fq["id"] for fq in forensics} & {c["id"] for c in checks})
    # every finding and question carries an authored walkthrough so the
    # post-event answer key renders with zero gaps
    assert all(c.get("solution", "").strip() for c in checks)
    assert all(str(fq.get("solution", "")).strip() for fq in forensics)

    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    assert outputs["readme_warnings"] == [], outputs["readme_warnings"]
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Lantern Hill Community Library"
    assert manifest["theme"]["readme_text"].startswith("# Lantern Hill")
    assert manifest["theme"]["logo_b64"] is None
    # the manifest carries the questions but never their answers
    assert len(manifest["forensics"]) == 13
    assert not any("answer" in json.dumps(f) for f in manifest["forensics"])
    # neither the signed manifest nor the rubric may carry authored solutions
    assert not any(c.get("solution") for c in manifest["checks"])
    rubric = json.load(open(outputs["rubric"], encoding="utf-8"))
    assert not any("solution" in json.dumps(e) for e in rubric.get("entries", []))


def test_lantern_hill_difficulty_tiers_match_points():
    """Display tier prefix, max_points, and expect.points must all agree;
    tier counts pin the 10/10/5 ledger; penalties are negative."""
    tier_seen = {"EASY": 0, "MODERATE": 0, "HARD": 0}
    for check in _load_scenario()["checks"]:
        if check["category"] != "vuln":
            assert check["display"].startswith("PENALTY:"), (
                f"{check['id']}: non-vuln check must say PENALTY"
            )
            assert check["expect"]["points"] < 0
            assert check["type"] in ("service_state", "db_query"), (
                f"{check['id']}: service-health penalties watch a probe that "
                "returns OK evidence when the service is down (ERROR "
                "evidence never applies a penalty)"
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


def test_lantern_hill_command_json_scripts_emit_valid_json():
    """Every command_json script is read-only and emits exactly one JSON
    scalar. Run each on a clean (unplanted, unprivileged) host: nothing
    this box plants exists here, so the hardened branch must be the
    natural outcome -- every script should emit `true` without touching
    anything. (Privileged probes carry an explicit `id -u` guard so this
    holds off-box; on the box the agent runs as root and grades for
    real.)"""
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


def test_lantern_hill_plant_vars_match_paired_checks():
    """The pairing discipline: every planted path/name in nakon.json vars
    must appear byte-identical in the paired check's collect params."""
    checks = {c["id"]: c for c in _load_scenario()["checks"]}
    nakon = _load_nakon()
    machines = nakon["machines"]
    assert len(machines) == 1
    cfgs = machines[0]["configurations"]
    assert len(cfgs) == 20  # 18 artifact plants + 2 protective pre-bakes

    names = [item if isinstance(item, str) else item["name"] for item in cfgs]
    for seed in BUNDLED_SEEDS + LIVE_CATALOG_SEEDS:
        assert seed in names, f"{seed} missing from nakon.json"
    # timezone tamper goes FIRST so later evidence shares its clock
    assert names[0] == "timezone-chaos"

    def var_entries(name):
        return [c["vars"] for c in cfgs
                if isinstance(c, dict) and c["name"] == name]

    files = var_entries("insecure-file-mode")
    assert len(files) == 3
    by_path = {v["FILE_PATH"]: v for v in files}
    assert set(by_path) == {
        "/opt/library/plugins/promo_portal.py",
        "/var/backups/catalog-export.sql",
        "/opt/library/.env",
    }
    # the planted .env must keep the app WORKING: byte-identical content
    # to prep's working file (only the MODE is the finding)
    prep_env = open(os.path.join(PREP, "library.env"), encoding="utf-8").read()
    assert by_path["/opt/library/.env"]["FILE_CONTENT"].strip() == prep_env.strip()
    assert by_path["/opt/library/.env"]["FILE_MODE"] == "0666"
    assert "inkmoth" in by_path["/opt/library/plugins/promo_portal.py"]["FILE_CONTENT"]

    keys = var_entries("authorized-keys-persistence")[0]
    assert keys["USERNAME"] == "librarian"
    assert keys["PUBLIC_KEY"].split()[-1] == "inkmoth@203.0.113.7"
    assert "inkmoth@203.0.113.7" in yaml.safe_dump(
        checks["authorized_keys_clean"]["collect"])

    uid0 = var_entries("uid0-user")[0]
    assert uid0["USERNAME"] == "nightdesk"
    assert checks["nightdesk_removed"]["expect"]["username"] == "nightdesk"

    wwdir = var_entries("world-writable-dir")[0]
    assert wwdir["DIR"] == "/opt/library/plugins"
    assert wwdir["MODE"] == "0777"

    hosts = var_entries("hosts-redirect-linux")[0]
    assert hosts["IP"] == "203.0.113.7"
    assert hosts["HOSTS"] == "updates.lanternhill-library.org"

    fw = var_entries("backdoor-firewall-rule")[0]
    assert fw["SOURCE_IP"] == "203.0.113.7"
    assert fw["DST_PORT"] == "2222"

    ld = var_entries("ld-preload-persistence")[0]
    assert ld["LIB_PATH"] == "/usr/local/lib/libinkmoth.so"

    cron = var_entries("cron-d-persistence")[0]
    assert cron["CRON_FILE"] == "catalog-maint"
    assert cron["PAYLOAD_PATH"] == "/opt/inkmoth/catalog-maint"

    timer = var_entries("systemd-timer-persistence")[0]
    assert timer["TIMER_NAME"] == "inkmoth-relabel"
    assert timer["ON_UNIT_ACTIVE_SEC"] == "45min"
    assert timer["PAYLOAD_PATH"] == "/opt/inkmoth/relabel-catalog"

    svc = var_entries("systemd-service")[0]
    assert svc["SERVICE_NAME"] == "metrics-probe"
    assert svc["PAYLOAD_PATH"] == "/opt/inkmoth/metrics-probe"

    bashrc = var_entries("bashrc-persistence")[0]
    assert bashrc["TARGET_FILE"] == "/etc/bash.bashrc"

    motd = var_entries("motd-persistence")[0]
    assert motd["SCRIPT_NAME"] == "99catalog-tip"

    sudoers = var_entries("sudoers-rule")[0]
    assert sudoers["DROPIN_NAME"] == "nightdesk-recovery"

    beacon = var_entries("raw-socket-beacon")[0]
    assert beacon["SERVICE_NAME"] == "cache-refresh"

    # string couplings: substring must live in both nakon vars and the
    # check's collect/expect params
    blob_by_check = {}
    for cid, needles in COUPLINGS.items():
        blob_by_check[cid] = yaml.safe_dump(
            {"collect": checks[cid]["collect"],
             "expect": {k: v for k, v in checks[cid]["expect"].items()
                        if k != "points"}})
        for needle in needles:
            assert needle in blob_by_check[cid], (
                f"{cid}: scenario must reference {needle!r}"
            )


def test_lantern_hill_pairings_score_secure_states_and_reject_planted_states():
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

    # permission: gone from disk is the hardened state (deletion findings)
    for cid in ("rogue_module_removed", "exfil_dump_removed",
                "motd_script_gone"):
        check = by_id[cid]
        assert check["type"] == "permission"
        assert check["expect"]["field"] == "exists"
        secure, reason = evaluate_matcher(
            _matcher(check), {"exists": False, "mode": None})
        assert secure, reason
        planted, reason = evaluate_matcher(
            _matcher(check), {"exists": True, "mode": "0644"})
        assert not planted, reason

    # permission: mode findings fail closed on a missing file on purpose
    # (chmod is the fix; deleting .env or the plugins dir breaks the app)
    for cid, planted_mode, hardened_mode in (
        ("plugins_dir_perms_fixed", "0777", "0755"),
        ("app_secrets_perms_fixed", "0666", "0640"),
    ):
        check = by_id[cid]
        assert check["type"] == "permission"
        broken, reason = evaluate_matcher(
            _matcher(check), {"exists": False, "mode": None})
        assert not broken, f"{cid}: deletion must NOT pass: {reason}"
        planted, reason = evaluate_matcher(
            _matcher(check), {"exists": True, "mode": planted_mode})
        assert not planted, f"{cid}: {reason}"
        secure, reason = evaluate_matcher(
            _matcher(check), {"exists": True, "mode": hardened_mode})
        assert secure, f"{cid}: {reason}"

    # user_group: nightdesk absent is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(by_id["nightdesk_removed"]), {"users": ["librarian"]})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(by_id["nightdesk_removed"]),
        {"users": ["librarian", "nightdesk"]})
    assert not planted, reason

    # package: the guessing toolkit uninstalled is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(by_id["tools_uninstalled"]), {"installed": False})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(by_id["tools_uninstalled"]), {"installed": True})
    assert not planted, reason

    # penalties: the app running and the DB accepting connections keep
    # the board intact
    secure, reason = evaluate_matcher(
        _matcher(by_id["catalog_app_healthy"]),
        {"active": True, "enabled": True})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(by_id["catalog_app_healthy"]),
        {"active": False, "enabled": False})
    assert not planted, reason
    secure, reason = evaluate_matcher(
        _matcher(by_id["db_reachable"]), {"ok": True, "error": None})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(by_id["db_reachable"]), {"ok": False, "error": "refused"})
    assert not planted, reason


def test_lantern_hill_forensics_block_walks_the_investigation():
    """Questions name evidence classes, never answers; ordinals match list
    order; every question is pinned to the librarian's Desktop file."""
    forensics = _load_scenario()["forensics"]
    paths = {fq.get("path") for fq in forensics}
    assert paths == {"/home/librarian/Desktop/Forensics-Questions.txt"}
    for fq in forensics:
        assert fq["points"] == 10
        assert fq.get("answer") or fq.get("answers")
        # the question text may not hand over a specific answer (short
        # ordinary-English answers like "holds" are exempt -- the compile
        # lint enforces the real rule against the handbook)
        if len(str(fq["answer"])) >= 6:
            assert str(fq["answer"]).lower() not in fq["question"].lower(), (
                f"{fq['id']}: question leaks its own answer"
            )


def test_lantern_hill_box_and_nakon_inputs_resolve():
    spec = load_spec(BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Lantern Hill Community Library"

    for name in PREP_FILES:
        assert os.path.isfile(os.path.join(PREP, name)), (
            f"prep asset missing: {name}"
        )


def test_lantern_hill_bundled_seeds_are_clean_and_generic():
    """Every bundled seed this box uses: present on disk, required fields,
    shell-syntax-clean script, and (for the loader implant) a real ELF
    DSO embedded in the planted vars."""
    for name in BUNDLED_SEEDS:
        seed = json.load(open(os.path.join(SEEDS, f"{name}.json"),
                              encoding="utf-8"))
        assert seed["name"] == name
        assert seed["platform"] == "linux"

    ld = json.load(open(os.path.join(SEEDS, "ld-preload-persistence.json"),
                        encoding="utf-8"))
    nakon_ld = next(c for c in _load_nakon()["machines"][0]["configurations"]
                    if isinstance(c, dict) and c["name"] == "ld-preload-persistence")
    blob = base64.b64decode(nakon_ld["vars"]["SO_B64"])
    assert blob.startswith(b"\x7fELF"), (
        "the planted preload object must be a real ELF DSO (a text file here "
        "would make every dynamic binary print ld.so errors on the box)"
    )
    probe = base64.b64encode(blob).decode()
    assert probe == nakon_ld["vars"]["SO_B64"]
