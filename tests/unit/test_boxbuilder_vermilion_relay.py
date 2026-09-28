"""Regression coverage for the Vermilion Deep-Space Relay box.

The pre-CDE capstone: a GUI Xubuntu box that pulls together the whole Linux
vulnerability universe from the earlier boxes plus new categories, into EIGHTY
scored hardening findings (weighting EASY=2 x33, MODERATE=4 x35, HARD=8 x12 =
302 attainable), three daemon/access penalty guards (cron, atd, ssh), and an
eight-question forensics block whose answers are breadcrumbs to specific
findings (8 x 8 = 64; 366 grand total).

What these tests pin down:
- the ledger itself (check count, tier<->points agreement, the tier
  distribution, the penalty floor, the forensics split) — the ledger IS the
  contract with the students, and the README quotes it;
- every command_json script is shell-syntax-clean and, when it runs, emits a
  single JSON document carrying the field its matcher reads;
- the plant<->check pairing discipline (critical planted paths/names/ports in
  nakon.json must byte-match the paired scenario collect params / forensics
  answers — nothing cross-checks them at build time);
- solutions never leak into the signed manifest or the rubric, and no forensics
  answer leaks into the in-box README;
- the new nakon seeds are shell-syntax-clean, and the reused ld.so.preload
  object still decodes to a real ELF DSO.
"""
import base64
import json
import os
import re
import subprocess

import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from common.crypto import signing


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "vermilion-relay")
SCENARIO = os.path.join(BOX_DIR, "scenario.yaml")
NAKON = os.path.join(BOX_DIR, "nakon.json")
README = os.path.join(BOX_DIR, "assets", "README.md")
SEEDS = os.path.join(REPO_ROOT, "boxbuilder", "vulndb_vuln_configs")

VULN_COUNT = 80
PENALTY_COUNT = 3
FORENSICS_COUNT = 8
TIER_POINTS = {"EASY": 2, "MODERATE": 4, "HARD": 8}
TIER_COUNTS = {"EASY": 33, "MODERATE": 35, "HARD": 12}
VULN_POINTS = 302
FORENSICS_POINTS = 64

NEW_SEEDS = [
    "weak-login-defs", "dup-uid", "sudoers-rule", "sshd-config-weak",
    "world-writable-dir", "suid-binary", "file-capability", "chown-file",
    "sysctl-insecure", "ufw-insecure", "hosts-redirect-linux",
    "apt-service-install", "vsftpd-anonymous", "samba-guest-share",
    "nfs-no-root-squash", "apache-insecure", "web-exposed-file",
    "mysql-anon-user", "desktop-autostart", "rhosts-trust",
]

# Scripts that scan large real directories on the dev host (fine on the small
# box). Syntax-check them, but do not execute them here.
HEAVY_SCAN = {"no_suid_backdoor", "no_setuid_capability"}


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_nakon():
    with open(NAKON, encoding="utf-8") as f:
        return json.load(f)


def test_vermilion_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, SCENARIO) == []
    checks = parsed["checks"]
    vuln = [c for c in checks if c["category"] == "vuln"]
    penalty = [c for c in checks if c["category"] == "penalty"]
    assert len(vuln) == VULN_COUNT
    assert len(penalty) == PENALTY_COUNT
    assert len({c["id"] for c in checks}) == len(checks)
    assert sum(c["max_points"] for c in vuln) == VULN_POINTS
    for p in penalty:
        assert p["display"].startswith("PENALTY:")
        assert p["expect"]["points"] == -10
        assert p["type"] in ("service_state", "db_query")

    forensics = parsed["forensics"]
    assert len(forensics) == FORENSICS_COUNT
    assert all(fq["points"] == 8 for fq in forensics)
    assert sum(fq["points"] for fq in forensics) == FORENSICS_POINTS
    assert not ({fq["id"] for fq in forensics} & {c["id"] for c in checks})

    # every check and every forensics question ships an authored solution
    assert all(c.get("solution", "").strip() for c in checks)
    assert all(fq.get("solution", "").strip() for fq in forensics)

    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Vermilion Deep-Space Relay"
    assert manifest["theme"]["readme_text"].startswith("# Vermilion")
    # solutions must never reach the box: not in the signed manifest, not the rubric
    assert not any(c.get("solution") for c in manifest["checks"])
    rubric = json.load(open(outputs["rubric"], encoding="utf-8"))
    assert "solution" not in json.dumps(rubric)


def test_vermilion_difficulty_tiers_match_points():
    tier_seen = {"EASY": 0, "MODERATE": 0, "HARD": 0}
    for check in _load_scenario()["checks"]:
        if check["category"] == "penalty":
            continue
        m = re.match(r"^(EASY|MODERATE|HARD):", check["display"])
        assert m, f"{check['id']}: display must start with a tier prefix"
        tier = m.group(1)
        tier_seen[tier] += 1
        assert check["max_points"] == TIER_POINTS[tier], check["id"]
        assert check["expect"]["points"] == TIER_POINTS[tier], check["id"]
    assert tier_seen == TIER_COUNTS, f"tier drift: {tier_seen} != {TIER_COUNTS}"


def test_vermilion_command_json_scripts_emit_field_json():
    """Every command_json script is shell-clean and, when run, emits one JSON
    document that carries the field its matcher reads (a bare true/false maps
    to the 'data' field; an object must contain the named key)."""
    for check in _load_scenario()["checks"]:
        if check["type"] != "command_json":
            continue
        script = check["collect"]["script"]
        syn = subprocess.run(["/bin/sh", "-n"], input=script,
                             text=True, capture_output=True)
        assert syn.returncode == 0, f"{check['id']}: shell syntax: {syn.stderr}"
        field = check["expect"].get("field", "data")
        if check["id"] in HEAVY_SCAN:
            continue
        try:
            proc = subprocess.run(["/bin/bash", "-c", script],
                                  capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            continue
        out = proc.stdout.strip()
        assert out, f"{check['id']}: script produced no stdout"
        parsed = json.loads(out)  # raises if the script broke its JSON contract
        if isinstance(parsed, dict):
            assert field in parsed, f"{check['id']}: missing field {field!r}"
        else:
            assert field == "data", f"{check['id']}: scalar output but field={field!r}"


def test_vermilion_plant_coupling_and_forensics_breadcrumbs():
    """Critical planted values in nakon.json must match, byte-for-byte, the
    paired scenario collect params and the forensics answers they lead to."""
    scenario = _load_scenario()
    checks = {c["id"]: c for c in scenario["checks"]}
    fq = {f["id"]: f for f in scenario["forensics"]}
    cfgs = _load_nakon()["machines"][0]["configurations"]

    def vars_of(name, **match):
        out = []
        for c in cfgs:
            if isinstance(c, dict) and c["name"] == name:
                if all(c["vars"].get(k) == v for k, v in match.items()):
                    out.append(c["vars"])
        return out

    # beacon: BEACON_PATH couples the process/permission checks and the C2 is Q2
    beacon = vars_of("raw-socket-beacon")[0]
    assert beacon["BEACON_PATH"] == "/opt/telemetry-uplink/uplink-relayd"
    assert beacon["BEACON_PATH"] in checks["beacon_process_gone"]["collect"]["pattern"]
    assert checks["beacon_binary_removed"]["collect"]["path"] == beacon["BEACON_PATH"]
    assert fq["fq-beacon-destination"]["answer"] == "203.0.113.66:8443"

    # suid backdoor: DEST is the forensics Q5 answer
    suid = vars_of("suid-binary")[0]
    assert suid["DEST"] == "/usr/local/bin/relay-diag"
    assert fq["fq-suid-backdoor"]["answer"] == suid["DEST"]

    # persistence timer: TIMER_NAME.timer is forensics Q6
    resync = vars_of("systemd-timer-persistence", TIMER_NAME="relay-resync")[0]
    assert fq["fq-persistence-timer"]["answer"] == resync["TIMER_NAME"] + ".timer"
    assert resync["TIMER_NAME"] in checks["persistence_timer_gone"]["collect"]["script"]

    # ld.so.preload lib path is forensics Q7 and appears in the check script
    ldp = vars_of("ld-preload-persistence")[0]
    assert ldp["LIB_PATH"] == "/opt/void/libvoidhook.so"
    assert fq["fq-ldpreload-lib"]["answer"] == ldp["LIB_PATH"]
    assert "libvoidhook" in checks["ld_preload_gone"]["collect"]["script"]

    # /etc/hosts redirect IP is forensics Q8 and the redirected host is checked
    hosts = vars_of("hosts-redirect-linux")[0]
    assert fq["fq-hosts-redirect"]["answer"] == hosts["IP"] == "10.66.6.6"
    assert "security.ubuntu.com" in hosts["HOSTS"]
    hosts_script = checks["hosts_no_redirect"]["collect"]["script"]
    assert "security" in hosts_script and "ubuntu" in hosts_script

    # hidden root (uid0) name is forensics Q1 and removable via user_absent-style check
    uid0 = vars_of("uid0-user")[0]
    assert uid0["USERNAME"] == "nightwatch" == fq["fq-hidden-root"]["answer"]

    # sudo-group account is forensics Q3, and it is the user_group finding + subset guard
    vega = vars_of("local-user", USERNAME="vega")[0]
    assert vega.get("GROUPS_ADD") == "sudo"
    assert fq["fq-sudo-account"]["answer"] == "vega"
    assert checks["no_vega"]["expect"]["username"] == "vega"
    assert checks["sudo_group_clean"]["expect"]["allowed"] == ["relayadmin"]

    # bind shell port (catalog ncat row) is forensics Q4 and checked on 4444
    assert "ncat-listener-autostart" in [c for c in cfgs if isinstance(c, str)]
    assert fq["fq-bind-shell-port"]["answer"] == "4444"
    assert ":4444" in checks["bind_shell_removed"]["collect"]["script"]

    # ordering invariant: /etc/shadow and /etc/passwd loosening runs after every
    # account/shell plant (useradd/usermod reset those modes on the way out)
    names = [c["name"] if isinstance(c, dict) else c for c in cfgs]
    acct_seeds = {"user-login-shell", "uid0-user", "local-user", "dup-uid"}
    last_acct = max(i for i, n in enumerate(names) if n in acct_seeds)
    shadow_idx = [i for i, c in enumerate(cfgs)
                  if isinstance(c, dict) and c["name"] == "loosen-file-mode"
                  and c["vars"]["FILE_PATH"] in ("/etc/shadow", "/etc/passwd")]
    assert shadow_idx and min(shadow_idx) > last_acct


def test_vermilion_readme_hides_forensics_answers():
    """The in-box handbook is the assignment, not the answer key: no forensics
    answer (>= 4 chars) may appear verbatim in the README."""
    readme = open(README, encoding="utf-8").read()
    for f in _load_scenario()["forensics"]:
        ans = f["answer"]
        if len(ans) >= 4:
            assert ans not in readme, f"README leaks forensics answer {ans!r}"


def test_vermilion_new_seeds_present_and_shell_clean():
    for name in NEW_SEEDS:
        path = os.path.join(SEEDS, name + ".json")
        assert os.path.isfile(path), f"missing new seed {name}"
        seed = json.load(open(path, encoding="utf-8"))
        assert seed["run_as"] == "root"
        syn = subprocess.run(["/bin/sh", "-n"], input=seed["script"],
                             text=True, capture_output=True)
        assert syn.returncode == 0, f"{name}: shell syntax: {syn.stderr}"


def test_vermilion_ld_preload_object_is_a_real_elf():
    cfgs = _load_nakon()["machines"][0]["configurations"]
    ldp = next(c["vars"] for c in cfgs
               if isinstance(c, dict) and c["name"] == "ld-preload-persistence")
    blob = base64.b64decode(ldp["SO_B64"])
    assert blob[:4] == b"\x7fELF", "ld.so.preload object must be a real ELF DSO"
