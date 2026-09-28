"""Regression coverage for the Harborline Transit Authority box.

The pre-CDE capstone WINDOWS box (the Windows twin of vermilion-relay): a
single-DC box that consolidates the whole Windows vulnerability universe
from pinecrest-hospital (local hardening) and meridian-hq (AD) plus new
categories, into EIGHTY scored hardening findings (weighting EASY=2 x33,
MODERATE=4 x35, HARD=8 x12 = 302 attainable), three penalty guards (staff
roster, payroll evidence, DNS service), and an eight-question forensics
block whose answers are breadcrumbs to specific findings (8 x 8 = 64; 366
grand total).

What these tests pin down:
- the ledger itself (check count, tier<->points agreement, the tier
  distribution, the penalty floor, the forensics split) — the ledger IS the
  contract with the students, and the README quotes it;
- every powershell_json script follows the nakon rc-trailer discipline (no
  SilentlyContinue) and emits JSON the way its matcher reads it;
- the plant<->check pairing discipline (critical planted paths/names/IPs in
  nakon.json must byte-match the paired scenario collect params / forensics
  answers — nothing cross-checks them at build time);
- plant ordering (weak policy first; accounts before group-adds/ACLs; the
  hosts redirect last);
- solutions never leak into the signed manifest or the rubric, no forensics
  answer leaks into the in-box README, and the investigate-it answers appear
  in no check body at all;
- the new nakon seeds are valid generic Windows configs.
"""
import json
import os
import re

import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from common.crypto import signing

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "harborline-transit")
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
    "defender-off-win", "ps-logging-off-win", "wdigest-cleartext-win",
    "lsa-ppl-off-win", "ntlm-downgrade-win", "anonymous-enumeration-win",
    "ifeo-backdoor-win", "winlogon-shell-win",
    "wmi-subscription-persistence-win", "startup-folder-item-win",
    "ad-blank-password-win", "always-install-elevated-win",
    "uac-toggles-off-win",
]

# The purest investigate-it answers: planted names that must appear in NO
# check display AND no check body (the checks that pair with them are
# sweeps -- meridian's svc_legacy precedent). fq_ifeo_executable's answer
# ("sethc.exe") is exempt: the check and the question both point at the IFEO
# keys by name, so the executable is discoverable from the check itself.
PUREST_ANSWERS = {"helpdesk$", "qa_kiosk", "svc_turnstile"}


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_nakon():
    with open(NAKON, encoding="utf-8") as f:
        return json.load(f)


def test_harborline_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, source_path=SCENARIO) == []
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
        assert p["max_points"] == 10

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
    assert manifest["theme"]["title"] == "Harborline Transit Authority"
    assert manifest["theme"]["readme_text"].startswith("# Harborline")
    # solutions must never reach the box: not in the signed manifest, not the rubric
    assert not any(c.get("solution") for c in manifest["checks"])
    rubric = json.load(open(outputs["rubric"], encoding="utf-8"))
    assert "solution" not in json.dumps(rubric)


def test_harborline_difficulty_tiers_match_points():
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


def test_harborline_powershell_scripts_follow_collect_contract():
    """powershell_json scripts must be non-empty, emit JSON (ConvertTo-Json),
    and honor the rc-trailer discipline (no SilentlyContinue -- a probe that
    misses must not pollute $Error, the pinecrest five-round lesson)."""
    for check in _load_scenario()["checks"]:
        if check["type"] != "powershell_json":
            continue
        script = check["collect"]["script"]
        assert script.strip(), check["id"]
        assert "SilentlyContinue" not in script, check["id"]
        assert "ConvertTo-Json" in script, check["id"]
        assert check["expect"].get("field", "data") == "data", check["id"]
    for check in _load_scenario()["checks"]:
        if check["type"] == "registry_value":
            assert {"hive", "key", "value"} <= set(check["collect"]), check["id"]
        if check["type"] in ("permission",):
            assert "path" in check["collect"], check["id"]
        if check["type"] == "file_regex":
            assert "extract" in check["collect"], check["id"]


def test_harborline_plant_coupling_and_forensics_breadcrumbs():
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

    def script_of(cid):
        return checks[cid]["collect"]["script"]

    # --- AD accounts ---------------------------------------------------------
    hidden = vars_of("ad-user-win", USERNAME="helpdesk$")[0]
    assert hidden["NEVER_EXPIRES"] == "1"
    assert fq["fq_hidden_dollar_account"]["answer"] == "helpdesk$"

    kiosk = vars_of("ad-blank-password-win", USERNAME="qa_kiosk")[0]
    assert kiosk["FULLNAME"] == "Fare Gate QA Kiosk"
    assert fq["fq_no_password_account"]["answer"] == "qa_kiosk"

    turnstile = vars_of("ad-user-win", USERNAME="svc_turnstile")[0]
    assert turnstile["NO_PREAUTH"] == "1" and turnstile["DES_ONLY"] == "1"
    assert fq["fq_asrep_user"]["answer"] == "svc_turnstile"

    sched = vars_of("ad-user-win", USERNAME="svc_sched")[0]
    assert sched["SPN"] == "HTTP/har-dc01.harborline.local"
    assert fq["fq_gpp_password"]["answer"] == "FareKiosk2026!"
    assert "'svc_sched'" in script_of("svc_sched_password_rotated")
    assert "'SchedSpring2026!'" in script_of("svc_sched_password_rotated")
    assert "harborline.local" in script_of("svc_sched_password_rotated")
    # DC boot window: the rotation check must gate on uptime (fake-pass guard)
    assert "LastBootUpTime" in script_of("svc_sched_password_rotated")
    assert "8" in script_of("svc_sched_password_rotated")

    repl = vars_of("ad-acl-dcsync-win")[0]
    assert repl["TRUSTEE"] == "svc_repl"
    assert "'svc_repl'" in script_of("dcsync_rights_revoked")

    assert vars_of("ad-user-win", USERNAME="bprieto")
    assert "'bprieto'" in script_of("bprieto_disabled")
    assert vars_of("ad-user-win", USERNAME="lhaight")
    assert "'lhaight'" in script_of("lhaight_disabled")
    group_adds = [e for e in cfgs
                  if isinstance(e, dict) and e.get("name") == "ad-group-member-win"]
    assert {e["vars"]["USERNAME"] for e in group_adds} == {"bprieto", "lhaight"}
    assert {e["vars"]["GROUP"] for e in group_adds} == {
        "Domain Admins", "Account Operators", "Remote Desktop Users", "DNSAdmins"}

    assert vars_of("ad-delegation-win")[0]["ACCOUNT"] == "FAREGW01"
    assert '"FAREGW01"' in script_of("faregw_delegation_cleared")
    assert vars_of("ad-computer-win")[0]["COMPUTER_NAME"] == "WS-OLD2301"
    assert '"WS-OLD2301"' in script_of("stale_computer_disabled")

    # --- GPO / GPP -----------------------------------------------------------
    gpo = vars_of("gpo-persistence-win")[0]
    assert gpo["GPO_NAME"] == "TransitPulse"
    assert gpo["RUN_VALUE_NAME"] == "EdgeUpdateOrchestrator"
    assert "'TransitPulse'" in script_of("gpo_persistence_removed")
    assert "'EdgeUpdateOrchestrator'" in script_of("gpo_persistence_removed")
    gpp = vars_of("gpp-cpassword-win")[0]
    assert gpp["GPO_NAME"] == "Deploy Fare Kiosk"
    assert gpp["PASSWORD"] == fq["fq_gpp_password"]["answer"]

    # --- firewall ------------------------------------------------------------
    rule = vars_of("firewall-allow-rule-win", RULE_NAME="TransitSync")[0]
    assert rule["LOCAL_PORT"] == "9001"
    assert "'TransitSync'" in script_of("backdoor_rule_removed")
    rule2 = vars_of("firewall-allow-rule-win", RULE_NAME="FleetCommand")[0]
    assert rule2["LOCAL_PORT"] == "4444"
    assert "'FleetCommand'" in script_of("backdoor_rule2_removed")

    # --- persistence: run keys, tasks, services -------------------------------
    pulse = vars_of("runkey-persistence-win", RUN_VALUE_NAME="FleetPulseCore")[0]
    assert checks["runkey_pulse_removed"]["collect"]["value"] == "FleetPulseCore"
    assert checks["runkey_pulse_payload_gone"]["collect"]["path"] == pulse["PAYLOAD_PATH"]
    widget = vars_of("runkey-persistence-win", RUN_VALUE_NAME="RelayStatusWidget")[0]
    assert checks["runkey_widget_removed"]["collect"]["value"] == "RelayStatusWidget"
    assert checks["runkey_widget_payload_gone"]["collect"]["path"] == widget["PAYLOAD_PATH"]

    task1 = vars_of("scheduled-task-persistence-win", TASK_NAME="ChromeUpdateCore")[0]
    assert "ChromeUpdateCore" in script_of("rogue_task_removed")
    assert checks["task_payload_removed"]["collect"]["path"] == task1["PAYLOAD_PATH"]
    task2 = vars_of("scheduled-task-persistence-win", TASK_NAME="OfficeTelemetryAgent")[0]
    assert "OfficeTelemetryAgent" in script_of("rogue_task2_removed")
    assert checks["task2_payload_removed"]["collect"]["path"] == task2["PAYLOAD_PATH"]
    assert fq["fq_task_name"]["answer"] == "ChromeUpdateCore"
    assert fq["fq_runkey_value"]["answer"] == "FleetPulseCore"

    fleet = vars_of("malicious-service-win", SERVICE_NAME="HarborlineFleetSync")[0]
    assert checks["fleetsync_stopped"]["collect"]["service"] == "HarborlineFleetSync"
    assert "fleetsync" in checks["fleetsync_process_killed"]["collect"]["pattern"]
    assert checks["fleetsync_disabled"]["collect"]["service"] == "HarborlineFleetSync"
    boost = vars_of("malicious-service-win", SERVICE_NAME="RegBoostSvc")[0]
    assert checks["regboost_stopped"]["collect"]["service"] == "RegBoostSvc"
    assert "regboost" in checks["regboost_process_killed"]["collect"]["pattern"]
    assert checks["regboost_disabled"]["collect"]["service"] == "RegBoostSvc"

    # --- persistence: IFEO / Winlogon / WMI / startup ---------------------------
    sethc = vars_of("ifeo-backdoor-win", EXECUTABLE="sethc.exe")[0]
    assert checks["ifeo_sethc_clean"]["collect"]["key"].endswith("\\sethc.exe")
    assert checks["ifeo_sethc_clean"]["collect"]["value"] == "Debugger"
    utilman = vars_of("ifeo-backdoor-win", EXECUTABLE="utilman.exe")[0]
    assert checks["ifeo_utilman_clean"]["collect"]["key"].endswith("\\utilman.exe")
    assert fq["fq_ifeo_executable"]["answer"] == "sethc.exe"

    winit = vars_of("winlogon-shell-win")[0]
    assert "Userinit" in script_of("winlogon_userinit_clean")
    assert "userinit.exe," in script_of("winlogon_userinit_clean")
    assert winit["PAYLOAD_EXE"] == r"C:\ProgramData\Subsystems\winitupd.exe"

    wmi = vars_of("wmi-subscription-persistence-win")[0]
    assert wmi["FILTER_NAME"] == "HarborlineHealthFilter"
    assert wmi["CONSUMER_NAME"] == "HarborlineHealthConsumer"
    assert "__FilterToConsumerBinding" in script_of("wmi_binding_removed")
    assert "root\\subscription" in script_of("wmi_binding_removed")
    assert checks["wmi_payload_gone"]["collect"]["path"] == wmi["PAYLOAD_PATH"]

    startup = vars_of("startup-folder-item-win")[0]
    assert checks["startup_item_removed"]["collect"]["path"] == \
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\dispatch-helper.bat"
    assert "dispatch-helper" == startup["ITEM_NAME"]

    # --- files / shares / hosts -------------------------------------------------
    acl = vars_of("insecure-file-acl-win")[0]
    assert acl["FILE_PATH"] == r"C:\HarborlineData\payroll-export.csv"
    assert acl["FILE_PATH"] in script_of("payroll_acl_restricted")
    share = vars_of("insecure-smb-share-win")[0]
    assert share["SHARE_NAME"] == "TransitData"
    assert "'TransitData'" in script_of("transit_share_restricted")
    assert "'TransitData'" in script_of("share_encrypted_or_removed")

    creds = [e["vars"] for e in cfgs if isinstance(e, dict)
             and e.get("name") == "sensitive-file-win"
             and "dispatch_creds" in e["vars"]["FILE_PATH"]][0]
    assert checks["dispatch_creds_removed"]["collect"]["path"] == creds["FILE_PATH"]
    unattend = [e["vars"] for e in cfgs if isinstance(e, dict)
                and e.get("name") == "sensitive-file-win"
                and "unattend" in e["vars"]["FILE_PATH"]][0]
    assert checks["unattend_leftover_removed"]["collect"]["path"] == unattend["FILE_PATH"]

    hosts = vars_of("hosts-redirect-win")[0]
    assert hosts["IP"] == "10.44.9.9"
    assert fq["fq_hidden_dollar_account"]  # ordering guard below
    assert hosts["HOSTNAME"] == "payroll.harborline.example"
    assert re.escape(hosts["HOSTNAME"]) in checks["hosts_redirect_removed"]["collect"]["extract"]
    assert hosts["IP"].replace(".", r"\.") in checks["hosts_redirect_removed"]["collect"]["extract"]

    # --- new-category seeds (parameterless or var-coupled) -----------------------
    defender = vars_of("defender-off-win")[0]
    assert defender["EXCLUSION_PATH"] == r"C:\ProgramData\Subsystems"
    assert "MicrosoftWindowsPowerShellV2" in script_of("ps2_legacy_engine_removed")
    assert "ExclusionPath" in script_of("defender_exclusions_clean")
    assert "wdigest" in script_of("wdigest_cleartext_off").lower() or \
        "UseLogonCredential" in script_of("wdigest_cleartext_off")
    assert "RunAsPPL" in script_of("lsa_ppl_on")
    assert "LmCompatibilityLevel" in script_of("lm_compat_ntlmv2_only")
    anon = script_of("anonymous_enum_restricted")
    assert "RestrictAnonymous " in anon or "RestrictAnonymous" in anon


def test_harborline_plant_ordering_invariants():
    cfgs = _load_nakon()["machines"][0]["configurations"]
    names = [c["name"] if isinstance(c, dict) else c for c in cfgs]
    # weak policy first (complexity off before any account password is set)
    assert names[0] == "weak-password-policy-win"
    # accounts exist before group-adds and before the DCSync ACL
    acct = {"ad-user-win", "ad-blank-password-win"}
    last_acct = max(i for i, n in enumerate(names) if n in acct)
    first_consumer = min(i for i, n in enumerate(names)
                         if n in ("ad-group-member-win", "ad-acl-dcsync-win",
                                  "ad-delegation-win"))
    assert last_acct < first_consumer
    # the file ACL that creates the share target must run before the share seed
    assert names.index("insecure-file-acl-win") < names.index("insecure-smb-share-win")
    # the hosts redirect goes last (pinecrest convention)
    assert names[-1] == "hosts-redirect-win"
    # every referenced seed exists locally
    for n in names:
        assert os.path.isfile(os.path.join(SEEDS, n + ".json")), f"missing seed {n}"


def test_harborline_new_seeds_are_valid_generic_windows_configs():
    for name in NEW_SEEDS:
        path = os.path.join(SEEDS, name + ".json")
        d = json.load(open(path, encoding="utf-8"))
        assert d["name"] == name, path
        assert d["platform"] == "windows", path
        assert d["category"] == "misconfiguration", path
        assert d["type"] == "powershell", path
        assert d["run_as"] == "Administrator", path
        assert d["script"].strip(), path
        assert isinstance(d["depends_on"], list), path
        assert "$args" not in d["script"], f"{path}: $args is reserved"
        # the nakon PS rc-trailer trap: a probe that misses must not pollute
        # $Error -- the pinecrest round lost five plant rounds to this
        assert "SilentlyContinue" not in d["script"], path
        assert "Vars:" in d["description"], f"{path}: document vars"
        assert "Pairs with" in d["description"], f"{path}: document the check"


def test_harborline_forensics_answers_never_named_in_displays():
    """The eight answers must come from investigating the planted artifacts,
    not from reading the report: no check display may name any of them."""
    sc = _load_scenario()
    answers = {
        "helpdesk$", "qa_kiosk", "svc_turnstile", "FareKiosk2026!",
        "TransitPulse", "ChromeUpdateCore", "FleetPulseCore",
    }
    for c in sc["checks"]:
        low = c["display"].lower()
        for a in answers:
            assert a.lower() not in low, f"{c['id']} display leaks {a}"
    # the purest investigate-it answers appear in no check body at all
    for c in sc["checks"]:
        body = c["collect"].get("script", "") or str(c["collect"].get("path", "")) \
            or str(c["collect"].get("value", ""))
        for a in PUREST_ANSWERS:
            assert a not in body, f"{c['id']} names investigate-it answer {a}"


def test_harborline_disable_not_delete_semantics():
    """Rogue accounts and stale objects score on exists-AND-disabled; the
    rotation target must still exist and be enabled in the hardened state."""
    sc = _load_scenario()
    by_id = {c["id"]: c for c in sc["checks"]}
    for cid in ("bprieto_disabled", "lhaight_disabled", "stale_svc_disabled",
                "stale_computer_disabled"):
        script = by_id[cid]["collect"]["script"]
        assert "$null -ne" in script, f"{cid} must require the account to exist"
        assert "Enabled -eq $false" in script, f"{cid} must key on disabled"
    rotated = by_id["svc_sched_password_rotated"]["collect"]["script"]
    assert "$u.Enabled" in rotated, "rotation requires the account stays enabled"
    # never_expires sweep keeps the designed krbtgt exception
    assert "krbtgt" in by_id["never_expires_clean"]["collect"]["script"]


def test_harborline_penalty_guards():
    sc = _load_scenario()
    guards = [c for c in sc["checks"] if c["category"] == "penalty"]
    assert len(guards) == 3
    by_id = {g["id"]: g for g in guards}
    assert "'rcastillo'" in by_id["legit_staff_intact"]["collect"]["script"]
    assert by_id["payroll_file_present"]["collect"]["path"] == \
        r"C:\HarborlineData\payroll-export.csv"
    assert by_id["payroll_file_present"]["expect"]["equals"] is True
    assert by_id["dns_service_running"]["collect"]["service"] == "DNS"
    assert by_id["dns_service_running"]["expect"]["equals"] is True
    for g in guards:
        assert g["expect"]["points"] == -10
        assert g["max_points"] == 10


def test_harborline_readme_hides_forensics_answers():
    """The in-box handbook is the assignment, not the answer key: no forensics
    answer (>= 4 chars) may appear verbatim in the README."""
    readme = open(README, encoding="utf-8").read()
    for f in _load_scenario()["forensics"]:
        for ans in [f["answer"]] + list(f.get("answers", [])):
            if len(ans) >= 4 and ans not in f["question"]:
                assert ans not in readme, f"README leaks forensics answer {ans!r}"


def test_harborline_readme_names_the_forensics_answers_file_path():
    # Students look in C:\Users\sysadmin\Desktop and report the file missing;
    # the README must name the real path (Public Desktop) explicitly.
    readme = open(README, encoding="utf-8").read()
    assert "C:\\Users\\Public\\Desktop\\Forensics-Questions.txt" in readme
    assert "save it in place" in readme


def test_harborline_theme_block_wired_for_windows():
    from boxbuilder.spec import load_spec
    from boxbuilder.theme import _target_is_windows

    sc = _load_scenario()
    theme = sc.get("theme") or {}
    for key in ("title", "wallpaper", "readme"):
        assert theme.get(key), f"harborline theme missing {key}"
    for key in ("logo", "wallpaper", "readme"):
        assert os.path.isfile(os.path.join(BOX_DIR, theme[key])), key

    spec = load_spec(os.path.join(BOX_DIR, "box.yaml"))
    assert _target_is_windows(spec), "harborline must resolve as a windows target"


def test_harborline_answerkey_renders_with_zero_missing_walkthroughs():
    from boxbuilder import answerkey

    sc = _load_scenario()
    for c in sc["checks"]:
        assert c.get("solution"), f"check {c['id']} has no solution walkthrough"
    for f in sc["forensics"]:
        assert f.get("solution"), f"forensics {f['id']} has no solution"
    md, gaps = answerkey.render_markdown(sc, SCENARIO)
    assert gaps == [], f"answer key gaps: {gaps}"
    assert answerkey._PLACEHOLDER not in md


def test_harborline_win_task_script_self_heals_forensics_acl():
    # The answers file is written by the SYSTEM agent but edited by a
    # UAC-filtered desktop user; os.chmod cannot express NTFS ACLs, so the
    # task script must re-grant BUILTIN\Users modify every cycle (packaging/
    # huitz-agent-task.ps1 ships to every Windows box at install time).
    task = open(os.path.join(REPO_ROOT, "packaging", "huitz-agent-task.ps1"),
                encoding="utf-8").read()
    assert "Forensics-Questions.txt" in task
    assert "*S-1-5-32-545:M" in task
