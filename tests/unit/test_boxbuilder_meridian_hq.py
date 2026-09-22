"""Box-level contract tests for the meridian-hq AD workshop box (the second
Windows round): the new generic ad-*/gpp-*/gpo-*/ldap-*/firewall-allow seeds,
nakon<->scenario name discipline, difficulty-weighted points, disable-not-
delete semantics, forensics-answer hygiene, the penalty guard, and the theme
block that the 2026-09-13 pinecrest seal taught us to never ship without."""
import json
import os

import yaml

from authoring.validate import validate_scenario_yaml
from boxbuilder import answerkey

SCENARIO = "boxes/meridian-hq/scenario.yaml"
NAKON = "boxes/meridian-hq/nakon.json"
NEW_SEEDS = [
    "ad-user-win",
    "ad-group-member-win",
    "ad-delegation-win",
    "ad-acl-dcsync-win",
    "ad-computer-win",
    "gpp-cpassword-win",
    "gpo-persistence-win",
    "ldap-signing-off-win",
    "firewall-allow-rule-win",
]


def _scenario():
    return yaml.safe_load(open(SCENARIO, encoding="utf-8"))


def _nakon():
    return json.load(open(NAKON, encoding="utf-8"))


def test_ad_seeds_are_valid_generic_windows_configs():
    for name in NEW_SEEDS:
        path = f"boxbuilder/vulndb_vuln_configs/{name}.json"
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


def test_meridian_nakon_config_seeds_exist_locally():
    machine = _nakon()["machines"][0]
    assert "win" in machine["os"]
    for entry in machine["configurations"]:
        name = entry if isinstance(entry, str) else entry["name"]
        path = f"boxbuilder/vulndb_vuln_configs/{name}.json"
        assert os.path.isfile(path), f"missing local seed for {name}"


def test_meridian_scenario_validates_and_weights_points():
    sc = _scenario()
    assert validate_scenario_yaml(sc, source_path=SCENARIO) == []
    vuln = [c for c in sc["checks"] if c["category"] == "vuln"]
    penalty = [c for c in sc["checks"] if c["category"] == "penalty"]
    assert len(vuln) == 27
    assert len(penalty) == 1
    # difficulty weighting is Hamza's standing preference (flat 10s rejected)
    assert {c["max_points"] for c in vuln} == {5, 10, 20}
    assert sum(c["max_points"] for c in vuln) == 330
    assert len(sc["forensics"]) == 6
    assert sum(f["points"] for f in sc["forensics"]) == 60


def test_meridian_scenario_nakon_name_discipline():
    """Every planted name must match its paired check's collect params
    byte-for-byte -- nothing cross-validates them."""
    sc = _scenario()
    entries = _nakon()["machines"][0]["configurations"]

    def vars_of(name):
        for e in entries:
            if isinstance(e, dict) and e.get("name") == name:
                return e.get("vars", {})
        return {}

    by_id = {c["id"]: c for c in sc["checks"]}

    def script_of(cid):
        return by_id[cid]["collect"]["script"]

    # GPO persistence: GPO name + Run value byte-identical in the check script
    assert vars_of("gpo-persistence-win")["GPO_NAME"] == "MeridianTelemetry"
    assert vars_of("gpo-persistence-win")["RUN_VALUE_NAME"] == "TeamsBootstrapper"
    assert "'MeridianTelemetry'" in script_of("gpo_persistence_removed")
    assert "'TeamsBootstrapper'" in script_of("gpo_persistence_removed")

    # GPP: the check sweeps by pattern (New-GPO GUIDs are random), but the
    # planted GPO name is the forensics answer and must exist in the config
    assert vars_of("gpp-cpassword-win")["GPO_NAME"] == "Deploy Local Admin"

    # local persistence trio
    assert vars_of("runkey-persistence-win")["RUN_VALUE_NAME"] == "TelemetryCore"
    assert by_id["runkey_removed"]["collect"]["value"] == "TelemetryCore"
    assert vars_of("scheduled-task-persistence-win")["TASK_NAME"] == "OneDriveTelemetrySync"
    assert "OneDriveTelemetrySync" in script_of("no_task")
    assert vars_of("malicious-service-win")["SERVICE_NAME"] == "MeridianBackupAgent"
    assert by_id["rogue_svc_stopped"]["collect"]["service"] == "MeridianBackupAgent"
    assert "mbdeploy" in by_id["rogue_svc_killed"]["collect"]["pattern"]
    for cid, path in (
        ("runkey_payload_gone", r"C:\ProgramData\Subsystems\telemetry.ps1"),
        ("task_payload_removed", r"C:\ProgramData\Subsystems\odsync.ps1"),
    ):
        assert by_id[cid]["collect"]["path"] == path

    # firewall backdoor rule
    assert vars_of("firewall-allow-rule-win")["RULE_NAME"] == "MeridianSync"
    assert "'MeridianSync'" in script_of("backdoor_rule_removed")

    # AD accounts: the kerberoast pairing is account + original password
    report = vars_of("ad-user-win") and None
    for e in entries:
        if isinstance(e, dict) and e.get("name") == "ad-user-win" \
                and e["vars"]["USERNAME"] == "svc_report":
            assert e["vars"]["PASSWORD"] == "ReportSpring2026!"
            assert e["vars"]["SPN"] == "HTTP/dc01.meridian.local"
    assert "'svc_report'" in script_of("svc_report_password_rotated")
    assert "'ReportSpring2026!'" in script_of("svc_report_password_rotated")

    # DCSync trustee, rogue account, group, computers
    assert vars_of("ad-acl-dcsync-win")["TRUSTEE"] == "svc_replication"
    assert "'svc_replication'" in script_of("dcsync_rights_revoked")
    group_adds = [e for e in entries
                  if isinstance(e, dict) and e.get("name") == "ad-group-member-win"]
    assert {e["vars"]["USERNAME"] for e in group_adds} == {"svc_contractor", "rreyes"}
    assert all(e["vars"]["GROUP"] == "Domain Admins" for e in group_adds)
    assert "'rreyes'" in script_of("rreyes_disabled")
    assert "'Domain Admins'" in script_of("domain_admins_subset")
    assert vars_of("ad-delegation-win")["ACCOUNT"] == "APP01"
    assert '"APP01"' in script_of("app01_delegation_cleared")
    assert vars_of("ad-computer-win")["COMPUTER_NAME"] == "WS-LEGACY01"
    assert '"WS-LEGACY01"' in script_of("stale_computer_disabled")
    # ldap-signing-off-win is parameterless and referenced as a bare string
    assert "ldap-signing-off-win" in entries
    assert by_id["ldap_signing_required"]["collect"]["value"] == "LDAPServerIntegrity"


def test_forensics_answers_never_named_in_displays():
    """The six answers must come from investigating the planted artifacts,
    not from reading the report: no check display may name any of them
    (script bodies may -- pinecrest precedent -- but the AS-REP account is
    answer material everywhere, so it stays out of scripts entirely)."""
    sc = _scenario()
    answers = {
        "svc_legacy",
        "SpringDeploy2026!",
        "MeridianTelemetry",
        "OneDriveTelemetrySync",
        "TelemetryCore",
        "svc_replication",
    }
    for c in sc["checks"]:
        low = c["display"].lower()
        for a in answers:
            assert a.lower() not in low, f"{c['id']} display leaks {a}"
    # the AS-REP account is the purest investigate-it answer: its fix is a
    # sweep, so the planted name belongs in no check body at all
    for c in sc["checks"]:
        body = c["collect"].get("script", "") or str(c["collect"].get("path", ""))
        assert "svc_legacy" not in body, f"{c['id']} names the AS-REP account"


def test_disable_not_delete_semantics():
    """Rogue accounts and stale objects score on exists-AND-disabled; the
    DCSync trustee and the rotation target must still exist in the hardened
    state (deleting evidence earns nothing)."""
    sc = _scenario()
    by_id = {c["id"]: c for c in sc["checks"]}
    for cid in ("rreyes_disabled", "stale_computer_disabled"):
        script = by_id[cid]["collect"]["script"]
        assert "$null -ne" in script, f"{cid} must require the account to exist"
        assert "Enabled -eq $false" in script, f"{cid} must key on disabled"
    dcsync = by_id["dcsync_rights_revoked"]["collect"]["script"]
    assert "$null -ne $t" in dcsync, "trustee must exist for the check to score"
    rotated = by_id["svc_report_password_rotated"]["collect"]["script"]
    assert "$u.Enabled" in rotated, "rotation requires the account stays enabled"


def test_penalty_guard_is_anti_scroched_earth():
    sc = _scenario()
    guard = [c for c in sc["checks"] if c["category"] == "penalty"]
    assert len(guard) == 1
    g = guard[0]
    assert g["id"] == "legit_user_intact"
    assert g["expect"]["equals"] is True and g["expect"]["points"] == -10
    assert "'mchen'" in g["collect"]["script"]


def test_theme_block_wired_for_windows():
    from boxbuilder.spec import load_spec
    from boxbuilder.theme import _target_is_windows

    sc = _scenario()
    theme = sc.get("theme") or {}
    for key in ("title", "wallpaper", "readme"):
        assert theme.get(key), f"meridian theme missing {key}"
    for key in ("logo", "wallpaper", "readme"):
        assert os.path.isfile(os.path.join("boxes/meridian-hq", theme[key])), key

    spec = load_spec("boxes/meridian-hq/box.yaml")
    assert _target_is_windows(spec), "meridian must resolve as a windows target"


def test_answerkey_renders_with_zero_missing_walkthroughs():
    sc = _scenario()
    for c in sc["checks"]:
        assert c.get("solution"), f"check {c['id']} has no solution walkthrough"
    for f in sc["forensics"]:
        assert f.get("solution"), f"forensics {f['id']} has no solution"
    md, gaps = answerkey.render_markdown(sc, SCENARIO)
    assert gaps == [], f"answer key gaps: {gaps}"
    assert answerkey._PLACEHOLDER not in md


def test_readme_names_the_forensics_answers_file_path():
    # Students look in C:\Users\sysadmin\Desktop and report the file missing;
    # the README must name the real path (Public Desktop) explicitly.
    readme = open("boxes/meridian-hq/assets/README.md", encoding="utf-8").read()
    assert "C:\\Users\\Public\\Desktop\\Forensics-Questions.txt" in readme
    assert "save it in place" in readme


def test_win_task_script_self_heals_forensics_acl():
    # The answers file is written by the SYSTEM agent but edited by a
    # UAC-filtered desktop user; os.chmod cannot express NTFS ACLs, so the
    # task script must re-grant BUILTIN\Users modify every cycle (packaging/
    # huitz-agent-task.ps1 ships to every Windows box at install time).
    task = open("packaging/huitz-agent-task.ps1", encoding="utf-8").read()
    assert "Forensics-Questions.txt" in task
    assert "*S-1-5-32-545:M" in task
