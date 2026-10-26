"""Regression coverage for the Saltmarsh Exchange box.

The IIS + FTP web-tier WINDOWS box (the web-edge counterpart to
harborline-transit): a workgroup member server that scores 37 hardening
findings (EASY=2 x14, MODERATE=4 x15, HARD=8 x8 = 152 attainable), three
penalty guards (portal service, FTP service, portal site) and a
six-question forensics block whose answers are breadcrumbs to specific
findings (6 x 8 = 48; 200 grand total).

What these tests pin down:
- the ledger itself (check count, tier<->points agreement, the tier
  distribution, the forensics split) -- the ledger IS the contract with
  the students, and the README quotes it;
- every powershell_json script follows the collect contract (no
  SilentlyContinue, one compressed JSON document, matcher on `data`);
- the plant<->check pairing discipline (critical planted paths/names/
  ports in nakon.json must byte-match the paired scenario collect params
  and forensics answers -- nothing cross-checks them at build time);
- plant ordering (the base first, the FTP flip last, accounts before
  group-adds, the config/file plants after the base);
- solutions never leak into the signed manifest or the rubric, no
  forensics answer leaks into the in-box README or a display, and the
  investigate-it answers appear in no check body at all;
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
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "saltmarsh-exchange")
SCENARIO = os.path.join(BOX_DIR, "scenario.yaml")
NAKON = os.path.join(BOX_DIR, "nakon.json")
README = os.path.join(BOX_DIR, "assets", "README.md")
SEEDS = os.path.join(REPO_ROOT, "boxbuilder", "vulndb_vuln_configs")

VULN_COUNT = 37
PENALTY_COUNT = 3
FORENSICS_COUNT = 6
TIER_POINTS = {"EASY": 2, "MODERATE": 4, "HARD": 8}
TIER_COUNTS = {"EASY": 14, "MODERATE": 15, "HARD": 8}
VULN_POINTS = 152
FORENSICS_POINTS = 48
MAX_POINTS = 200

NEW_SEEDS = [
    "iis-ftp-base-win", "iis-hardening-off-win", "iis-backoffice-open-win",
    "iis-admin-console-win", "ftp-hardening-off-win", "wmsvc-enabled-win",
    "local-group-member-win", "local-user-enable-win", "insecure-dir-acl-win",
    "zip-archive-win", "insecure-smb-share-quiet-win",
]

# Answers that must be earned by investigating, not by reading the report
# or the manifest. `svc_webdeploy` is exempt (its disable check names the
# account -- the harborline sethc.exe precedent); `8080` is exempt (the
# admin-console check's collect params use the port as the selector).
PURE_ANSWERS = {"Kestrel2026!", "SqlS3rv1ce!2024", "LocalSystem", "diag.aspx"}


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_nakon():
    with open(NAKON, encoding="utf-8") as f:
        return json.load(f)


def test_saltmarsh_scenario_validates_and_compiles(tmp_path):
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
    assert manifest["theme"]["title"] == "Saltmarsh Regional Water Authority"
    assert manifest["theme"]["readme_text"].startswith("# Saltmarsh")
    # solutions must never reach the box: not in the signed manifest, not the rubric
    assert not any(c.get("solution") for c in manifest["checks"])
    assert "solution" not in json.dumps(manifest)
    rubric = json.load(open(outputs["rubric"], encoding="utf-8"))
    assert "solution" not in json.dumps(rubric)


def test_saltmarsh_difficulty_tiers_match_points():
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


def test_saltmarsh_powershell_scripts_follow_collect_contract():
    """powershell_json scripts must be non-empty, emit one JSON document, and
    honor the rc-trailer discipline (no SilentlyContinue -- a probe that
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
        if check["type"] == "permission":
            assert "path" in check["collect"], check["id"]
        if check["type"] == "file_regex":
            assert "extract" in check["collect"], check["id"]


def test_saltmarsh_plant_coupling_and_forensics_breadcrumbs():
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

    # --- base / site names ---------------------------------------------------
    base = [c for c in cfgs if c == "iis-ftp-base-win"]
    assert base, "iis-ftp-base-win must be selected"

    # --- local accounts ------------------------------------------------------
    deploy = vars_of("local-user-win", USERNAME="svc_webdeploy")[0]
    assert deploy["ADMIN_ADD"] == "1"
    assert vars_of("local-user-enable-win", USERNAME="svc_webdeploy")
    assert "'svc_webdeploy'" in script_of("webdeploy_account_disabled")
    assert fq["fq_webdeploy_account"]["answer"] == "svc_webdeploy"

    group = vars_of("local-group-member-win", USERNAME="ftp_vendor")[0]
    assert group["GROUP"] == "Administrators"
    assert "'ftp_vendor'" in script_of("ftp_vendor_not_admin")

    # --- IIS artifacts -------------------------------------------------------
    cfg = vars_of("sensitive-file-win", FILE_PATH=r"C:\inetpub\saltmarsh\wwwroot\web.config")[0]
    assert 'debug="true"' in cfg["FILE_CONTENT"]
    assert checks["aspnet_debug_off"]["collect"]["path"] == cfg["FILE_PATH"]

    bak = vars_of(
        "sensitive-file-win",
        FILE_PATH=r"C:\inetpub\saltmarsh\wwwroot\app\web.config.bak",
    )[0]
    assert "SqlS3rv1ce!2024" in bak["FILE_CONTENT"]
    assert fq["fq_db_password"]["answer"] == "SqlS3rv1ce!2024"
    assert checks["config_backup_removed"]["collect"]["path"] == bak["FILE_PATH"]

    shell = vars_of(
        "sensitive-file-win",
        FILE_PATH=r"C:\inetpub\saltmarsh\wwwroot\diag.aspx",
    )[0]
    assert shell["FILE_PATH"].endswith("diag.aspx")
    assert fq["fq_webshell_name"]["answer"] == "diag.aspx"

    git = vars_of(
        "sensitive-file-win",
        FILE_PATH=r"C:\inetpub\saltmarsh\wwwroot\.git\config",
    )[0]
    assert checks["git_dir_removed"]["collect"]["path"] == \
        r"C:\inetpub\saltmarsh\wwwroot\.git"
    assert git["FILE_PATH"].endswith(r".git\config")

    creds = vars_of(
        "sensitive-file-win",
        FILE_PATH=r"C:\inetpub\saltmarsh\ftproot\outgoing\vendor-credentials.txt",
    )[0]
    assert "Kestrel2026!" in creds["FILE_CONTENT"]
    assert fq["fq_ftp_vendor_password"]["answer"] == "Kestrel2026!"
    assert checks["ftp_cleartext_creds_removed"]["collect"]["path"] == creds["FILE_PATH"]

    archive = vars_of(
        "zip-archive-win",
        ZIP_PATH=r"C:\inetpub\saltmarsh\wwwroot\backup\portal-source.zip",
    )[0]
    assert checks["portal_archive_removed"]["collect"]["path"] == archive["ZIP_PATH"]

    # --- network exposure ----------------------------------------------------
    assert vars_of("firewall-allow-rule-win", RULE_NAME="VendorFtpAlt")[0]["LOCAL_PORT"] == "2121"
    assert "'VendorFtpAlt'" in script_of("rogue_ftp_rule_removed")
    assert "iis-admin-console-win" in cfgs
    assert "'SaltmarshAdmin'" in script_of("admin_console_removed")
    assert "'SaltmarshFtpIn'" in script_of("ftp_firewall_scoped")
    assert "'SaltmarshWeb$'" in script_of("web_share_restricted")
    assert vars_of("insecure-smb-share-quiet-win", SHARE_NAME="SaltmarshWeb$")

    # --- FTP seeds / settings ------------------------------------------------
    assert [c for c in cfgs if c == "ftp-hardening-off-win"]
    assert "anonymousAuthentication" in script_of("ftp_anonymous_off")
    # the FTP seeds write the site element in applicationHost; the checks
    # must read that same path (not the site-level delegated view)
    for cid in ("ftp_anonymous_off", "ftp_control_ssl_required",
                "ftp_data_ssl_required", "ftp_user_isolation_on"):
        assert "system.applicationHost/sites/site[@name=" in script_of(cid), cid
    assert "accessType" in script_of("ftp_anonymous_write_off")

    # --- WMSVC ---------------------------------------------------------------
    assert [c for c in cfgs if c == "wmsvc-enabled-win"]
    assert "WMSVC" in script_of("wmsvc_disabled")

    # --- forensics -----------------------------------------------------------
    assert fq["fq_apppool_identity"]["answer"] == "LocalSystem"
    assert fq["fq_admin_port"]["answer"] == "8080"


def test_saltmarsh_plant_ordering_invariants():
    cfgs = _load_nakon()["machines"][0]["configurations"]
    names = [c["name"] if isinstance(c, dict) else c for c in cfgs]
    # the base installs roles + creates every site/account/dir before any flip
    assert names[0] == "iis-ftp-base-win"
    # the live web.config plant must precede the site-level flips; otherwise it
    # overwrites directoryBrowse/httpErrors/verbs/WebDAV with a fresh web.config
    web_i = next(
        i for i, c in enumerate(cfgs)
        if isinstance(c, dict) and c.get("name") == "sensitive-file-win"
        and c.get("vars", {}).get("FILE_PATH", "").endswith("\\wwwroot\\web.config")
    )
    assert names.index("iis-ftp-base-win") < web_i < names.index("iis-hardening-off-win")
    # accounts exist before the group-add
    assert names.index("local-user-win") < names.index("local-user-enable-win")
    assert names.index("local-user-enable-win") < names.index("local-group-member-win")
    # the artifact plants follow the base (the directories/sites exist)
    assert names.index("iis-ftp-base-win") < names.index("sensitive-file-win")
    assert names.index("iis-ftp-base-win") < names.index("iis-admin-console-win")
    assert names.index("iis-ftp-base-win") < names.index("ftp-hardening-off-win")
    # the FTP flip is last, so its broad firewall scope is the final state
    assert names[-1] == "ftp-hardening-off-win"
    # every referenced seed exists locally
    for n in names:
        assert os.path.isfile(os.path.join(SEEDS, n + ".json")), f"missing seed {n}"


def test_saltmarsh_new_seeds_are_valid_generic_windows_configs():
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


def test_saltmarsh_forensics_answers_never_named_in_displays():
    """The answers must come from investigating the planted artifacts, not
    from reading the report: no check display may name any of them."""
    sc = _load_scenario()
    answers = {
        "svc_webdeploy", "Kestrel2026!", "SqlS3rv1ce!2024",
        "LocalSystem", "diag.aspx", "8080",
    }
    for c in sc["checks"]:
        low = c["display"].lower()
        for a in answers:
            assert a.lower() not in low, f"{c['id']} display leaks {a}"
    # the purest investigate-it answers appear in no check body at all
    for c in sc["checks"]:
        body = c["collect"].get("script", "") or str(c["collect"].get("path", "")) \
            or str(c["collect"].get("value", ""))
        for a in PURE_ANSWERS:
            assert a not in body, f"{c['id']} names investigate-it answer {a}"


def test_saltmarsh_penalty_guards():
    sc = _load_scenario()
    guards = [c for c in sc["checks"] if c["category"] == "penalty"]
    assert len(guards) == 3
    by_id = {g["id"]: g for g in guards}
    assert by_id["penalty_w3svc_running"]["collect"]["service"] == "W3SVC"
    assert by_id["penalty_w3svc_running"]["expect"]["field"] == "active"
    assert by_id["penalty_ftpsvc_running"]["collect"]["service"] == "FTPSVC"
    assert by_id["penalty_ftpsvc_running"]["expect"]["field"] == "active"
    assert "'SaltmarshPortal'" in by_id["penalty_portal_started"]["collect"]["script"]
    for g in guards:
        assert g["expect"]["points"] == -10
        assert g["max_points"] == 10


def test_saltmarsh_readme_hides_forensics_answers():
    """The in-box handbook is the assignment, not the answer key: no forensics
    answer (>= 4 chars) may appear verbatim in the README."""
    readme = open(README, encoding="utf-8").read()
    for f in _load_scenario()["forensics"]:
        for ans in [f["answer"]] + list(f.get("answers", [])):
            if len(ans) >= 4 and ans not in f["question"]:
                assert ans not in readme, f"README leaks forensics answer {ans!r}"


def test_saltmarsh_theme_assets_exist_and_fit_caps():
    sc = _load_scenario()
    theme = sc["theme"]
    for key in ("logo", "wallpaper", "readme"):
        path = os.path.join(BOX_DIR, theme[key])
        assert os.path.isfile(path), f"missing theme asset {key}: {path}"
    assert os.path.getsize(os.path.join(BOX_DIR, theme["logo"])) <= 150 * 1024
    assert len(open(os.path.join(BOX_DIR, theme["readme"]), encoding="utf-8").read()) <= 64 * 1024
