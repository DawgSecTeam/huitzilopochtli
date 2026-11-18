"""Birchwood Academy regression checks.

Box-specific invariants: the ledger's arithmetic, the ranked service /
adversary safety rules (kills must target recoverable services only —
never the RDP listener the players are using), and the planted-portal
protection that keeps the webshell finding from eating the school's own
home page.
"""
import os

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX = os.path.join(REPO, "boxes", "birchwood-academy")


def _parsed():
    with open(os.path.join(BOX, "scenario.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _nakon():
    with open(os.path.join(BOX, "nakon.json"), encoding="utf-8") as f:
        return __import__("json").load(f)


def test_ledger_arithmetic():
    """10x5 + 16x10 + 4x20 hardening + 10x10 forensics = 390 static."""
    d = _parsed()
    vuln = [c for c in d["checks"] if c["category"] == "vuln"]
    assert len(vuln) == 30
    assert sum(1 for c in vuln if c["max_points"] == 5) == 10
    assert sum(1 for c in vuln if c["max_points"] == 10) == 16
    assert sum(1 for c in vuln if c["max_points"] == 20) == 4
    assert len(d["forensics"]) == 10
    assert all(f["points"] == 10 for f in d["forensics"])
    total = sum(c["max_points"] for c in vuln) + sum(f["points"] for f in d["forensics"])
    assert total == 390


def test_answer_key_has_no_gaps():
    d = _parsed()
    missing = [c["id"] for c in d["checks"] if not (c.get("solution") or "").strip()]
    missing += [f["id"] for f in d["forensics"] if not (f.get("solution") or "").strip()]
    assert not missing, missing


def test_ranked_services_are_the_school_day():
    ranked = _parsed()["ranked"]
    services = {s["id"]: s for s in ranked["services"]}
    assert set(services) == {"portal", "records", "rdp"}
    assert services["portal"]["type"] == "http_uptime"  # first live HTTP SLA on Windows
    assert services["portal"]["collect"]["url"] == "http://127.0.0.1/"
    assert services["records"]["collect"]["port"] == 445
    assert services["rdp"]["collect"]["port"] == 3389


def test_adversary_kills_only_recoverable_services():
    """Never TermService (bricks the players' own console) and never a
    service a check rewards stopping (Spooler-class). W3SVC and
    LanmanServer are both restartable from an open RDP session."""
    events = _parsed()["ranked"]["adversary"]["events"]
    kills = sorted(e["params"]["service"] for e in events
                   if e["action"] == "kill_service")
    assert kills == ["W3SVC", "lanmanserver"]
    forbidden = {"TermService", "Spooler", "WinDefend", "mpssvc"}
    assert not (set(kills) & forbidden)
    assert "flush_firewall" not in {e["action"] for e in events}
    for e in events:
        if e["action"] == "kill_service":
            assert e["affects_check"] in {s["id"] for s in _parsed()["ranked"]["services"]}


def test_adversary_windows_are_ordered_and_sane():
    events = _parsed()["ranked"]["adversary"]["events"]
    windows = [tuple(e["window_s"]) for e in events]
    assert windows == sorted(windows)
    assert all(300 <= lo < hi <= 5400 for lo, hi in windows)


def test_planted_portal_page_is_protected():
    """The portal home page is planted via sensitive-file-win (the only
    content-bearing row); the penalty check must guard exactly that
    path, and the webshell finding must point at the OTHER file."""
    planted = None
    for c in _nakon()["machines"][0]["configurations"]:
        if isinstance(c, dict) and c["name"] == "sensitive-file-win":
            planted = c["vars"]["FILE_PATH"]
    assert planted == r"C:\inetpub\wwwroot\index.html"
    checks = {c["id"]: c for c in _parsed()["checks"]}
    assert checks["portal_homepage_present"]["collect"]["path"] == planted
    assert checks["portal_homepage_present"]["category"] == "penalty"
    assert checks["webshell_removed"]["collect"]["path"] == r"C:\inetpub\wwwroot\cmd.aspx"


def test_admin_roster_allows_exactly_the_player():
    script = next(c for c in _parsed()["checks"]
                  if c["id"] == "admin_roster_clean")["collect"]["script"]
    assert "$allowed = @('Administrator', 'registrar')" in script


def test_pool_placeholders_follow_the_box_slug():
    pool = _parsed()["ranked"]["pool"]
    assert pool["template_vm_id"] == "${HUITZILOPOCHTLI_BIRCHWOOD_ACADEMY_POOL_TEMPLATE_VM_ID}"
    assert pool["template_vm_username"] == "${HUITZILOPOCHTLI_BIRCHWOOD_ACADEMY_POOL_TEMPLATE_USER}"
    assert pool["template_vm_password"] == "${HUITZILOPOCHTLI_BIRCHWOOD_ACADEMY_POOL_TEMPLATE_PASSWORD}"
    assert pool["template_vm_access_method"] == "rdp"


def test_intruder_address_agrees_across_the_incident():
    ip = "198.51.100.77"
    fq = {q["id"]: q for q in _parsed()["forensics"]}
    assert str(fq["fq-c2-ip"]["answer"]) == ip
    for c in _nakon()["machines"][0]["configurations"]:
        if isinstance(c, dict) and c["name"] == "hosts-redirect-win":
            assert c["vars"]["IP"] == ip
            assert c["vars"]["HOSTNAME"] == "grades.birchwoodacademy.example"


def test_windows_checks_carry_powershell_timeouts():
    """Cold WMI/Defender calls on a just-booted pool VM blow the 5s
    default; every powershell_json check needs explicit headroom."""
    for c in _parsed()["checks"]:
        if c["type"] == "powershell_json":
            assert c.get("timeout_s", 5) >= 25, c["id"]
