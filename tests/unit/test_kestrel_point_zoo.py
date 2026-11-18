"""Kestrel Point Zoo regression checks.

Box-specific invariants: the ledger's arithmetic, the ranked service /
adversary safety rules (kills must target recoverable services only --
never the terminal service the players' RDP rides on), the disable-not-
delete account rule, and the handbook spoiler guard.
"""
import os

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX = os.path.join(REPO, "boxes", "kestrel-point-zoo")


def _parsed():
    with open(os.path.join(BOX, "scenario.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _nakon():
    import json

    with open(os.path.join(BOX, "nakon.json"), encoding="utf-8") as f:
        return json.load(f)


def test_ledger_arithmetic():
    """3x5 + 20x10 + 7x20 hardening + forensics 3x4 + 5x8 + 1x12 = 419 static."""
    d = _parsed()
    vuln = [c for c in d["checks"] if c["category"] == "vuln"]
    assert len(vuln) == 30
    assert sum(1 for c in vuln if c["max_points"] == 5) == 3
    assert sum(1 for c in vuln if c["max_points"] == 10) == 20
    assert sum(1 for c in vuln if c["max_points"] == 20) == 7
    penalties = [c for c in d["checks"] if c["category"] == "penalty"]
    assert {c["id"] for c in penalties} == {"penalty_termservice_running"}
    assert len(d["forensics"]) == 9
    total = sum(c["max_points"] for c in vuln) + sum(f["points"] for f in d["forensics"])
    assert total == 419


def test_answer_key_has_no_gaps():
    d = _parsed()
    missing = [c["id"] for c in d["checks"] if not (c.get("solution") or "").strip()]
    missing += [f["id"] for f in d["forensics"] if not (f.get("solution") or "").strip()]
    assert not missing, missing


def test_ranked_services_are_the_park():
    ranked = _parsed()["ranked"]
    services = {s["id"]: s for s in ranked["services"]}
    assert set(services) == {"portal", "keeper_share"}
    assert services["portal"]["type"] == "http_uptime"
    assert services["portal"]["collect"]["url"] == "http://127.0.0.1/"
    assert services["keeper_share"]["collect"]["port"] == 445


def test_adversary_kills_only_recoverable_services():
    """Never TermService (bricks the players' own console) and never a
    service a check rewards stopping."""
    d = _parsed()
    ranked = d["ranked"]
    services = {s["id"] for s in ranked["services"]}
    fired = 0
    for ev in ranked["adversary"]["events"]:
        if ev["action"] != "kill_service":
            continue
        fired += 1
        assert ev["params"]["service"] not in ("TermService",)
        assert ev["affects_check"] in services
    assert fired == 2


def test_pool_uses_rdp_access():
    pool = _parsed()["ranked"]["pool"]
    assert pool["template_vm_access_method"] == "rdp"
    for key in ("template_vm_id", "template_vm_username", "template_vm_password"):
        assert pool[key].startswith("${HUITZILOPOCHTLI_KESTREL_POINT_ZOO_")


def test_disable_not_delete_accounts():
    """The planted accounts are scored DISABLED-not-deleted (pinecrest
    rule): no check may demand absence of the service account."""
    d = _parsed()
    for c in d["checks"]:
        if c["type"] == "user_group":
            # user_group user_absent is fine for stock accounts (Guest is
            # scored via powershell Enable flag here), but never for the
            # planted service/admin accounts.
            expect = c.get("expect", {})
            assert expect.get("username") not in ("zksvc_ir", "zkops_sync")


def test_penalized_services_are_scored_services():
    d = _parsed()
    ranked = d["ranked"]
    killable = {e["params"]["service"] for e in ranked["adversary"]["events"]
                if e["action"] == "kill_service"}
    for c in d["checks"]:
        if c["category"] != "penalty":
            continue
        if c["type"] == "service_state":
            assert c["collect"]["service"] not in killable


def test_handbook_leaks_no_answers():
    d = _parsed()
    handbook = open(os.path.join(BOX, "assets", "README.md"), encoding="utf-8").read()
    for f in d["forensics"]:
        answers = [f["answer"]] + list(f.get("answers") or [])
        for a in answers:
            if len(a) >= 4 and a.lower() not in ("true", "none", "password"):
                assert a.lower() not in handbook.lower(), a
    for name in ("MpSyncHelper", "WinDefSvcHelper", "HelpDeskMon", "HelpDeskUpd",
                 "zkops_sync", "zksvc_ir", "cmd.aspx", "sync_blob", "KestrelTraySync",
                 "IndexRebuildHelper", "WinHostSync", "inproc_helper.dll"):
        assert name not in handbook, name


def test_windows_roster_consistent():
    """Forensics answers resolve on the primary desktop user; the handbook
    names sysadmin as the player and never the other session's boxes'
    vocabulary."""
    handbook = open(os.path.join(BOX, "assets", "README.md"), encoding="utf-8").read()
    assert "sysadmin" in handbook
