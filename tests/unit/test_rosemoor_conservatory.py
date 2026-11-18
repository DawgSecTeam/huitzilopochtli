"""Rosemoor Conservatory regression checks.

Box-specific invariants: the ledger's arithmetic, the ranked service /
adversary safety rules (kills must target recoverable services only --
never the SSH daemon the responders are using), the no-SUID plant rule,
and the handbook spoiler guard.
"""
import os
import re

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX = os.path.join(REPO, "boxes", "rosemoor-conservatory")


def _parsed():
    with open(os.path.join(BOX, "scenario.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _nakon():
    import json

    with open(os.path.join(BOX, "nakon.json"), encoding="utf-8") as f:
        return json.load(f)


def test_ledger_arithmetic():
    """6x5 + 20x10 + 9x20 hardening + forensics 3x4 + 5x8 + 2x12 = 486 static."""
    d = _parsed()
    vuln = [c for c in d["checks"] if c["category"] == "vuln"]
    assert len(vuln) == 35
    assert sum(1 for c in vuln if c["max_points"] == 5) == 6
    assert sum(1 for c in vuln if c["max_points"] == 10) == 20
    assert sum(1 for c in vuln if c["max_points"] == 20) == 9
    penalties = [c for c in d["checks"] if c["category"] == "penalty"]
    assert {c["id"] for c in penalties} == {"penalty_sshd_running"}
    assert len(d["forensics"]) == 10
    total = sum(c["max_points"] for c in vuln) + sum(f["points"] for f in d["forensics"])
    assert total == 486


def test_answer_key_has_no_gaps():
    d = _parsed()
    missing = [c["id"] for c in d["checks"] if not (c.get("solution") or "").strip()]
    missing += [f["id"] for f in d["forensics"] if not (f.get("solution") or "").strip()]
    assert not missing, missing


def test_ranked_services_are_the_glasshouse():
    ranked = _parsed()["ranked"]
    services = {s["id"]: s for s in ranked["services"]}
    assert set(services) == {"glassboard", "mariadb", "cache", "ssh"}
    assert services["glassboard"]["type"] == "http_uptime"
    assert services["glassboard"]["collect"]["url"] == "http://127.0.0.1:8080/"
    assert services["mariadb"]["collect"]["port"] == 3306
    assert services["cache"]["collect"]["port"] == 6379
    assert services["ssh"]["collect"]["port"] == 22


def test_adversary_kills_only_recoverable_services():
    """Never the SSH daemon (bricks the responders' own channel) and
    nothing whose check rewards stopping it."""
    ranked = _parsed()["ranked"]
    services = {s["id"] for s in ranked["services"]}
    fired = 0
    for ev in ranked["adversary"]["events"]:
        if ev["action"] != "kill_service":
            continue
        fired += 1
        assert ev["params"]["service"] not in ("ssh", "sshd")
        assert ev["affects_check"] in services
    assert fired == 3


def test_no_suid_plants():
    """House rule (practice-box design preferences): no SUID configs."""
    names = [c["name"] for m in _nakon()["machines"] for c in m["configurations"]]
    assert not [n for n in names if n.startswith("suid-")]


def test_penalized_services_are_scored_services():
    """A penalty must guard something the handbook calls a critical
    service, and the adversary must never be able to trigger it."""
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
    # planted artifact names must not leak either (spot list, lint covers the rest)
    for name in ("glasshouse-sync", "95-glasshouse-helpers", "journal-maintenance",
                 "sync-fetch", "attacker@botforge", "svc-daemon", "nightbloom"):
        assert name not in handbook, name


def test_roster_consistent_between_handbook_and_checks():
    """The player account the forensics path uses must be the handbook's
    admin user."""
    d = _parsed()
    handbook = open(os.path.join(BOX, "assets", "README.md"), encoding="utf-8").read()
    paths = [f.get("path") for f in d["forensics"] if f.get("path")]
    assert paths and all("/home/gardener/Desktop/" in p for p in paths)
    assert "gardener" in handbook and "sysadmin" not in handbook
