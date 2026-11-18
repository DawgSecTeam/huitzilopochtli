"""Tamarack Regional Airport regression checks.

The generic corpus contract (test_boxes_contract.py) covers layout and
compilation; these are the box-specific invariants: the ledger's
arithmetic, the ranked service/adversary safety rules (no firewall flush
on a box whose firewall finding is a planted ACCEPT rule), and the
replay <-> forensics pinning the guessing ledger depends on.
"""
import os
import re

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX = os.path.join(REPO, "boxes", "tamarack-airport")


def _parsed():
    with open(os.path.join(BOX, "scenario.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def _nakon():
    with open(os.path.join(BOX, "nakon.json"), encoding="utf-8") as f:
        return __import__("json").load(f)


def test_ledger_arithmetic():
    """11x5 + 15x10 + 2x20 hardening + 12x10 forensics = 365 static."""
    d = _parsed()
    vuln = [c for c in d["checks"] if c["category"] == "vuln"]
    assert len(vuln) == 28
    assert sum(1 for c in vuln if c["max_points"] == 5) == 11
    assert sum(1 for c in vuln if c["max_points"] == 10) == 15
    assert sum(1 for c in vuln if c["max_points"] == 20) == 2
    assert len(d["forensics"]) == 12
    assert all(f["points"] == 10 for f in d["forensics"])
    total = sum(c["max_points"] for c in vuln) + sum(f["points"] for f in d["forensics"])
    assert total == 365


def test_answer_key_has_no_gaps():
    """Every check and forensics question carries a solution walkthrough."""
    d = _parsed()
    missing = [c["id"] for c in d["checks"] if not (c.get("solution") or "").strip()]
    missing += [f["id"] for f in d["forensics"] if not (f.get("solution") or "").strip()]
    assert not missing, missing


def test_ranked_services_are_the_display_stack():
    ranked = _parsed()["ranked"]
    services = {s["id"]: s for s in ranked["services"]}
    assert set(services) == {"portal", "ops", "sched-db", "boards"}
    assert services["portal"]["type"] == "http_uptime"
    assert services["portal"]["collect"]["url"] == "http://127.0.0.1/"
    assert services["ops"]["collect"]["port"] == 22
    assert services["sched-db"]["type"] == "db_query"
    assert services["sched-db"]["collect"]["port"] == 5432  # first PostgreSQL SLA
    assert services["boards"]["collect"]["port"] == 6379


def test_adversary_never_flushes_the_firewall():
    """A planted iptables ACCEPT rule makes `flush_firewall` award free
    points: the whole ruleset (finding included) dies at once. This box
    must only ever kill recoverable services."""
    events = _parsed()["ranked"]["adversary"]["events"]
    actions = {e["action"] for e in events}
    assert "flush_firewall" not in actions
    kills = sorted(e["params"]["service"] for e in events if e["action"] == "kill_service")
    assert kills == ["nginx", "redis-server"]


def test_adversary_windows_are_ordered_and_sane():
    events = _parsed()["ranked"]["adversary"]["events"]
    windows = [tuple(e["window_s"]) for e in events]
    assert windows == sorted(windows)
    assert all(300 <= lo < hi <= 5400 for lo, hi in windows)
    for e in events:
        if e["action"] == "kill_service":
            assert e["affects_check"] in {s["id"] for s in _parsed()["ranked"]["services"]}


def test_guess_count_matches_the_replay():
    """The failed-login ledger and its forensics answer cannot drift."""
    replay = open(os.path.join(BOX, "assets", "prep", "85-skylark-replay.py"),
                  encoding="utf-8").read()
    block = replay[replay.index("attempts = ["):]
    block = block[:block.index("]") + 1]
    failures = block.count(", False")
    assert failures == 4, block
    fq = next(q for q in _parsed()["forensics"] if q["id"] == "fq-guess-count")
    assert str(fq["answer"]) == str(failures)


def test_intruder_address_agrees_across_the_incident():
    """One address in the journal story, the key comment, the firewall
    rule, the hosts redirect, and the bashrc filter."""
    ip = "203.0.113.44"
    scenario = open(os.path.join(BOX, "scenario.yaml"), encoding="utf-8").read()
    nakon = _nakon()
    fq = {q["id"]: q for q in _parsed()["forensics"]}
    assert str(fq["fq-source-ip"]["answer"]) == ip

    def cfg(name):
        for c in nakon["machines"][0]["configurations"]:
            if isinstance(c, dict) and c["name"] == name:
                return c["vars"]
        return None

    assert cfg("backdoor-firewall-rule")["SOURCE_IP"] == ip
    assert ip in cfg("hosts-redirect-linux")["IP"]
    assert ip in cfg("bashrc-command-hijack")["SCANNER_IP"]
    assert ip in cfg("authorized-keys-persistence")["PUBLIC_KEY"].split()[-1]
    assert "203\\.0\\.113\\.44" in scenario  # the checks grade the same address


def test_pool_placeholders_follow_the_box_slug():
    """The contract test seeds HUITZILOPOCHTLI_<DIR>_POOL_TEMPLATE_*; the
    committed placeholders must expand from exactly those names."""
    pool = _parsed()["ranked"]["pool"]
    assert pool["template_vm_id"] == "${HUITZILOPOCHTLI_TAMARACK_AIRPORT_POOL_TEMPLATE_VM_ID}"
    assert pool["template_vm_username"] == "${HUITZILOPOCHTLI_TAMARACK_AIRPORT_POOL_TEMPLATE_USER}"
    assert pool["template_vm_password"] == "${HUITZILOPOCHTLI_TAMARACK_AIRPORT_POOL_TEMPLATE_PASSWORD}"
    assert pool["template_vm_access_method"] == "ssh"


def test_respawn_password_matches_prep():
    """The respawn machinery re-asserts the account the replay guesses;
    prep and nakon must agree on the password."""
    nakon = _nakon()

    def cfg(name):
        for c in nakon["machines"][0]["configurations"]:
            if isinstance(c, dict) and c["name"] == name:
                return c["vars"]
        return None

    assert cfg("priv-user-respawn-service") == {
        "USERNAME": "fieldsvc", "PASSWORD": "SkylarkField22!"}
    prep = open(os.path.join(BOX, "assets", "prep", "01-accounts.sh"),
                encoding="utf-8").read()
    assert "fieldsvc:SkylarkField22!" in prep
