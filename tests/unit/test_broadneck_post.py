"""Broadneck Post regression checks pinned by the live Blue Team Ladder.

The generic corpus contract covers layout and compilation; these are the
box-specific invariants the first live field exposed.
"""
import os

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCENARIO = os.path.join(REPO, "boxes", "broadneck-post", "scenario.yaml")


def _parsed():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_cold_start_probes_have_timeout_headroom():
    """A cold postfix pays ~7s of TLS/DH init before it answers.

    The default 5s check budget turns that into a false negative. The SMTP
    greeting, submission handshake, and domain/doveadm probe must all have
    at least 15 seconds.
    """
    checks = {c["id"]: c for c in _parsed()["checks"]}
    for check_id in ("smtp_listener_answers", "submission_auth_required",
                     "local_domain_configured"):
        assert checks[check_id].get("timeout_s", 5.0) >= 15, check_id


def test_ranked_services_are_the_four_mail_doors():
    """The ranked target scores the four doors the sabotage shut."""
    ranked = _parsed()["ranked"]
    services = {s["id"]: s for s in ranked["services"]}
    assert set(services) == {"smtp", "submission", "imaps", "pop3s"}
    assert {s["collect"]["port"] for s in services.values()} == {25, 587, 993, 995}
    assert all(s["type"] == "tcp_port" for s in services.values())


def test_guess_count_matches_the_replay():
    """The failed-login ledger and its forensics answer cannot drift."""
    replay = open(os.path.join(
        REPO, "boxes", "broadneck-post", "assets", "prep",
        "80-redtag-replay.py"), encoding="utf-8").read()
    block = replay[replay.index("attempts = ["):]
    block = block[:block.index("]") + 1]
    failures = block.count(", False")
    assert failures == 4, block
    fq = next(q for q in _parsed()["forensics"] if q["id"] == "fq-guess-count")
    assert str(fq["answer"]) == str(failures)
