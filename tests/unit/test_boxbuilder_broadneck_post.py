"""Regression coverage for the Broadneck Post box.

The mail-flavored blue-team box: headless Debian 13, postfix + dovecot
SABOTAGED on the way out by an intruder ("redtag", documentation IP
198.51.100.23) who relay-blasted the open relay, planted interception
(.forward + aliases pipe backdoor + mailbox tarball), then deleted the
mail configuration, the certs, and the logs. THIRTY-EIGHT scored checks
-- bring-up from scratch (9) + postfix hardening (11) + dovecot
hardening (7) + red-path cleanup (11), difficulty-weighted (EASY=2 x16,
MODERATE=4 x15, HARD=6 x7 = 134), NO penalties, and a 20-question
forensics block (6x2 + 10x4 + 4x6 = 76; 210 grand total). What these
tests pin:

- the ledger itself (check count, tier/points agreement, the forensics
  split) -- the ledger IS the contract with the students;
- every command_json script actually runs and emits exactly one JSON
  scalar, and the CLEAN-HOST branch is the hardened one -- EXCEPT the
  bring-up/liveness checks, which legitimately read false on a dev host
  with no mail stack (they are pinned separately to emit booleans);
- the plant<->check pairing discipline (every planted path/name must
  byte-match between nakon.json vars and the scenario collect params,
  and every prep-baked artifact must byte-match between the prep scripts
  and the scenario -- nothing cross-checks them at build time);
- matcher pass/reject pairs for every check's hardened vs planted state;
- the prep stack is complete on disk and the load-bearing ordering
  invariants hold (rotation before sabotage; the sabotage verifies the
  exactly-one-held post-state).
"""
import json
import os
import re
import subprocess

import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from boxbuilder.spec import load_spec
from common.matchers import evaluate_matcher


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "broadneck-post")
SCENARIO = os.path.join(BOX_DIR, "scenario.yaml")
BOX = os.path.join(BOX_DIR, "box.yaml")
NAKON = os.path.join(BOX_DIR, "nakon.json")
SEEDS = os.path.join(REPO_ROOT, "boxbuilder", "vulndb_vuln_configs")
PREP = os.path.join(BOX_DIR, "assets", "prep")

CHECK_COUNT = 38          # all vuln; this box has NO penalties
VULN_POINTS = 134
FORENSICS_COUNT = 20
FORENSICS_POINTS = 76     # 6x2 + 10x4 + 4x6
TOTAL_POINTS = VULN_POINTS + FORENSICS_POINTS  # 210
TIER_POINTS = {"EASY": 2, "MODERATE": 4, "HARD": 6}
TIER_COUNTS = {"EASY": 16, "MODERATE": 15, "HARD": 7}

BUNDLED_SEEDS = [
    "authorized-keys-persistence", "cron-d-persistence",
    "systemd-timer-persistence", "systemd-service", "sudoers-rule",
    "backdoor-firewall-rule", "local-user", "apt-service-install",
]

VULN_CHECK_IDS = {
    # bring-up from scratch (EASY x5, MODERATE x3, HARD x1)
    "postfix_config_restored", "dovecot_config_restored",
    "postfix_service_up", "dovecot_service_up", "smtp_listener_answers",
    "imap_tls_listener_up", "pop3_tls_listener_up",
    "submission_listener_up", "submission_auth_required",
    # postfix hardening (EASY x5, MODERATE x4, HARD x2)
    "open_relay_closed", "mynetworks_tightened", "vrfy_disabled",
    "helo_required", "banner_no_version", "tls_auth_only",
    "postfix_tls_cert_configured", "postfix_key_perms",
    "postfix_config_perms", "aliases_pipe_backdoor_removed",
    "forward_interception_removed",
    # dovecot hardening (EASY x1, MODERATE x5, HARD x1)
    "dovecot_plaintext_auth_off", "dovecot_ssl_required",
    "dovecot_plain_listeners_off", "dovecot_tls_cert_configured",
    "maildir_perms_fixed", "local_domain_configured",
    "mailboxes_deliverable",
    # red-path cleanup (EASY x6, MODERATE x3, HARD x3)
    "routeaudit_disabled", "mailsync_removed", "authorized_keys_clean",
    "queue_tidy_cron_removed", "harvest_timer_neutralized",
    "metrics_service_removed", "sudoers_dropin_removed",
    "firewall_rule_removed", "swaks_uninstalled", "restore_kit_removed",
    "mailroom_export_removed",
}
assert len(VULN_CHECK_IDS) == CHECK_COUNT

FORENSIC_IDS = {
    "fq-entry-account", "fq-first-probe", "fq-source-ip", "fq-relay-count",
    "fq-relay-domain", "fq-relay-sender", "fq-lure-recipient",
    "fq-held-origin", "fq-export-archive", "fq-export-victim",
    "fq-forward-destination", "fq-alias-name", "fq-alias-payload",
    "fq-wiper-file", "fq-wiper-cadence", "fq-swaks-tool",
    "fq-restore-kit", "fq-restore-backdoor", "fq-timer-cadence",
    "fq-btmp-attempts",
}
assert len(FORENSIC_IDS) == FORENSICS_COUNT

# command_json checks that legitimately read FALSE on a clean dev host
# (no mail stack installed/configured there). Everything else must emit
# the hardened `true` when run on an unplanted, unprivileged host.
STATE_CHECK_IDS = {
    "postfix_config_restored", "dovecot_config_restored",
    "postfix_service_up", "dovecot_service_up", "smtp_listener_answers",
    "submission_auth_required", "local_domain_configured",
    "mailboxes_deliverable",
}

# Planted artifact <-> check couplings: every (needle, where it must
# appear) pair, taken from nakon.json vars / prep scripts and mirrored in
# scenario.yaml.
COUPLINGS = {
    "authorized_keys_clean": ["redtag@198.51.100.23",
                              "/home/postmaster/.ssh/authorized_keys"],
    "queue_tidy_cron_removed": ["/etc/cron.d/queue-tidy",
                                "/opt/redtag/queue-tidy"],
    "harvest_timer_neutralized": ["redtag-harvest.timer",
                                  "/opt/redtag/harvest"],
    "metrics_service_removed": ["smtpd-metrics",
                                "/opt/redtag/.metrics-snap"],
    "sudoers_dropin_removed": ["/etc/sudoers.d/routeaudit-recovery"],
    "firewall_rule_removed": ["198.51.100.23"],
    "mailsync_removed": ["mailsync"],
    "swaks_uninstalled": ["swaks"],
    "aliases_pipe_backdoor_removed": ["routesupport",
                                      "/usr/local/libexec/.queue-flush",
                                      "/etc/aliases"],
    "forward_interception_removed": ["/home/postmaster/.forward"],
    "restore_kit_removed": ["/root/.mail-restore"],
    "mailroom_export_removed": ["mailroom-export-2026-10-17.tar.gz"],
    "routeaudit_disabled": ["routeaudit"],
    "maildir_perms_fixed": ["/home/dispatch/Maildir"],
}

# Prep-baked artifacts <-> scenario pairings: the needle must appear in
# the named prep file AND in the check/fq's authored content.
PREP_FILES = [
    "prep-notes.md", "01-packages.sh", "02-accounts.sh", "03-mailstack.sh",
    "seed-mail.py", "80-redtag-replay.py", "85-rotate-logs.sh",
    "90-sabotage.sh",
]
PREP_COUPLINGS = {
    # (needle, prep file, scenario location kind)
    ("mailroom-export-2026-10-17.tar.gz", "80-redtag-replay.py", "check"),
    ("redtag.chute@mailchute.top", "80-redtag-replay.py", "forensic"),
    ("routesupport", "80-redtag-replay.py", "check"),
    ("/usr/local/libexec/.queue-flush", "80-redtag-replay.py", "check"),
    ("route.slips@postal-audit.example", "90-sabotage.sh", "forensic"),
    ("/root/.mail-restore", "90-sabotage.sh", "check"),
    ("glittercrate.buzz", "80-redtag-replay.py", "forensic"),
    ("promo@glittercrate.buzz", "80-redtag-replay.py", "forensic"),
    ("198.51.100.23", "80-redtag-replay.py", "forensic"),
}

HANDBOOK = os.path.join(BOX_DIR, "assets", "README.md")


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_nakon():
    with open(NAKON, encoding="utf-8") as f:
        return json.load(f)


def _matcher(check):
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_broadneck_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, SCENARIO) == []
    checks = parsed["checks"]
    assert len(checks) == CHECK_COUNT
    assert {c["id"] for c in checks} == VULN_CHECK_IDS
    assert all(c["category"] == "vuln" for c in checks), (
        "this box has no penalties: the stack starts DOWN, the bring-up "
        "checks are their own drift guard")
    assert sum(c["max_points"] for c in checks) == VULN_POINTS
    forensics = parsed["forensics"]
    assert len(forensics) == FORENSICS_COUNT
    assert {fq["id"] for fq in forensics} == FORENSIC_IDS
    assert sum(fq["points"] for fq in forensics) == FORENSICS_POINTS
    assert VULN_POINTS + FORENSICS_POINTS == TOTAL_POINTS
    assert not ({fq["id"] for fq in forensics} & {c["id"] for c in checks})
    # every finding and question carries an authored walkthrough so the
    # post-event answer key renders with zero gaps
    assert all(c.get("solution", "").strip() for c in checks)
    assert all(str(fq.get("solution", "")).strip() for fq in forensics)

    from common.crypto import signing
    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    assert outputs["readme_warnings"] == [], outputs["readme_warnings"]
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Broadneck Post"
    assert manifest["theme"]["readme_text"].startswith("# Broadneck Post")
    assert manifest["theme"]["logo_b64"] is None
    # the manifest carries the questions but never their answers
    assert len(manifest["forensics"]) == FORENSICS_COUNT
    assert not any("answer" in json.dumps(f) for f in manifest["forensics"])
    # neither the signed manifest nor the rubric may carry authored solutions
    assert not any(c.get("solution") for c in manifest["checks"])
    rubric = json.load(open(outputs["rubric"], encoding="utf-8"))
    assert not any("solution" in json.dumps(e) for e in rubric.get("entries", []))


def test_broadneck_difficulty_tiers_match_points():
    """Display tier prefix, max_points, and expect.points must all agree
    at the 2/4/6 scale; tier counts pin the 16/15/7 ledger."""
    tier_seen = {"EASY": 0, "MODERATE": 0, "HARD": 0}
    for check in _load_scenario()["checks"]:
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


def test_broadneck_forensics_tiers_match_2_4_6():
    counts = {2: 0, 4: 0, 6: 0}
    for fq in _load_scenario()["forensics"]:
        assert fq["points"] in counts, (
            f"{fq['id']}: forensics points must be 2/4/6, got {fq['points']}"
        )
        counts[fq["points"]] += 1
    assert counts == {2: 6, 4: 10, 6: 4}, counts  # 6x2 + 10x4 + 4x6
    assert sum(k * v for k, v in counts.items()) == FORENSICS_POINTS


def test_broadneck_command_json_scripts_emit_valid_json():
    """Every command_json script is read-only and emits exactly one JSON
    scalar. Run each on a clean (unplanted, unprivileged) host: plant
    guards short-circuit to the hardened `true`, and the bring-up/liveness
    checks (STATE_CHECK_IDS) legitimately read false with no mail stack
    installed -- either way the contract is one boolean, nothing else."""
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
        if check["id"] not in STATE_CHECK_IDS:
            assert parsed is True, (
                f"{check['id']}: unplanted host should already be hardened"
            )


def test_broadneck_plant_vars_match_paired_checks():
    """The pairing discipline: every planted path/name in nakon.json vars
    must appear byte-identical in the paired check's collect/expect."""
    checks = {c["id"]: c for c in _load_scenario()["checks"]}
    nakon = _load_nakon()
    machines = nakon["machines"]
    assert len(machines) == 1
    cfgs = machines[0]["configurations"]
    assert len(cfgs) == len(BUNDLED_SEEDS)

    names = [c["name"] for c in cfgs]
    for seed in BUNDLED_SEEDS:
        assert seed in names, f"{seed} missing from nakon.json"

    def var_entries(name):
        return [c["vars"] for c in cfgs if c["name"] == name]

    keys = var_entries("authorized-keys-persistence")[0]
    assert keys["USERNAME"] == "postmaster"
    assert keys["PUBLIC_KEY"].split()[-1] == "redtag@198.51.100.23"
    assert "redtag@198.51.100.23" in yaml.safe_dump(
        checks["authorized_keys_clean"]["collect"])

    cron = var_entries("cron-d-persistence")[0]
    assert cron["CRON_FILE"] == "queue-tidy"
    assert cron["PAYLOAD_PATH"] == "/opt/redtag/queue-tidy"
    assert cron["SCHEDULE"] == "* * * * *"
    assert "/var/log/mail.log" in cron["PAYLOAD_BODY"]

    timer = var_entries("systemd-timer-persistence")[0]
    assert timer["TIMER_NAME"] == "redtag-harvest"
    assert timer["ON_UNIT_ACTIVE_SEC"] == "20min"
    assert timer["PAYLOAD_PATH"] == "/opt/redtag/harvest"

    svc = var_entries("systemd-service")[0]
    assert svc["SERVICE_NAME"] == "smtpd-metrics"
    assert svc["PAYLOAD_PATH"] == "/opt/redtag/.metrics-snap"

    sudoers = var_entries("sudoers-rule")[0]
    assert sudoers["DROPIN_NAME"] == "routeaudit-recovery"
    assert sudoers["RULE"].startswith("routeaudit ")

    fw = var_entries("backdoor-firewall-rule")[0]
    assert fw["SOURCE_IP"] == "198.51.100.23"
    assert fw["DST_PORT"] == "25"

    user = var_entries("local-user")[0]
    assert user["USERNAME"] == "mailsync"

    pkg = var_entries("apt-service-install")[0]
    assert pkg["PACKAGES"] == "swaks"

    # string couplings: substring must live in both the plant and the
    # check's collect/expect params
    for cid, needles in COUPLINGS.items():
        blob = yaml.safe_dump(
            {"collect": checks[cid]["collect"],
             "expect": {k: v for k, v in checks[cid]["expect"].items()
                        if k != "points"}})
        for needle in needles:
            assert needle in blob, (
                f"{cid}: scenario must reference {needle!r}"
            )


def test_broadneck_prep_artifacts_match_scenario():
    """Prep-baked artifacts pair with checks/forensics too: every needle
    must appear byte-identical in its prep script and in the scenario."""
    scenario_text = open(SCENARIO, encoding="utf-8").read()
    for needle, prep_file, kind in PREP_COUPLINGS:
        prep_path = os.path.join(PREP, prep_file)
        assert os.path.isfile(prep_path), f"prep asset missing: {prep_file}"
        assert needle in open(prep_path, encoding="utf-8").read(), (
            f"{prep_file} must contain {needle!r}"
        )
        assert needle in scenario_text, (
            f"scenario ({kind}) must reference {needle!r}"
        )


def test_broadneck_prep_ordering_invariants_hold():
    """The load-bearing prep ordering is written into the scripts: the
    rotation (85) must run BEFORE the sabotage (90) and archive exactly
    the blast count the forensics answer pins; the sabotage must verify
    its exactly-one-held post-state and mask both units."""
    rotate = open(os.path.join(PREP, "85-rotate-logs.sh"), encoding="utf-8").read()
    assert "grep -c '198.51.100.23'" in rotate
    assert '"$COUNT" -ne 40' in rotate, (
        "rotation must verify the blast count the forensics answer pins"
    )
    sabotage = open(os.path.join(PREP, "90-sabotage.sh"), encoding="utf-8").read()
    assert sabotage.index("postsuper -d ALL") < sabotage.index(
        "postsuper -h ALL"), "clear-before-hold ordering broken"
    assert "postsuper -h ALL" in sabotage
    assert '"$HELD" -eq 1' in sabotage, (
        "sabotage must verify exactly one held message"
    )
    for unit in ("postfix", "dovecot"):
        assert f"mask {unit}" in sabotage or f"mask postfix dovecot" in sabotage
    assert "rm -rf /etc/postfix /etc/dovecot /etc/ssl/depot-mail" in sabotage
    # the rotation copy must never be WRITTEN by the wiper or the sabotage
    # (the sabotage may verify it survived -- the intruder just misses it)
    for line in sabotage.splitlines():
        if "truncate" in line:
            assert "mail.log.1" not in line, (
                f"the wiper/sabotage must only touch the live log: {line}"
            )
    assert "/var/log/mail.log.1" not in _load_nakon()["machines"][0][
        "configurations"][1]["vars"]["PAYLOAD_BODY"]
    wiper = _load_nakon()["machines"][0]["configurations"][1]
    assert wiper["name"] == "cron-d-persistence"
    assert "mail.log.1" not in wiper["vars"]["PAYLOAD_BODY"], (
        "the wiper must only ever name the live mail.log"
    )


def test_broadneck_pairings_score_secure_states_and_reject_planted_states():
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

    # bring-up/liveness checks: the UP state scores, DOWN does not
    for cid in ("postfix_service_up", "dovecot_service_up",
                "smtp_listener_answers", "submission_auth_required",
                "postfix_config_restored", "dovecot_config_restored",
                "mailboxes_deliverable", "local_domain_configured"):
        check = by_id[cid]
        assert check["type"] == "command_json"
        up, reason = evaluate_matcher(
            _matcher(check), {"data": True, "text": "true"})
        assert up, f"{cid}: {reason}"
        down, reason = evaluate_matcher(
            _matcher(check), {"data": False, "text": "false"})
        assert not down, f"{cid}: {reason}"

    # tcp_port listeners: open scores, closed does not
    for cid, port in (("imap_tls_listener_up", 993),
                      ("pop3_tls_listener_up", 995),
                      ("submission_listener_up", 587)):
        check = by_id[cid]
        assert check["type"] == "tcp_port"
        assert check["collect"]["port"] == port
        secure, reason = evaluate_matcher(
            _matcher(check), {"open": True, "error": None})
        assert secure, reason
        planted, reason = evaluate_matcher(
            _matcher(check), {"open": False, "error": "refused"})
        assert not planted, reason

    # permission deletion findings: gone from disk is the hardened state
    for cid in ("forward_interception_removed", "sudoers_dropin_removed",
                "restore_kit_removed", "mailroom_export_removed"):
        check = by_id[cid]
        assert check["type"] == "permission"
        assert check["expect"]["field"] == "exists"
        secure, reason = evaluate_matcher(
            _matcher(check), {"exists": False, "mode": None})
        assert secure, reason
        planted, reason = evaluate_matcher(
            _matcher(check), {"exists": True, "mode": "0644"})
        assert not planted, reason

    # permission mode finding: the Maildir must EXIST and be tightened
    # (deletion must NOT pass: the mailbox is the deliverable)
    check = by_id["maildir_perms_fixed"]
    assert check["type"] == "permission"
    broken, reason = evaluate_matcher(
        _matcher(check), {"exists": False, "mode": None})
    assert not broken, f"maildir_perms_fixed: deletion must NOT pass: {reason}"
    planted, reason = evaluate_matcher(
        _matcher(check), {"exists": True, "mode": "0755"})
    assert not planted, reason
    secure, reason = evaluate_matcher(
        _matcher(check), {"exists": True, "mode": "0750"})
    assert secure, reason

    # user_group: mailsync absent is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(by_id["mailsync_removed"]), {"users": ["postmaster"]})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(by_id["mailsync_removed"]),
        {"users": ["postmaster", "mailsync"]})
    assert not planted, reason

    # package: the blasting tool uninstalled is the hardened state
    secure, reason = evaluate_matcher(
        _matcher(by_id["swaks_uninstalled"]), {"installed": False})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(by_id["swaks_uninstalled"]), {"installed": True})
    assert not planted, reason


def test_broadneck_forensics_block_walks_the_incident():
    """Questions name evidence classes, never answers; every question is
    pinned to the postmaster's Desktop file; points are 2/4/6."""
    forensics = _load_scenario()["forensics"]
    paths = {fq.get("path") for fq in forensics}
    assert paths == {"/home/postmaster/Desktop/Forensics-Questions.txt"}
    for fq in forensics:
        assert fq["points"] in (2, 4, 6)
        assert fq.get("answer") or fq.get("answers")
        # the question text may not hand over a specific answer (short
        # ordinary answers like "40" are exempt -- the compile lint
        # enforces the real rule against the handbook)
        values = [str(fq["answer"])] + [
            str(a) for a in (fq.get("answers") or [])]
        for value in values:
            if len(value) >= 6:
                assert value.lower() not in fq["question"].lower(), (
                    f"{fq['id']}: question leaks its own answer {value!r}"
                )


def test_broadneck_handbook_stays_on_the_right_side_of_the_bar():
    """The handbook is the assignment, not the answer key: no planted
    artifact names, no forensics answers beyond the lint-allowlisted
    roster words, no mutation commands."""
    text = open(HANDBOOK, encoding="utf-8").read().lower()
    forbidden = [
        "redtag", "routeaudit", "mailsync", "swaks", "queue-tidy",
        "redtag-harvest", "smtpd-metrics", "glittercrate", "mailchute",
        "mail-restore", "queue-flush", "routesupport", "198.51.100.23",
        "mailroom-export", "mynetworks", "unauth_destination",
        "disable_vrfy", "reject_relay", "bigmail.example",
        "postal-audit.example",
    ]
    for word in forbidden:
        assert word not in text, f"handbook leaks {word!r}"
    # the roster IS allowed (and lint-allowlisted): the answers that
    # collide with it are handled by theme.readme_lint_allow
    for allowed in ("postmaster", "dispatch", "routes", "freight"):
        assert allowed in text
    # no mutation commands in code spans/fences -- the handbook has no
    # code blocks beyond `huitz` usage
    for mutation in ("systemctl disable", "systemctl mask", "chmod ",
                     "userdel", "postconf -e", "apt-get remove",
                     "iptables -d", "truncate "):
        assert mutation not in text, f"handbook carries a mutation: {mutation!r}"


def test_broadneck_box_and_nakon_inputs_resolve():
    spec = load_spec(BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Broadneck Post"

    for name in PREP_FILES:
        assert os.path.isfile(os.path.join(PREP, name)), (
            f"prep asset missing: {name}"
        )


def test_broadneck_bundled_seeds_are_clean_and_generic():
    """Every bundled seed this box uses is present on disk, linux-only,
    and shell-syntax-clean in its templated form."""
    for name in BUNDLED_SEEDS:
        seed = json.load(open(os.path.join(SEEDS, f"{name}.json"),
                              encoding="utf-8"))
        assert seed["name"] == name
        assert seed["platform"] == "linux"
