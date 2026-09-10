"""Regression coverage for the themed Kalypso Deep Marine Research Station box."""
import json
import os
import re

import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from boxbuilder.spec import load_spec
from common.crypto import signing
from common.matchers import evaluate_matcher


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOX_DIR = os.path.join(REPO_ROOT, "boxes", "coral-reef-station")
SCENARIO = os.path.join(BOX_DIR, "scenario.yaml")
BOX = os.path.join(BOX_DIR, "box.yaml")
NAKON = os.path.join(BOX_DIR, "nakon.json")

CHECK_COUNT = 23
TOTAL_POINTS = 230


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _matcher(check):
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_coral_reef_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, SCENARIO) == []
    assert len(parsed["checks"]) == CHECK_COUNT
    assert len({check["id"] for check in parsed["checks"]}) == CHECK_COUNT
    assert sum(check["max_points"] for check in parsed["checks"]) == TOTAL_POINTS

    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Kalypso Deep Marine Research Station"
    assert manifest["theme"]["logo_b64"]


def test_coral_reef_box_and_nakon_inputs_resolve():
    spec = load_spec(BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Kalypso Deep Marine Research Station"

    with open(NAKON, encoding="utf-8") as f:
        machines = json.load(f)["machines"]
    assert len(machines) == 1
    requested = machines[0]["configurations"]
    names = [item if isinstance(item, str) else item["name"] for item in requested]
    # Generic, reusable seeds instantiated multiple times with different vars.
    assert names.count("loosen-file-mode") == 2
    assert names.count("insecure-file-mode") == 2
    assert names.count("local-user") == 3
    assert names.count("systemd-service") == 4
    for name in (
        "uid0-user", "user-login-shell", "user-sudo-nopasswd", "pam-permit-auth",
        "apache-site", "ssh-root-login",
    ):
        assert name in names


def test_coral_reef_file_regex_extracts_have_capturing_groups():
    """The file_regex collector REQUIRES a capturing group in `extract`
    (it reports the group text as evidence and errors on `groups < 1`); an
    ungrouped pattern makes the check unpassable (see the solar 150 round)."""
    for check in _load_scenario()["checks"]:
        if check["type"] != "file_regex":
            continue
        pattern = check["collect"]["extract"]
        compiled = re.compile(pattern)  # raises on an invalid pattern
        assert compiled.groups >= 1, (
            f"{check['id']}: file_regex extract {pattern!r} has no capturing "
            "group; the collector would error on every run"
        )


def test_coral_reef_scenario_nakon_names_agree():
    """Nothing cross-validates the two halves: every FILE_PATH / SERVICE_NAME /
    USERNAME planted by nakon.json must be byte-identical to its paired
    check's collect.path / service / username, and vice versa."""
    checks = {check["id"]: check for check in _load_scenario()["checks"]}
    with open(NAKON, encoding="utf-8") as f:
        configs = json.load(f)["machines"][0]["configurations"]

    planted_paths, planted_services, planted_users = set(), set(), set()
    for item in configs:
        if isinstance(item, str):
            continue
        name, vars_ = item["name"], item.get("vars", {})
        if name in ("insecure-file-mode", "loosen-file-mode"):
            planted_paths.add(vars_["FILE_PATH"])
        elif name == "systemd-service":
            planted_services.add(vars_["SERVICE_NAME"])
        elif name in ("local-user", "uid0-user", "user-login-shell", "user-sudo-nopasswd"):
            planted_users.add(vars_["USERNAME"])

    check_paths = {c["collect"]["path"] for c in checks.values()
                   if c["type"] in ("file_regex", "permission")}
    check_services = {c["collect"]["service"].removesuffix(".service")
                      for c in checks.values() if c["type"] == "service_state"}
    check_usernames = {c["expect"]["username"] for c in checks.values()
                       if c["expect"].get("user_absent")}

    # /etc/passwd and /etc/shadow are checked for other reasons; the planted
    # loosen-file-mode targets must be checked, and the reverse pairing holds.
    assert planted_paths <= check_paths
    # tide-sampler is scored via its unit-file flag (file_regex), not service
    # state, so service_state checks must be a subset of planted services.
    assert check_services <= planted_services
    assert planted_users >= check_usernames
    # Rogue look-alike and beacon payloads need distinctively-named cmdlines
    # for the process_state patterns.
    assert re.search(checks["pump_process_killed"]["collect"]["pattern"],
                     "/usr/local/sbin/pump-ctrl")
    assert re.search(checks["sonar_process_killed"]["collect"]["pattern"],
                     "/usr/bin/python3 /opt/.sonar/beacon.py")


def test_coral_reef_pairings_score_secure_states_and_reject_planted_states():
    checks = {check["id"]: check for check in _load_scenario()["checks"]}

    # permission mode_at_most
    secure, reason = evaluate_matcher(
        _matcher(checks["dive_keys_private"]),
        {"mode": "0640", "uid": 0, "gid": 0, "exists": True},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["dive_keys_private"]),
        {"mode": "0666", "uid": 0, "gid": 0, "exists": True},
    )
    assert not planted, reason

    # file_regex, hardened == no match (second root-uid account removed)
    secure, reason = evaluate_matcher(_matcher(checks["no_uid0_user"]), {"matched": None})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_uid0_user"]), {"matched": "leviathan"}
    )
    assert not planted, reason

    # file_regex, hardened == specific value (apache worker user)
    secure, reason = evaluate_matcher(
        _matcher(checks["apache_not_root"]), {"matched": "www-data"}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["apache_not_root"]), {"matched": "root"}
    )
    assert not planted, reason

    # file_regex regex (service account shell -> nologin)
    secure, reason = evaluate_matcher(
        _matcher(checks["service_account_no_shell"]), {"matched": "/usr/sbin/nologin"}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["service_account_no_shell"]), {"matched": None}
    )
    assert not planted, reason

    # permission exists == false (sudoers drop-in removed)
    secure, reason = evaluate_matcher(
        _matcher(checks["no_passwordless_sudo"]), {"exists": False, "mode": None}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_passwordless_sudo"]), {"exists": True, "mode": "0440"}
    )
    assert not planted, reason

    # user_group user_absent
    secure, reason = evaluate_matcher(
        _matcher(checks["no_nemo"]),
        {"users": ["root", "reefadmin"], "group_members": {}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_nemo"]),
        {"users": ["root", "reefadmin", "nemo"], "group_members": {}},
    )
    assert not planted, reason

    # user_group group_members_subset_of
    secure, reason = evaluate_matcher(
        _matcher(checks["reef_sole_admin"]),
        {"users": ["root", "reefadmin"], "group_members": {"sudo": ["reefadmin"]}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["reef_sole_admin"]),
        {"users": ["root", "reefadmin", "poseidon"],
         "group_members": {"sudo": ["reefadmin", "poseidon"]}},
    )
    assert not planted, reason

    # service_state enabled == false (rogue oxygen-pump disabled)
    secure, reason = evaluate_matcher(
        _matcher(checks["pump_disabled"]), {"active": False, "enabled": False}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["pump_disabled"]), {"active": True, "enabled": True}
    )
    assert not planted, reason

    # process_state running == false (live process killed, not just unit-disabled)
    secure, reason = evaluate_matcher(
        _matcher(checks["pump_process_killed"]),
        {"running": False, "count": 0, "pids": [], "sample_cmdline": None},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["pump_process_killed"]),
        {"running": True, "count": 1, "pids": [1234], "sample_cmdline": "/usr/local/sbin/pump-ctrl"},
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["sonar_process_killed"]),
        {"running": False, "count": 0, "pids": [], "sample_cmdline": None},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["sonar_process_killed"]),
        {"running": True, "count": 1, "pids": [5678],
         "sample_cmdline": "/usr/bin/python3 /opt/.sonar/beacon.py"},
    )
    assert not planted, reason
