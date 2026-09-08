"""Regression coverage for the themed Coyolxauhqui Ridge Solar Observatory example."""
import json
import os

import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from boxbuilder.spec import load_spec
from common.crypto import signing
from common.matchers import evaluate_matcher


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXAMPLES = os.path.join(REPO_ROOT, "boxbuilder", "examples")
SCENARIO = os.path.join(EXAMPLES, "solar-observatory.scenario.yaml")
BOX = os.path.join(EXAMPLES, "solar-observatory.box.yaml")
NAKON = os.path.join(EXAMPLES, "solar-observatory.nakon.json")

CHECK_COUNT = 23
TOTAL_POINTS = 230


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _matcher(check):
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_solar_observatory_scenario_validates_and_compiles(tmp_path):
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
    assert manifest["theme"]["title"] == "Coyolxauhqui Ridge Solar Observatory"
    assert manifest["theme"]["logo_b64"]


def test_solar_observatory_box_and_nakon_inputs_resolve():
    spec = load_spec(BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Coyolxauhqui Ridge Solar Observatory"

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


def test_solar_observatory_pairings_score_secure_states_and_reject_planted_states():
    checks = {check["id"]: check for check in _load_scenario()["checks"]}

    # permission mode_at_most
    secure, reason = evaluate_matcher(
        _matcher(checks["telescope_keys_private"]),
        {"mode": "0640", "uid": 0, "gid": 0, "exists": True},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["telescope_keys_private"]),
        {"mode": "0666", "uid": 0, "gid": 0, "exists": True},
    )
    assert not planted, reason

    # file_regex, hardened == no match (second root-uid account removed)
    secure, reason = evaluate_matcher(_matcher(checks["no_uid0_user"]), {"matched": None})
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_uid0_user"]), {"matched": "sunwatch"}
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
        _matcher(checks["no_red"]),
        {"users": ["root", "obsadmin"], "group_members": {}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_red"]),
        {"users": ["root", "obsadmin", "red"], "group_members": {}},
    )
    assert not planted, reason

    # user_group group_members_subset_of
    secure, reason = evaluate_matcher(
        _matcher(checks["obs_sole_admin"]),
        {"users": ["root", "obsadmin"], "group_members": {"sudo": ["obsadmin"]}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["obs_sole_admin"]),
        {"users": ["root", "obsadmin", "red"], "group_members": {"sudo": ["obsadmin", "red"]}},
    )
    assert not planted, reason

    # service_state enabled == false (rogue mirror-fan disabled)
    secure, reason = evaluate_matcher(
        _matcher(checks["mirror_fan_disabled"]), {"active": False, "enabled": False}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["mirror_fan_disabled"]), {"active": True, "enabled": True}
    )
    assert not planted, reason

    # process_state running == false (live process killed, not just unit-disabled)
    secure, reason = evaluate_matcher(
        _matcher(checks["mirror_fan_process_killed"]),
        {"running": False, "count": 0, "pids": [], "sample_cmdline": None},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["mirror_fan_process_killed"]),
        {"running": True, "count": 1, "pids": [1234], "sample_cmdline": "/usr/local/sbin/mirror-fanctl"},
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["uplink_process_killed"]),
        {"running": False, "count": 0, "pids": [], "sample_cmdline": None},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["uplink_process_killed"]),
        {"running": True, "count": 1, "pids": [5678],
         "sample_cmdline": "/usr/bin/python3 /opt/.uplink/relay.py"},
    )
    assert not planted, reason
