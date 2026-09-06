"""Regression coverage for the themed Cocoa Falls worked example."""
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
SCENARIO = os.path.join(EXAMPLES, "chocolate-factory.scenario.yaml")
BOX = os.path.join(EXAMPLES, "chocolate-factory.box.yaml")
NAKON = os.path.join(EXAMPLES, "chocolate-factory.nakon.json")


def _load_scenario():
    with open(SCENARIO, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _matcher(check):
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_chocolate_factory_scenario_validates_and_compiles(tmp_path):
    parsed = _load_scenario()
    assert validate_scenario_yaml(parsed, SCENARIO) == []
    assert len(parsed["checks"]) == 19
    assert len({check["id"] for check in parsed["checks"]}) == 19
    assert sum(check["max_points"] for check in parsed["checks"]) == 190

    private_key, _ = signing.keypair()
    outputs = compile_scenario(SCENARIO, str(tmp_path), private_key)
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    manifest = json.load(open(outputs["manifest"], encoding="utf-8"))
    assert manifest["theme"]["title"] == "Cocoa Falls Chocolate Works"
    assert manifest["theme"]["logo_b64"]


def test_chocolate_factory_box_and_nakon_inputs_resolve():
    spec = load_spec(BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Cocoa Falls Chocolate Works"

    with open(NAKON, encoding="utf-8") as f:
        machines = json.load(f)["machines"]
    assert len(machines) == 1
    requested = machines[0]["configurations"]
    names = [item if isinstance(item, str) else item["name"] for item in requested]
    assert names.count("insecure-file-mode") == 5
    for name in (
        "passwordless-sudo", "malicious-factory-users", "unauthorized-shipping-account",
        "unauthorized-admin-user", "service-account-shell", "hidden-cron-persistence",
        "polyglot-media", "malicious-autostart", "malicious-systemd-service", "ssh-root-login",
    ):
        assert name in names


def test_chocolate_factory_pairings_score_secure_states_and_reject_planted_states():
    checks = {check["id"]: check for check in _load_scenario()["checks"]}

    secure, reason = evaluate_matcher(
        _matcher(checks["recipe_private"]),
        {"mode": "0640", "uid": 0, "gid": 0, "exists": True},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["recipe_private"]),
        {"mode": "0666", "uid": 0, "gid": 0, "exists": True},
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["no_passwordless_sudo"]), {"exists": False, "mode": None}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_passwordless_sudo"]), {"exists": True, "mode": "0440"}
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["intern_not_admin"]),
        {"users": ["root", "ubuntu"], "group_members": {"sudo": ["ubuntu"]}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["intern_not_admin"]),
        {"users": ["root", "ubuntu", "intern"], "group_members": {"sudo": ["ubuntu", "intern"]}},
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["cocoa_service_disabled"]), {"active": False, "enabled": False}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["cocoa_service_disabled"]), {"active": True, "enabled": True}
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["no_shipping_bot"]),
        {"users": ["root", "ubuntu"], "group_members": {}},
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_shipping_bot"]),
        {"users": ["root", "ubuntu", "shipping_bot"], "group_members": {}},
    )
    assert not planted, reason

    secure, reason = evaluate_matcher(
        _matcher(checks["no_backdoor_ssh_key"]), {"matched": None}
    )
    assert secure, reason
    planted, reason = evaluate_matcher(
        _matcher(checks["no_backdoor_ssh_key"]), {"matched": "planted-training-key"}
    )
    assert not planted, reason
