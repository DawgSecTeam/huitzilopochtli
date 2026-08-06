"""Smoke test: the worked example in boxbuilder/examples/ is valid and
internally consistent.

- linux-fundamentals.scenario.yaml passes the real authoring validator and
  compiles (produces a signed manifest + rubric).
- nakon-config.json is well-formed and single-machine.
- linux-fundamentals.box.yaml resolves both files.

This guards against drift: if the scenario schema or the example changes in a
way that breaks the pairing, this test fails.
"""
import json
import os

import pytest
import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from common.crypto import signing

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
EXAMPLES = os.path.join(REPO_ROOT, "boxbuilder", "examples")


def test_example_scenario_validates():
    path = os.path.join(EXAMPLES, "linux-fundamentals.scenario.yaml")
    with open(path) as f:
        parsed = yaml.safe_load(f)
    errors = validate_scenario_yaml(parsed, path)
    assert errors == [], f"example scenario has validation errors: {errors}"


def test_example_scenario_compiles(tmp_path):
    path = os.path.join(EXAMPLES, "linux-fundamentals.scenario.yaml")
    priv, _ = signing.keypair()
    outputs = compile_scenario(path, str(tmp_path), priv)
    # Honor mode emits a rubric (local scoring).
    assert os.path.isfile(outputs["manifest"])
    assert os.path.isfile(outputs["rubric"])
    assert os.path.isfile(outputs["authoring_public_key"])
    assert os.path.isfile(outputs["engine_record"])


def test_example_nakon_config_well_formed():
    path = os.path.join(EXAMPLES, "nakon-config.json")
    with open(path) as f:
        cfg = json.load(f)
    machines = cfg["machines"]
    assert len(machines) == 1, "v1 example is single-box"
    m = machines[0]
    assert m["name"] == "web01"
    assert isinstance(m["configurations"], list) and len(m["configurations"]) >= 1


def test_example_box_spec_resolves():
    """The box spec's relative paths resolve against the examples dir, and the
    referenced files exist."""
    from boxbuilder.spec import load_spec
    path = os.path.join(EXAMPLES, "linux-fundamentals.box.yaml")
    spec = load_spec(path)
    assert spec.mode in ("honor", "ranked")
    assert os.path.isfile(spec.scenario_path)
    assert os.path.isfile(spec.nakon_config_path)


def test_example_vuln_check_pairing_documented():
    """The example scenario's header documents the vuln->check pairing. This is
    a soft check that the pairing rationale is present (agents read it)."""
    path = os.path.join(EXAMPLES, "linux-fundamentals.scenario.yaml")
    text = open(path).read()
    # Each of the three example vulns should be mentioned alongside a check id.
    for vuln in ("nginx", "ssh-root-login", "suid-find"):
        assert vuln in text, f"example scenario header should reference vuln {vuln!r}"
