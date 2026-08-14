"""Regression test for boxbuilder/examples/linux-fundamentals.scenario.yaml.

This is the canonical worked example `boxbuilder/README.md` points authors
at. Two of its three checks (`nginx_up`/service_state, `no_suid_find`/
permission) used to silently score 0 regardless of box state -- missing an
explicit `field:` in `expect` (equals/contains/... default `field` to
"matched", which only file_regex's raw evidence happens to have) and, for
`no_suid_find`, targeting the wrong path entirely. Only `ssh_no_root`
(file_regex) worked, by luck of the default matching its raw key.

This test validates the file structurally, then exercises each check's real
`expect` matcher (loaded straight from the YAML, not hand-duplicated) against
synthetic raw evidence matching what the paired nakon vuln actually plants
and its hardened counterpart -- confirming all three checks now evaluate
correctly in both directions, not just once.
"""
import os

import yaml

from authoring.validate import validate_scenario_yaml
from common.matchers import evaluate_matcher

_EXAMPLE_PATH = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "boxbuilder", "examples",
    "linux-fundamentals.scenario.yaml",
))


def _load():
    with open(_EXAMPLE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _checks_by_id(parsed):
    return {c["id"]: c for c in parsed["checks"]}


def _matcher(check):
    """Mirror authoring/compile.py::_build_rubric_entry: the compiled matcher
    is `expect` with `points`/`sla` stripped -- verbatim, no rewriting."""
    return {k: v for k, v in check["expect"].items() if k not in ("points", "sla")}


def test_example_scenario_validates():
    parsed = _load()
    errors = validate_scenario_yaml(parsed, _EXAMPLE_PATH)
    assert errors == [], errors


def test_validate_rejects_empty_expect_mapping():
    # BUG-V1: `expect: {}` (and null `expect:`) passed the required-key +
    # isinstance-dict guards but compiled to an empty matcher {} that crashed
    # the evaluator with KeyError('tag') at scoring time. Authoring-time
    # validation must reject it.
    parsed = _load()
    parsed["checks"][0]["expect"] = {}
    errors = validate_scenario_yaml(parsed, _EXAMPLE_PATH)
    assert any("expect" in e and "non-empty" in e for e in errors), errors


def test_validate_rejects_null_expect():
    parsed = _load()
    parsed["checks"][0]["expect"] = None
    errors = validate_scenario_yaml(parsed, _EXAMPLE_PATH)
    assert any("expect" in e for e in errors), errors


def test_nginx_up_matches_service_state_raw_shape():
    # agent/checks/service_state.py raw shape: {"active": bool, "enabled": bool}
    matcher = _matcher(_checks_by_id(_load())["nginx_up"])
    # nginx vuln plants: apt-get install + enable + start -> stays active.
    # The check verifies it STAYS up; the planted state is the passing state.
    passed, reason = evaluate_matcher(matcher, {"active": True, "enabled": True})
    assert passed, reason
    passed, reason = evaluate_matcher(matcher, {"active": False, "enabled": True})
    assert not passed, reason


def test_ssh_no_root_matches_file_regex_raw_shape():
    # agent/checks/file_regex.py raw shape: {"matched": str|None, "present": bool}
    matcher = _matcher(_checks_by_id(_load())["ssh_no_root"])
    # ssh-root-login vuln plants `PermitRootLogin yes` -- unhardened, must fail.
    passed, reason = evaluate_matcher(matcher, {"matched": "yes", "present": True})
    assert not passed, reason
    # Hardened: author flips it back to "no".
    passed, reason = evaluate_matcher(matcher, {"matched": "no", "present": True})
    assert passed, reason


def test_no_suid_find_matches_permission_raw_shape():
    # agent/checks/permission.py raw shape: {"mode": "0NNNN", "uid", "gid", "exists"}
    matcher = _matcher(_checks_by_id(_load())["no_suid_find"])
    # suid-find vuln plants: chmod +s $(which find) -> setuid + 0755 = 04755.
    passed, reason = evaluate_matcher(
        matcher, {"mode": "4755", "uid": 0, "gid": 0, "exists": True})
    assert not passed, reason
    # Hardened: author removes the setuid bit (chmod -s find) -> 0755.
    passed, reason = evaluate_matcher(
        matcher, {"mode": "0755", "uid": 0, "gid": 0, "exists": True})
    assert passed, reason
