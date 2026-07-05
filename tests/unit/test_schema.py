"""Unit tests for common/schema.py validate_manifest() and validate_rubric()."""
import copy

import pytest

from common.schema import validate_manifest, validate_rubric, SCHEMA_VERSION


def minimal_manifest():
    return {
        "schema_version": SCHEMA_VERSION,
        "scenario_name": "demo",
        "scenario_version": 1,
        "mode": "honor",
        "hosts": [],
        "checks": [],
    }


def minimal_check():
    return {
        "id": "chk-1",
        "type": "http",
        "category": "vuln",
        "host_id": "host-1",
        "collect_params": {},
        "display_title": "Some check",
        "display_max_points": 10,
    }


def minimal_rubric():
    return {
        "schema_version": SCHEMA_VERSION,
        "scenario_name": "demo",
        "scenario_version": 1,
        "entries": [],
    }


def minimal_rubric_entry():
    return {
        "check_id": "chk-1",
        "category": "vuln",
        "matcher": {},
        "points": 10,
    }


# --- validate_manifest: top-level -------------------------------------------


def test_minimal_valid_manifest_returns_no_errors():
    assert validate_manifest(minimal_manifest()) == []


_MANIFEST_REQUIRED_KEYS = (
    "schema_version", "scenario_name", "scenario_version", "mode", "hosts", "checks",
)


@pytest.mark.parametrize("missing_key", _MANIFEST_REQUIRED_KEYS)
def test_manifest_missing_each_required_key(missing_key):
    manifest = minimal_manifest()
    del manifest[missing_key]
    errors = validate_manifest(manifest)
    assert errors != []
    assert any(missing_key in e for e in errors)


def test_manifest_mode_bogus_rejected():
    manifest = minimal_manifest()
    manifest["mode"] = "bogus"
    errors = validate_manifest(manifest)
    assert errors != []


def test_manifest_mode_ranked_without_engine_url_rejected():
    manifest = minimal_manifest()
    manifest["mode"] = "ranked"
    errors = validate_manifest(manifest)
    assert errors != []
    assert any("engine_url" in e for e in errors)


def test_manifest_mode_ranked_with_engine_url_accepted():
    manifest = minimal_manifest()
    manifest["mode"] = "ranked"
    manifest["engine_url"] = "https://engine.example.com"
    errors = validate_manifest(manifest)
    assert errors == []


# --- validate_manifest: checks[] ---------------------------------------------


_CHECK_SPEC_REQUIRED_KEYS = (
    "id", "type", "category", "host_id", "collect_params",
    "display_title", "display_max_points",
)


@pytest.mark.parametrize("missing_key", _CHECK_SPEC_REQUIRED_KEYS)
def test_check_spec_missing_each_required_key(missing_key):
    manifest = minimal_manifest()
    check = minimal_check()
    del check[missing_key]
    manifest["checks"] = [check]
    errors = validate_manifest(manifest)
    assert errors != []
    assert any(missing_key in e for e in errors)


def test_check_spec_invalid_category_rejected():
    manifest = minimal_manifest()
    check = minimal_check()
    check["category"] = "not-a-real-category"
    manifest["checks"] = [check]
    errors = validate_manifest(manifest)
    assert errors != []
    assert any("category" in e for e in errors)


def test_check_spec_duplicate_ids_rejected():
    manifest = minimal_manifest()
    check_a = minimal_check()
    check_b = minimal_check()  # same id "chk-1"
    manifest["checks"] = [check_a, check_b]
    errors = validate_manifest(manifest)
    assert errors != []
    assert any("duplicate check id" in e for e in errors)


@pytest.mark.parametrize("leaked_key", ("expect", "points", "matcher"))
def test_check_spec_collect_params_leak_guard(leaked_key):
    manifest = minimal_manifest()
    check = minimal_check()
    check["collect_params"] = {leaked_key: "should not be here"}
    manifest["checks"] = [check]
    errors = validate_manifest(manifest)
    assert errors != []
    assert any(
        "collect_params must not contain" in e and leaked_key in e for e in errors
    )


def test_check_spec_collect_params_without_leak_is_fine():
    manifest = minimal_manifest()
    check = minimal_check()
    check["collect_params"] = {"url": "http://example.com", "timeout": 5}
    manifest["checks"] = [check]
    assert validate_manifest(manifest) == []


# --- validate_rubric: top-level ----------------------------------------------


def test_minimal_valid_rubric_returns_no_errors():
    assert validate_rubric(minimal_rubric()) == []


_RUBRIC_REQUIRED_KEYS = ("schema_version", "scenario_name", "scenario_version", "entries")


@pytest.mark.parametrize("missing_key", _RUBRIC_REQUIRED_KEYS)
def test_rubric_missing_each_required_key(missing_key):
    rubric = minimal_rubric()
    del rubric[missing_key]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any(missing_key in e for e in errors)


# --- validate_rubric: entries[] ----------------------------------------------


_RUBRIC_ENTRY_REQUIRED_KEYS = ("check_id", "category", "matcher", "points")


@pytest.mark.parametrize("missing_key", _RUBRIC_ENTRY_REQUIRED_KEYS)
def test_rubric_entry_missing_each_required_key(missing_key):
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    del entry[missing_key]
    rubric["entries"] = [entry]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any(missing_key in e for e in errors)


def test_rubric_entry_invalid_category_rejected():
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    entry["category"] = "not-a-real-category"
    rubric["entries"] = [entry]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any("category" in e for e in errors)


def test_rubric_entry_non_int_points_rejected():
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    entry["points"] = "10"  # string, not int
    rubric["entries"] = [entry]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any("points must be an integer" in e for e in errors)


def test_rubric_entry_bool_points_rejected():
    # bool is a subclass of int in Python, so a naive isinstance(x, int)
    # check would silently accept a boolean as "points" -- validate_rubric()
    # explicitly guards against this since a boolean is not a sensible point
    # value.
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    entry["points"] = True
    rubric["entries"] = [entry]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any("points must be an integer" in e for e in errors)


def test_rubric_entry_non_dict_matcher_rejected():
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    entry["matcher"] = "not-a-dict"
    rubric["entries"] = [entry]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any("matcher must be an object" in e for e in errors)


def test_rubric_entry_duplicate_check_id_rejected():
    rubric = minimal_rubric()
    entry_a = minimal_rubric_entry()
    entry_b = minimal_rubric_entry()  # same check_id "chk-1"
    rubric["entries"] = [entry_a, entry_b]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any("duplicate check_id" in e for e in errors)


def test_rubric_entry_sla_present_but_not_dict_rejected():
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    entry["sla"] = "not-a-dict"
    rubric["entries"] = [entry]
    errors = validate_rubric(rubric)
    assert errors != []
    assert any("sla must be an object or null" in e for e in errors)


def test_rubric_entry_sla_none_is_fine():
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    entry["sla"] = None
    rubric["entries"] = [entry]
    assert validate_rubric(rubric) == []


def test_rubric_entry_sla_dict_is_fine():
    rubric = minimal_rubric()
    entry = minimal_rubric_entry()
    entry["sla"] = {"interval_s": 60, "points_per_interval": 1}
    rubric["entries"] = [entry]
    assert validate_rubric(rubric) == []
