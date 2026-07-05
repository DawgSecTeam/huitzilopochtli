"""Tests for common/matchers.py predicates and evaluate_matcher dispatcher."""
import pytest

from common.matchers import evaluate_matcher


# --- equals -------------------------------------------------------------

def test_equals_pass():
    matcher = {"tag": "equals", "field": "matched", "value": "no"}
    passed, reason = evaluate_matcher(matcher, {"matched": "no"})
    assert passed
    assert "matched" in reason


def test_equals_fail():
    matcher = {"tag": "equals", "field": "matched", "value": "no"}
    passed, reason = evaluate_matcher(matcher, {"matched": "yes"})
    assert not passed


def test_equals_missing_raw_field_does_not_raise():
    matcher = {"tag": "equals", "field": "matched", "value": "no"}
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field" in reason


def test_equals_shorthand_form():
    # §8 shorthand: {"equals": "no"} with no explicit "tag"/"field"/"value";
    # defaults field to "matched", pulls expected value from the "equals" key.
    matcher = {"equals": "no"}
    passed, reason = evaluate_matcher(matcher, {"matched": "no"})
    assert passed

    passed, reason = evaluate_matcher(matcher, {"matched": "yes"})
    assert not passed


# --- not_equals -----------------------------------------------------------

def test_not_equals_pass():
    matcher = {"tag": "not_equals", "field": "matched", "value": "no"}
    passed, reason = evaluate_matcher(matcher, {"matched": "yes"})
    assert passed


def test_not_equals_fail():
    matcher = {"tag": "not_equals", "field": "matched", "value": "no"}
    passed, reason = evaluate_matcher(matcher, {"matched": "no"})
    assert not passed


def test_not_equals_missing_raw_field_does_not_raise():
    matcher = {"tag": "not_equals", "field": "matched", "value": "no"}
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field" in reason


def test_not_equals_shorthand_form():
    matcher = {"not_equals": "no"}
    passed, _ = evaluate_matcher(matcher, {"matched": "yes"})
    assert passed
    passed, _ = evaluate_matcher(matcher, {"matched": "no"})
    assert not passed


# --- contains ---------------------------------------------------------------

def test_contains_pass():
    matcher = {"tag": "contains", "field": "matched", "value": "wo"}
    passed, reason = evaluate_matcher(matcher, {"matched": "hello world"})
    assert passed


def test_contains_fail():
    matcher = {"tag": "contains", "field": "matched", "value": "zzz"}
    passed, reason = evaluate_matcher(matcher, {"matched": "hello world"})
    assert not passed


def test_contains_missing_raw_field_does_not_raise():
    matcher = {"tag": "contains", "field": "matched", "value": "zzz"}
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field" in reason


def test_contains_non_container_actual_does_not_raise():
    # "in" against an int raises TypeError internally; predicate should
    # catch it and return a graceful failure rather than propagating.
    matcher = {"tag": "contains", "field": "matched", "value": "zzz"}
    passed, reason = evaluate_matcher(matcher, {"matched": 42})
    assert not passed
    assert "cannot check containment" in reason


def test_contains_shorthand_form():
    matcher = {"contains": "wo"}
    passed, _ = evaluate_matcher(matcher, {"matched": "hello world"})
    assert passed
    passed, _ = evaluate_matcher(matcher, {"matched": "zzz"})
    assert not passed


# --- regex --------------------------------------------------------------

def test_regex_pass():
    matcher = {"tag": "regex", "field": "matched", "pattern": r"^\d+$"}
    passed, reason = evaluate_matcher(matcher, {"matched": "12345"})
    assert passed


def test_regex_fail():
    matcher = {"tag": "regex", "field": "matched", "pattern": r"^\d+$"}
    passed, reason = evaluate_matcher(matcher, {"matched": "abc"})
    assert not passed


def test_regex_missing_raw_field_does_not_raise():
    matcher = {"tag": "regex", "field": "matched", "pattern": r"^\d+$"}
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field" in reason


def test_regex_none_actual_does_not_raise():
    matcher = {"tag": "regex", "field": "matched", "pattern": r"^\d+$"}
    passed, reason = evaluate_matcher(matcher, {"matched": None})
    assert not passed
    assert "None" in reason


def test_regex_shorthand_form_via_pattern_key():
    # docstring: fallback keys are "regex" and "pattern"
    matcher = {"regex": r"^\d+$"}
    passed, _ = evaluate_matcher(matcher, {"matched": "999"})
    assert passed
    passed, _ = evaluate_matcher(matcher, {"matched": "nope"})
    assert not passed


# --- mode_at_most ---------------------------------------------------------

def test_mode_at_most_within_bounds_passes():
    # 644 has no bits outside of 644 -> subset -> passes
    matcher = {"tag": "mode_at_most", "field": "mode", "max_mode": "644"}
    passed, reason = evaluate_matcher(matcher, {"mode": "644"})
    assert passed


def test_mode_at_most_looser_mode_fails():
    # 666 has bits (other-write) not present in 644 -> not a subset -> fails
    matcher = {"tag": "mode_at_most", "field": "mode", "max_mode": "644"}
    passed, reason = evaluate_matcher(matcher, {"mode": "666"})
    assert not passed


def test_mode_at_most_stricter_mode_passes():
    # 600 is a strict subset of 644's bits -> passes (no looser than max)
    matcher = {"tag": "mode_at_most", "field": "mode", "max_mode": "644"}
    passed, reason = evaluate_matcher(matcher, {"mode": "600"})
    assert passed


def test_mode_at_most_missing_raw_field_does_not_raise():
    matcher = {"tag": "mode_at_most", "field": "mode", "max_mode": "644"}
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field" in reason


def test_mode_at_most_default_field_is_mode():
    matcher = {"tag": "mode_at_most", "max_mode": "644"}
    passed, reason = evaluate_matcher(matcher, {"mode": "644"})
    assert passed


# --- user_absent ----------------------------------------------------------

def test_user_absent_pass():
    matcher = {"tag": "user_absent", "username": "eve"}
    passed, reason = evaluate_matcher(matcher, {"users": ["alice", "bob"]})
    assert passed


def test_user_absent_fail():
    matcher = {"tag": "user_absent", "username": "alice"}
    passed, reason = evaluate_matcher(matcher, {"users": ["alice", "bob"]})
    assert not passed


def test_user_absent_missing_raw_field_does_not_raise():
    matcher = {"tag": "user_absent", "username": "alice"}
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field 'users'" in reason


# --- user_present ---------------------------------------------------------

def test_user_present_pass():
    matcher = {"tag": "user_present", "username": "alice"}
    passed, reason = evaluate_matcher(matcher, {"users": ["alice", "bob"]})
    assert passed


def test_user_present_fail():
    matcher = {"tag": "user_present", "username": "eve"}
    passed, reason = evaluate_matcher(matcher, {"users": ["alice", "bob"]})
    assert not passed


def test_user_present_missing_raw_field_does_not_raise():
    matcher = {"tag": "user_present", "username": "alice"}
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field 'users'" in reason


# --- group_members_subset_of -----------------------------------------------

def test_group_members_subset_of_empty_group_passes():
    matcher = {
        "tag": "group_members_subset_of",
        "group": "wheel",
        "allowed": ["root", "admin"],
    }
    passed, reason = evaluate_matcher(matcher, {"group_members": {"wheel": []}})
    assert passed


def test_group_members_subset_of_full_subset_passes():
    matcher = {
        "tag": "group_members_subset_of",
        "group": "wheel",
        "allowed": ["root", "admin"],
    }
    passed, reason = evaluate_matcher(
        matcher, {"group_members": {"wheel": ["root", "admin"]}}
    )
    assert passed


def test_group_members_subset_of_extra_member_fails():
    matcher = {
        "tag": "group_members_subset_of",
        "group": "wheel",
        "allowed": ["root", "admin"],
    }
    passed, reason = evaluate_matcher(
        matcher, {"group_members": {"wheel": ["root", "eve"]}}
    )
    assert not passed
    assert "eve" in reason


def test_group_members_subset_of_missing_raw_field_does_not_raise():
    matcher = {
        "tag": "group_members_subset_of",
        "group": "wheel",
        "allowed": ["root"],
    }
    passed, reason = evaluate_matcher(matcher, {})
    assert not passed
    assert "missing field 'group_members'" in reason


def test_group_members_subset_of_group_absent_from_raw_does_not_raise():
    matcher = {
        "tag": "group_members_subset_of",
        "group": "wheel",
        "allowed": ["root"],
    }
    passed, reason = evaluate_matcher(matcher, {"group_members": {"other": []}})
    assert not passed
    assert "not present" in reason


# --- evaluate_matcher dispatch errors ---------------------------------------

def test_evaluate_matcher_unrecognized_tag_raises_keyerror():
    # No "tag" key and no key matching a registered matcher name -> the
    # shorthand-inference fallback finds zero candidates and raises KeyError.
    with pytest.raises(KeyError):
        evaluate_matcher({"nonsense": "value"}, {})


def test_evaluate_matcher_explicit_unknown_tag_raises_keyerror():
    # Explicit but unregistered "tag" -> direct dict lookup in MATCHERS raises.
    with pytest.raises(KeyError):
        evaluate_matcher({"tag": "does_not_exist"}, {})
