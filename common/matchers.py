"""Matcher registry. See architecture.md §10.2.

A matcher is a small tagged dict evaluated against a check type's `raw`
evidence dict. Each predicate is a pure function `(matcher, raw) -> (bool, reason)`.

PHASE 1 TASK: implement the predicates below (equals, not_equals, contains,
regex, mode_at_most, user_absent, user_present, group_members_subset_of).
The registry mechanism itself (this scaffold) is frozen — do not change
MATCHERS / register / evaluate_matcher's signatures.

--- Matcher dict shapes (convention used throughout this module) ----------

Every matcher dict carries a "tag" key (added by the compiler, common/schema.py
RubricEntry.matcher) naming which predicate below applies. Beyond "tag", the
conventional keys are:

  equals                  {"tag": "equals", "field": <str>, "value": <any>}
  not_equals               {"tag": "not_equals", "field": <str>, "value": <any>}
  contains                 {"tag": "contains", "field": <str>, "value": <any>}
  regex                    {"tag": "regex", "field": <str>, "pattern": <str>}
  mode_at_most             {"tag": "mode_at_most", "field": <str>, "max_mode": <octal str>}
  user_absent              {"tag": "user_absent", "username": <str>}
  user_present             {"tag": "user_present", "username": <str>}
  group_members_subset_of  {"tag": "group_members_subset_of", "group": <str>, "allowed": [<str>, ...]}

"field" defaults to "matched" for equals/not_equals/contains/regex (the
common single-value raw field, e.g. file_regex's raw["matched"]) when not
given explicitly.

Shorthand (architecture.md §8 example): the author-facing YAML writes
`expect: {equals: "no", points: 5}`. The compiler is expected to tag this as
{"tag": "equals", "equals": "no", "points": 5} (i.e. it just stamps "tag" onto
the expect dict; it does not rewrite "equals" -> "value"). So equals/
not_equals/contains/regex also accept the value/pattern under a key that
matches their own tag name (e.g. "equals", "pattern"/"regex") as a fallback
when the conventional "value"/"pattern" key is absent. This lets the
documented §8 YAML example work unmodified through the pipeline.
"""
import re
from typing import Callable

MATCHERS: dict[str, Callable[[dict, dict], tuple]] = {}


def register(tag: str):
    """Class/function decorator registering a matcher predicate under `tag`."""
    def deco(fn):
        MATCHERS[tag] = fn
        return fn
    return deco


def evaluate_matcher(matcher: dict, raw: dict) -> tuple:
    """Look up matcher['tag'] in MATCHERS and evaluate it against raw.

    Returns (passed: bool, reason: str).

    If "tag" is absent, fall back to the §8 shorthand form where the tag
    name itself is used as the expected-value key (e.g. {"equals": "no"}):
    infer the tag as the one key present in `matcher` that also names a
    registered matcher. This keeps the call signature unchanged while
    letting the documented shorthand YAML work without an explicit "tag".
    """
    tag = matcher.get("tag")
    if tag is None:
        candidates = [k for k in matcher if k in MATCHERS]
        if len(candidates) == 1:
            tag = candidates[0]
        else:
            raise KeyError("tag")
    return MATCHERS[tag](matcher, raw)


# --- internal helpers -------------------------------------------------------

_MISSING = object()


def _field_name(matcher: dict, default: str = "matched") -> str:
    return matcher.get("field", default)


def _expected_value(matcher: dict, *fallback_keys: str):
    """Pull the expected value out of a matcher dict.

    Checks "value" first, then each of fallback_keys (e.g. the matcher's own
    tag name, to support the §8 shorthand form {"equals": "no"}). Returns
    _MISSING if none present.
    """
    if "value" in matcher:
        return matcher["value"]
    for key in fallback_keys:
        if key in matcher:
            return matcher[key]
    return _MISSING


def _get_raw(raw: dict, field: str):
    """Fetch raw[field], returning _MISSING (not raising) if absent."""
    if not isinstance(raw, dict) or field not in raw:
        return _MISSING
    return raw[field]


# --- predicates --------------------------------------------------------------

@register("equals")
def _equals(matcher: dict, raw: dict) -> tuple:
    field = _field_name(matcher)
    expected = _expected_value(matcher, "equals")
    if expected is _MISSING:
        return False, f"matcher missing expected value for field {field!r}"
    actual = _get_raw(raw, field)
    if actual is _MISSING:
        return False, f"raw evidence missing field {field!r}"
    if actual == expected:
        return True, f"{field}={actual!r} equals expected {expected!r}"
    return False, f"{field}={actual!r} does not equal expected {expected!r}"


@register("not_equals")
def _not_equals(matcher: dict, raw: dict) -> tuple:
    field = _field_name(matcher)
    expected = _expected_value(matcher, "not_equals")
    if expected is _MISSING:
        return False, f"matcher missing expected value for field {field!r}"
    actual = _get_raw(raw, field)
    if actual is _MISSING:
        return False, f"raw evidence missing field {field!r}"
    if actual != expected:
        return True, f"{field}={actual!r} does not equal forbidden {expected!r}"
    return False, f"{field}={actual!r} equals forbidden {expected!r}"


@register("contains")
def _contains(matcher: dict, raw: dict) -> tuple:
    field = _field_name(matcher)
    expected = _expected_value(matcher, "contains")
    if expected is _MISSING:
        return False, f"matcher missing expected value for field {field!r}"
    actual = _get_raw(raw, field)
    if actual is _MISSING:
        return False, f"raw evidence missing field {field!r}"
    try:
        found = expected in actual
    except TypeError:
        return False, f"{field}={actual!r} is not a container/string; cannot check containment"
    if found:
        return True, f"{field} contains {expected!r}"
    return False, f"{field}={actual!r} does not contain {expected!r}"


@register("regex")
def _regex(matcher: dict, raw: dict) -> tuple:
    field = _field_name(matcher)
    pattern = _expected_value(matcher, "regex", "pattern")
    if pattern is _MISSING:
        return False, f"matcher missing pattern for field {field!r}"
    actual = _get_raw(raw, field)
    if actual is _MISSING:
        return False, f"raw evidence missing field {field!r}"
    if actual is None:
        return False, f"{field} is None; cannot match pattern {pattern!r}"
    if re.search(pattern, str(actual)):
        return True, f"{field}={actual!r} matches pattern {pattern!r}"
    return False, f"{field}={actual!r} does not match pattern {pattern!r}"


@register("mode_at_most")
def _mode_at_most(matcher: dict, raw: dict) -> tuple:
    field = _field_name(matcher, default="mode")
    max_mode = matcher.get("max_mode")
    if max_mode is None:
        return False, "matcher missing max_mode"
    actual = _get_raw(raw, field)
    if actual is _MISSING or actual is None:
        return False, f"raw evidence missing field {field!r}"
    try:
        actual_bits = int(str(actual), 8)
        max_bits = int(str(max_mode), 8)
    except ValueError:
        return False, f"could not parse mode(s): actual={actual!r} max={max_mode!r}"
    # Passes if actual has no bits set beyond what max_mode allows, i.e.
    # actual is no looser than max_mode (a subset of its permission bits).
    if actual_bits & ~max_bits == 0:
        return True, f"mode {actual!r} is no looser than max {max_mode!r}"
    return False, f"mode {actual!r} is looser than max {max_mode!r}"


@register("user_absent")
def _user_absent(matcher: dict, raw: dict) -> tuple:
    username = matcher.get("username")
    if username is None:
        return False, "matcher missing username"
    users = _get_raw(raw, "users")
    if users is _MISSING:
        return False, "raw evidence missing field 'users'"
    if username not in users:
        return True, f"user {username!r} is absent"
    return False, f"user {username!r} is present"


@register("user_present")
def _user_present(matcher: dict, raw: dict) -> tuple:
    username = matcher.get("username")
    if username is None:
        return False, "matcher missing username"
    users = _get_raw(raw, "users")
    if users is _MISSING:
        return False, "raw evidence missing field 'users'"
    if username in users:
        return True, f"user {username!r} is present"
    return False, f"user {username!r} is absent"


@register("group_members_subset_of")
def _group_members_subset_of(matcher: dict, raw: dict) -> tuple:
    group = matcher.get("group")
    allowed = matcher.get("allowed")
    if group is None or allowed is None:
        return False, "matcher missing group or allowed list"
    group_members = _get_raw(raw, "group_members")
    if group_members is _MISSING:
        return False, "raw evidence missing field 'group_members'"
    members = group_members.get(group)
    if members is None:
        return False, f"group {group!r} not present in group_members"
    allowed_set = set(allowed)
    extra = [m for m in members if m not in allowed_set]
    if not extra:
        return True, f"members of {group!r} ({list(members)}) are all allowed"
    return False, f"members of {group!r} not in allowed list: {extra}"
