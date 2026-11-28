"""Matcher registry. See architecture.md §10.2.

A matcher is a small tagged dict evaluated against a check type's ``raw``
evidence dict. Each predicate is a pure function ``(matcher, raw) -> (bool, reason)``.

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
  answer_equals            {"tag": "answer_equals", "value": <str>, "accept": [<str>, ...]}

The data_* matchers read a subfield of raw["data"] (the parsed JSON document a
command_json/powershell_json collector emitted) instead of a top-level raw
field. "field" is a dotted path into the data object. They exist so ranked
collectors can ship raw facts only — the pass condition lives in the rubric
(engine-side), never in the on-box script:

  data_equals              {"tag": "data_equals", "field": <str>, "value": <any>}
  data_not_equals          {"tag": "data_not_equals", "field": <str>, "value": <any>}
  data_contains            {"tag": "data_contains", "field": <str>, "value": <any>}
  data_regex               {"tag": "data_regex", "field": <str>, "pattern": <str>}
  data_in_range            {"tag": "data_in_range", "field": <str>, "min": <num>, "max": <num>}
  data_present             {"tag": "data_present", "field": <str>}
  data_absent              {"tag": "data_absent", "field": <str>}

Combinators (work over any sub-matchers, including the data_* ones) so a
compound pass condition — several facts that must all hold — lives in the
rubric rather than as an OR/AND chain inside an on-box script:

  all_of                   {"tag": "all_of", "matchers": [<matcher>, ...]}
  any_of                   {"tag": "any_of", "matchers": [<matcher>, ...]}
  not                      {"tag": "not", "matcher": <matcher>}

"field" defaults to "matched" for equals/not_equals/contains/regex (the
common single-value raw field, e.g. file_regex's raw["matched"]) when not
given explicitly.

Shorthand (§8): the compiler just stamps "tag" onto the author's expect dict,
so `expect: {equals: "no"}` arrives as {"tag": "equals", "equals": "no"} —
predicates therefore also read the value from a key named after their own
tag when "value"/"pattern" is absent.
"""
import re
import string
from typing import Callable

MATCHERS: dict[str, Callable[[dict, dict], tuple]] = {}

# stdlib re has no per-match timeout and holds the GIL while running, so the
# haystack is capped; pathological trusted patterns are an operator concern.
_REGEX_HAYSTACK_LIMIT = 1_000_000
_REGEX_CACHE: dict[str, "re.Pattern"] = {}


def _compile_pattern(pattern: str) -> "re.Pattern":
    """Cached compile of a regex pattern (patterns recur across check-ins)."""
    compiled = _REGEX_CACHE.get(pattern)
    if compiled is None:
        compiled = re.compile(pattern)
        _REGEX_CACHE[pattern] = compiled
    return compiled


def register(tag: str):
    """Class/function decorator registering a matcher predicate under `tag`."""
    def deco(fn):
        MATCHERS[tag] = fn
        return fn
    return deco


def _resolve_tag(matcher: dict):
    """Resolve the matcher tag, including the documented shorthand form.

    Returns the tag string, or None when the matcher is not an object, the tag
    is not a string/registered, or the shorthand form is ambiguous.
    """
    if not isinstance(matcher, dict):
        return None
    tag = matcher.get("tag")
    if tag is None:
        candidates = [k for k in matcher if isinstance(k, str) and k in MATCHERS]
        if len(candidates) != 1:
            return None
        return candidates[0]
    if not isinstance(tag, str) or tag not in MATCHERS:
        return None
    return tag


def validate_matcher(matcher: dict) -> list:
    """Return human-readable argument errors for a matcher (empty = valid).

    Without this, {"tag": "regex", "pattern": 123} passes tag-only checks and
    raises TypeError inside every later check-in. Validates the arguments each
    predicate actually reads, with the same shorthand fallbacks."""
    errors = []
    if not isinstance(matcher, dict):
        return ["matcher must be an object"]

    tag = matcher.get("tag")
    if tag is None:
        candidates = [k for k in matcher if isinstance(k, str) and k in MATCHERS]
        if len(candidates) != 1:
            if not candidates:
                return ["matcher has no resolvable tag (none of its keys name a registered matcher)"]
            return [f"matcher is ambiguous: several keys name registered matchers ({candidates})"]
        tag = candidates[0]
    elif not isinstance(tag, str):
        return ["matcher tag must be a string"]
    elif tag not in MATCHERS:
        return [f"matcher has unknown tag {tag!r}"]

    if "field" in matcher and not isinstance(matcher["field"], str):
        errors.append("matcher field must be a string")

    if tag in ("equals", "not_equals", "contains"):
        if "value" not in matcher and tag not in matcher:
            errors.append(f"{tag} matcher is missing its expected value")
    elif tag == "regex":
        pattern = _expected_value(matcher, "regex", "pattern")
        if pattern is _MISSING:
            errors.append("regex matcher is missing its pattern")
        elif not isinstance(pattern, str):
            errors.append(f"regex pattern must be a string, got {type(pattern).__name__}")
        else:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"regex pattern does not compile: {exc}")
    elif tag == "mode_at_most":
        max_mode = matcher.get("max_mode")
        if max_mode is None:
            errors.append("mode_at_most matcher is missing max_mode")
        else:
            try:
                _parse_mode(max_mode)
            except (TypeError, ValueError):
                errors.append(f"mode_at_most max_mode is not a valid mode: {max_mode!r}")
    elif tag in ("user_absent", "user_present"):
        username = matcher.get("username")
        if not isinstance(username, str) or not username:
            errors.append(f"{tag} matcher requires a non-empty string username")
    elif tag == "group_members_subset_of":
        group = matcher.get("group")
        allowed = matcher.get("allowed")
        if not isinstance(group, str) or not group:
            errors.append("group_members_subset_of requires a non-empty string group")
        if not isinstance(allowed, list) or not all(isinstance(a, str) for a in allowed):
            errors.append("group_members_subset_of requires allowed to be a list of strings")
    elif tag == "answer_equals":
        value = matcher.get("value")
        accept = matcher.get("accept")
        if value is None and accept is None:
            errors.append("answer_equals requires value or accept")
        if value is not None and not isinstance(value, str):
            errors.append("answer_equals value must be a string")
        if accept is not None and (
            not isinstance(accept, list) or not all(isinstance(a, str) for a in accept)
        ):
            errors.append("answer_equals accept must be a list of strings")
    elif tag in ("data_equals", "data_not_equals", "data_contains"):
        if "value" not in matcher and tag not in matcher:
            errors.append(f"{tag} matcher is missing its expected value")
        if "field" not in matcher:
            errors.append(f"{tag} matcher requires a 'field' (dotted path into raw data)")
    elif tag == "data_regex":
        pattern = _expected_value(matcher, "data_regex", "pattern")
        if pattern is _MISSING:
            errors.append("data_regex matcher is missing its pattern")
        elif not isinstance(pattern, str):
            errors.append("data_regex pattern must be a string")
        elif "field" not in matcher:
            errors.append("data_regex matcher requires a 'field'")
        else:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"data_regex pattern does not compile: {exc}")
    elif tag == "data_in_range":
        if "field" not in matcher:
            errors.append("data_in_range matcher requires a 'field'")
        for bound in ("min", "max"):
            if bound not in matcher or isinstance(matcher[bound], bool) or \
                    not isinstance(matcher[bound], (int, float)):
                errors.append(f"data_in_range {bound} must be a number")
    elif tag in ("data_present", "data_absent"):
        if not matcher.get("field"):
            errors.append(f"{tag} matcher requires a non-empty 'field'")
    elif tag in ("all_of", "any_of"):
        sub = matcher.get("matchers")
        if not isinstance(sub, list) or not sub:
            errors.append(f"{tag} requires a non-empty 'matchers' list")
        elif not all(isinstance(m, dict) for m in sub):
            errors.append(f"{tag} matchers must all be objects")
        else:
            for m in sub:
                errors.extend(f"{tag}: {e}" for e in validate_matcher(m))
    elif tag == "not":
        sub = matcher.get("matcher")
        if not isinstance(sub, dict):
            errors.append("not requires a 'matcher' object")
        else:
            errors.extend(f"not: {e}" for e in validate_matcher(sub))
    return errors


def evaluate_matcher(matcher: dict, raw: dict) -> tuple:
    """Look up matcher['tag'] in MATCHERS and evaluate against raw.

    Returns (passed, reason). Never raises: a malformed matcher is an
    unsatisfied observation, never an aborted check-in."""
    tag = _resolve_tag(matcher)
    if tag is None:
        return False, "matcher has no resolvable tag"
    try:
        return MATCHERS[tag](matcher, raw)
    except Exception as exc:  # noqa: BLE001 - evaluator must stay total
        return False, f"matcher {tag!r} could not be evaluated ({type(exc).__name__})"



_MISSING = object()


def _field_name(matcher: dict, default: str = "matched") -> str:
    return matcher.get("field", default)


def _expected_value(matcher: dict, *fallback_keys: str):
    """Pull the expected value: "value" first, then fallback_keys (the tag
    name, for the §8 shorthand {"equals": "no"}). _MISSING if none present."""
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


def _parse_mode(value) -> int:
    """Normalize a file mode to int permission bits (masked to the low 12).

    Accepts an octal *string* ("0755", the permission collector's convention)
    or a plain *int* — take ints as-is: re-parsing 493 as octal is wrong."""
    if isinstance(value, bool):
        raise TypeError("bool is not a valid file mode")
    if isinstance(value, int):
        return value & 0o7777
    if isinstance(value, str):
        return int(value.strip(), 8) & 0o7777
    raise TypeError(f"unsupported mode type: {type(value).__name__}")



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
    haystack = str(actual)
    if len(haystack) > _REGEX_HAYSTACK_LIMIT:
        return False, f"{field} exceeds length limit {_REGEX_HAYSTACK_LIMIT}; not evaluated"
    try:
        compiled = _compile_pattern(pattern)
    except re.error as e:
        return False, f"invalid regex pattern {pattern!r}: {e}"
    try:
        hit = compiled.search(haystack)
    except RecursionError:
        return False, f"regex {pattern!r} hit recursion limit"
    if hit:
        return True, f"{field}={actual!r} matches pattern {pattern!r}"
    return False, f"{field}={actual!r} does not match pattern {pattern!r}"


@register("answer_equals")
def _answer_equals(matcher: dict, raw: dict) -> tuple:
    """Forensics answers: value/accept vs raw["answer"], normalized via
    normalize_answer(). A blank or missing submission NEVER matches —
    unanswered earns nothing."""
    expected = _expected_value(matcher, "answer_equals")
    accept = matcher.get("accept")
    if expected is _MISSING and accept is None:
        return False, "matcher missing expected value (value/accept)"
    if accept is not None and (
        not isinstance(accept, list) or not all(isinstance(a, str) for a in accept)
    ):
        return False, "matcher 'accept' must be a list of strings"

    candidates = []
    if expected is not _MISSING:
        candidates.append(expected)
    if accept:
        candidates.extend(accept)

    actual = _get_raw(raw, "answer")
    if actual is _MISSING or actual is None:
        return False, "answer not submitted"
    if not isinstance(actual, str):
        return False, f"answer must be a string (got {type(actual).__name__})"

    normalized = normalize_answer(actual)
    if not normalized:
        return False, "answer is blank"
    for candidate in candidates:
        if normalized == normalize_answer(candidate):
            return True, f"answer {actual!r} matches expected"
    return False, f"answer {actual!r} is not correct"


def normalize_answer(value: str) -> str:
    """Casefold, collapse whitespace, strip surrounding punctuation.

    The single definition of "blank" — the matcher and the board's submitted
    flag must agree with it."""
    collapsed = " ".join(str(value).casefold().split())
    return collapsed.strip(string.punctuation + "\u201c\u201d\u2018\u2019")


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
        actual_bits = _parse_mode(actual)
        max_bits = _parse_mode(max_mode)
    except (ValueError, TypeError):
        return False, f"could not parse mode(s): actual={actual!r} max={max_mode!r}"
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
    try:
        absent = username not in users
    except TypeError:
        return False, f"raw field 'users' is not a container (got {type(users).__name__}); cannot check membership"
    if absent:
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
    try:
        present = username in users
    except TypeError:
        return False, f"raw field 'users' is not a container (got {type(users).__name__}); cannot check membership"
    if present:
        return True, f"user {username!r} is present"
    return False, f"user {username!r} is absent"


# data_* predicates. Contract: ranked collectors ship raw facts only — the
# pass condition lives here, in the rubric, never in the on-box script.

def _get_data_field(raw: dict, field: str):
    """Dotted-path lookup into raw["data"]; _MISSING when absent/not an object."""
    if not isinstance(raw, dict) or not isinstance(raw.get("data"), dict):
        return _MISSING
    node = raw["data"]
    for part in field.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


@register("data_equals")
def _data_equals(matcher: dict, raw: dict) -> tuple:
    field = matcher.get("field", "value")
    expected = _expected_value(matcher, "data_equals")
    if expected is _MISSING:
        return False, f"matcher missing expected value for data field {field!r}"
    actual = _get_data_field(raw, field)
    if actual is _MISSING:
        return False, f"raw data missing field {field!r}"
    if actual == expected:
        return True, f"data.{field}={actual!r} equals expected {expected!r}"
    return False, f"data.{field}={actual!r} does not equal expected {expected!r}"


@register("data_not_equals")
def _data_not_equals(matcher: dict, raw: dict) -> tuple:
    field = matcher.get("field", "value")
    expected = _expected_value(matcher, "data_not_equals")
    if expected is _MISSING:
        return False, f"matcher missing expected value for data field {field!r}"
    actual = _get_data_field(raw, field)
    if actual is _MISSING:
        return False, f"raw data missing field {field!r}"
    if actual != expected:
        return True, f"data.{field}={actual!r} does not equal forbidden {expected!r}"
    return False, f"data.{field}={actual!r} equals forbidden {expected!r}"


@register("data_contains")
def _data_contains(matcher: dict, raw: dict) -> tuple:
    field = matcher.get("field", "value")
    expected = _expected_value(matcher, "data_contains")
    if expected is _MISSING:
        return False, f"matcher missing expected value for data field {field!r}"
    actual = _get_data_field(raw, field)
    if actual is _MISSING:
        return False, f"raw data missing field {field!r}"
    try:
        found = expected in actual
    except TypeError:
        return False, f"data.{field}={actual!r} is not a container/string; cannot check containment"
    if found:
        return True, f"data.{field} contains {expected!r}"
    return False, f"data.{field}={actual!r} does not contain {expected!r}"


@register("data_regex")
def _data_regex(matcher: dict, raw: dict) -> tuple:
    field = matcher.get("field", "value")
    pattern = _expected_value(matcher, "data_regex", "pattern")
    if pattern is _MISSING:
        return False, f"matcher missing pattern for data field {field!r}"
    actual = _get_data_field(raw, field)
    if actual is _MISSING:
        return False, f"raw data missing field {field!r}"
    if actual is None:
        return False, f"data.{field} is None; cannot match pattern {pattern!r}"
    haystack = str(actual)
    if len(haystack) > _REGEX_HAYSTACK_LIMIT:
        return False, f"data.{field} exceeds length limit {_REGEX_HAYSTACK_LIMIT}; not evaluated"
    try:
        compiled = _compile_pattern(pattern)
    except re.error as e:
        return False, f"invalid regex pattern {pattern!r}: {e}"
    try:
        hit = compiled.search(haystack)
    except RecursionError:
        return False, f"regex {pattern!r} hit recursion limit"
    if hit:
        return True, f"data.{field}={actual!r} matches pattern {pattern!r}"
    return False, f"data.{field}={actual!r} does not match pattern {pattern!r}"


@register("data_in_range")
def _data_in_range(matcher: dict, raw: dict) -> tuple:
    field = matcher.get("field", "value")
    lo = matcher.get("min")
    hi = matcher.get("max")
    if lo is None or hi is None:
        return False, "data_in_range requires numeric min and max"
    actual = _get_data_field(raw, field)
    if actual is _MISSING or actual is None:
        return False, f"raw data missing field {field!r}"
    try:
        value = float(actual)
        lo_f, hi_f = float(lo), float(hi)
    except (TypeError, ValueError):
        return False, f"data.{field}={actual!r} is not numeric"
    if lo_f <= value <= hi_f:
        return True, f"data.{field}={actual!r} is within [{lo}, {hi}]"
    return False, f"data.{field}={actual!r} is outside [{lo}, {hi}]"


@register("data_present")
def _data_present(matcher: dict, raw: dict) -> tuple:
    field = matcher.get("field")
    if not field:
        return False, "data_present requires a field"
    actual = _get_data_field(raw, field)
    if actual is _MISSING or actual is None or actual == "":
        return False, f"data.{field} is absent or empty"
    return True, f"data.{field}={actual!r} is present"


@register("data_absent")
def _data_absent(matcher: dict, raw: dict) -> tuple:
    field = matcher.get("field")
    if not field:
        return False, "data_absent requires a field"
    actual = _get_data_field(raw, field)
    if actual is _MISSING or actual is None or actual == "":
        return True, f"data.{field} is absent"
    return False, f"data.{field}={actual!r} is present"


@register("all_of")
def _all_of(matcher: dict, raw: dict) -> tuple:
    sub = matcher.get("matchers")
    if not isinstance(sub, list) or not sub:
        return False, "all_of requires a non-empty 'matchers' list"
    for sub_matcher in sub:
        passed, reason = evaluate_matcher(sub_matcher, raw)
        if not passed:
            return False, f"not all conditions hold: {reason}"
    return True, "all conditions hold"


@register("any_of")
def _any_of(matcher: dict, raw: dict) -> tuple:
    sub = matcher.get("matchers")
    if not isinstance(sub, list) or not sub:
        return False, "any_of requires a non-empty 'matchers' list"
    reasons = []
    for sub_matcher in sub:
        passed, reason = evaluate_matcher(sub_matcher, raw)
        if passed:
            return True, f"at least one condition holds: {reason}"
        reasons.append(reason)
    return False, "no condition holds: " + "; ".join(reasons)


@register("not")
def _not(matcher: dict, raw: dict) -> tuple:
    sub = matcher.get("matcher")
    if not isinstance(sub, dict):
        return False, "not requires a 'matcher' object"
    passed, reason = evaluate_matcher(sub, raw)
    if passed:
        return False, f"negated condition held: {reason}"
    return True, f"negated condition did not hold: {reason}"


@register("group_members_subset_of")
def _group_members_subset_of(matcher: dict, raw: dict) -> tuple:
    group = matcher.get("group")
    allowed = matcher.get("allowed")
    if group is None or allowed is None:
        return False, "matcher missing group or allowed list"
    group_members = _get_raw(raw, "group_members")
    if group_members is _MISSING:
        return False, "raw evidence missing field 'group_members'"
    if not isinstance(group_members, dict):
        return False, f"raw field 'group_members' must be an object (got {type(group_members).__name__})"
    members = group_members.get(group)
    if members is None:
        return False, f"group {group!r} not present in group_members"
    try:
        members_list = list(members)
    except TypeError:
        return False, f"members of {group!r} is not iterable (got {type(members).__name__})"
    allowed_set = set(allowed)
    extra = [m for m in members_list if m not in allowed_set]
    if not extra:
        return True, f"members of {group!r} ({members_list}) are all allowed"
    return False, f"members of {group!r} not in allowed list: {extra}"
