"""Matcher registry. See architecture.md §10.2.

A matcher is a small tagged dict evaluated against a check type's `raw`
evidence dict. Each predicate is a pure function `(matcher, raw) -> (bool, reason)`.

PHASE 1 TASK: implement the predicates below (equals, not_equals, contains,
regex, mode_at_most, user_absent, user_present, group_members_subset_of).
The registry mechanism itself (this scaffold) is frozen — do not change
MATCHERS / register / evaluate_matcher's signatures.
"""
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
    """
    tag = matcher["tag"]
    return MATCHERS[tag](matcher, raw)


# --- PHASE 1: implement each predicate below, e.g. -------------------------
#
# @register("equals")
# def _equals(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
#
# @register("not_equals")
# def _not_equals(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
#
# @register("contains")
# def _contains(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
#
# @register("regex")
# def _regex(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
#
# @register("mode_at_most")
# def _mode_at_most(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
#
# @register("user_absent")
# def _user_absent(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
#
# @register("user_present")
# def _user_present(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
#
# @register("group_members_subset_of")
# def _group_members_subset_of(matcher: dict, raw: dict) -> tuple:
#     raise NotImplementedError
