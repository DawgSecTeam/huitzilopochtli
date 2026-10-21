"""Adversary pool validation shared by authoring and the engine.

Keeping the closed action vocabulary and the structural checks in one stdlib
module means a scenario cannot pass compile with an action the box executor
will refuse, and the engine upload path cannot drift from the compiler.
"""
import math
import re

#: The closed action vocabulary (architecture §12.2). Adding an action means
#: adding an executor implementation and a validation branch here, together.
ADVERSARY_ACTIONS = frozenset({
    "flush_firewall",
    "kill_service",
    "drop_inert_artifact",
})

#: Service names the adversary may stop. Mirrors the agent executor's guard:
#: the first character cannot be '-' so it is never parsed as an option.
SERVICE_NAME_RE = re.compile(r"[A-Za-z0-9_.@+][A-Za-z0-9_.@+-]*\Z")

_EVENT_KEYS = frozenset({"id", "action", "params", "window_s", "affects_check"})


def _finite_number(value) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def validate_adversary_event(event, index: int, seen_ids: set) -> list:
    """Validate one event; returns human-readable errors."""
    ref = f"adversary.events[{index}]"
    errors = []
    if not isinstance(event, dict):
        return [f"{ref} must be an object"]

    unknown = sorted(set(event) - _EVENT_KEYS)
    if unknown:
        errors.append(f"{ref} has unknown key(s): {', '.join(unknown)}")

    event_id = event.get("id")
    if not isinstance(event_id, str) or not event_id.strip():
        errors.append(f"{ref}.id must be a non-empty string (stable event id)")
    elif event_id in seen_ids:
        errors.append(f"{ref} duplicate event id {event_id!r}")
    else:
        seen_ids.add(event_id)

    action = event.get("action")
    if not isinstance(action, str) or not action:
        errors.append(f"{ref}.action must be a non-empty string")
    elif action not in ADVERSARY_ACTIONS:
        errors.append(
            f"{ref}.action must be one of {sorted(ADVERSARY_ACTIONS)}, got {action!r}"
        )

    window = event.get("window_s")
    if not isinstance(window, (list, tuple)) or len(window) != 2:
        errors.append(f"{ref}.window_s must be [min_s, max_s]")
    elif not all(_finite_number(v) for v in window):
        errors.append(f"{ref}.window_s values must be finite numbers")
    elif window[0] < 0 or window[1] < 0:
        errors.append(f"{ref}.window_s values must be non-negative")
    elif window[0] > window[1]:
        errors.append(f"{ref}.window_s must have min_s <= max_s, got {window!r}")

    params = event.get("params", {})
    if not isinstance(params, dict):
        errors.append(f"{ref}.params must be an object")
    elif action == "kill_service":
        service = params.get("service")
        if not isinstance(service, str) or not SERVICE_NAME_RE.fullmatch(service):
            errors.append(
                f"{ref}.params.service must be a valid service name, got {service!r}"
            )
    elif action == "drop_inert_artifact":
        path = params.get("path")
        if not isinstance(path, str) or not path.strip():
            errors.append(f"{ref}.params.path must be a non-empty string")
        elif path.startswith(("/", "\\")) or ".." in re.split(r"[/\\]", path):
            errors.append(
                f"{ref}.params.path must be relative and stay inside the "
                f"artifact sandbox, got {path!r}"
            )

    affects = event.get("affects_check")
    if affects is not None and (not isinstance(affects, str) or not affects.strip()):
        errors.append(f"{ref}.affects_check must be a non-empty string when present")

    return errors


def validate_adversary_pool(adversary) -> list:
    """Return compile/upload-time errors for an adversary block (empty = valid)."""
    if adversary is None:
        return []
    if not isinstance(adversary, dict):
        return ["adversary must be an object"]
    unknown = sorted(set(adversary) - {"events"})
    if unknown:
        return [f"adversary has unknown key(s): {', '.join(unknown)}"]
    events = adversary.get("events", [])
    if not isinstance(events, list):
        return ["adversary.events must be a list"]
    errors = []
    seen_ids = set()
    for index, event in enumerate(events):
        errors.extend(validate_adversary_event(event, index, seen_ids))
    return errors
