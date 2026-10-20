"""Concurrent check runner. See architecture.md §9.1.

Each check has its own deadline measured from the moment a worker actually
starts it. The old implementation used one global deadline equal to the
*largest* timeout in the scenario; checks still queued behind the concurrency
cap could be marked TIMEOUT without ever running. Checks are therefore run in
daemon threads with a bounded number active at once, and a timed-out check's
logical slot is released immediately (the OS thread may linger, as it always
could with an unkillable check; the daemon flag keeps a one-shot honor run
exitable).
"""
import math
import threading
import time

from common.schema import CheckSpec, CollectorStatus, Evidence

# Populate CHECKS registry via decorator side-effects.
import agent.checks.command_json  # noqa: F401
import agent.checks.db_query  # noqa: F401
import agent.checks.file_regex  # noqa: F401
import agent.checks.forensics  # noqa: F401
import agent.checks.http_uptime  # noqa: F401
import agent.checks.package  # noqa: F401
import agent.checks.permission  # noqa: F401
import agent.checks.powershell_json  # noqa: F401
import agent.checks.process_state  # noqa: F401
import agent.checks.registry_value  # noqa: F401
import agent.checks.service_state  # noqa: F401
import agent.checks.user_group  # noqa: F401
from agent.checks.base import CHECKS

_MAX_CONCURRENCY = 20
_POLL_INTERVAL_S = 0.02


def _run_one(spec: CheckSpec, ctx: "agent.platform.base.PlatformContext") -> Evidence:
    """Instantiate and run the check for `spec`. Raises on any check-level
    failure; the runner translates that into ERROR evidence."""
    check_cls = CHECKS[spec.type]
    check = check_cls()
    return check.collect(spec, ctx)


def _timeout_s(spec: CheckSpec) -> float:
    try:
        value = float(spec.timeout_s)
    except (TypeError, ValueError):
        return 5.0
    return value if math.isfinite(value) and value > 0 else 5.0


def _timeout_evidence(spec: CheckSpec, elapsed: float) -> Evidence:
    return Evidence(
        check_id=spec.id,
        check_type=spec.type,
        host_id=spec.host_id,
        status=CollectorStatus.TIMEOUT,
        raw={},
        reason=(
            f"check {spec.id!r} exceeded timeout_s={_timeout_s(spec)}s "
            f"(took {elapsed:.2f}s)"
        ),
        collected_monotonic=time.monotonic(),
        collected_wall_claim=time.time(),
    )


def _error_evidence(spec: CheckSpec, reason: str) -> Evidence:
    return Evidence(
        check_id=spec.id,
        check_type=spec.type,
        host_id=spec.host_id,
        status=CollectorStatus.ERROR,
        raw={},
        reason=reason,
        collected_monotonic=time.monotonic(),
        collected_wall_claim=time.time(),
    )


def run_all(checks: list, ctx: "agent.platform.base.PlatformContext") -> list:
    """Run checks concurrently; a hung check yields TIMEOUT after its own
    ``timeout_s`` and never stalls the run."""
    n = len(checks)
    if n == 0:
        return []

    results: list = [None] * n
    state = [
        {"started": None, "done": False, "timed_out": False}
        for _ in range(n)
    ]
    active = {"count": 0}
    cond = threading.Condition()
    max_active = min(_MAX_CONCURRENCY, n)

    def worker(idx: int, spec: CheckSpec) -> None:
        with cond:
            while (active["count"] >= max_active
                   and not state[idx]["timed_out"]):
                cond.wait()
            if state[idx]["timed_out"]:
                return
            active["count"] += 1
            state[idx]["started"] = time.monotonic()

        try:
            outcome = _run_one(spec, ctx)
            if not isinstance(outcome, Evidence):
                outcome = _timeout_evidence(
                    spec, time.monotonic() - (state[idx]["started"] or 0.0)
                )
        except Exception as exc:  # noqa: BLE001 - one bad check must not fail the run
            outcome = _error_evidence(spec, f"check {spec.id!r} raised: {exc}")

        with cond:
            if state[idx]["timed_out"]:
                # The main loop already recorded TIMEOUT and released this
                # check's logical slot; discard the late result.
                return
            active["count"] -= 1
            state[idx]["done"] = True
            results[idx] = outcome
            cond.notify_all()

    for idx, spec in enumerate(checks):
        if spec.type not in CHECKS:
            results[idx] = _error_evidence(
                spec, f"unknown check type: {spec.type!r}")
            state[idx]["done"] = True
            continue
        thread = threading.Thread(
            target=worker, args=(idx, spec),
            name=f"huitz-check-{idx}",
            daemon=True,
        )
        thread.start()

    pending = {
        idx for idx in range(n)
        if not state[idx]["done"] and checks[idx].type in CHECKS
    }
    while pending:
        with cond:
            now = time.monotonic()
            for idx in list(pending):
                st = state[idx]
                if st["done"]:
                    pending.discard(idx)
                    continue
                if st["started"] is None:
                    continue
                elapsed = now - st["started"]
                if elapsed >= _timeout_s(checks[idx]):
                    st["timed_out"] = True
                    results[idx] = _timeout_evidence(checks[idx], elapsed)
                    active["count"] = max(0, active["count"] - 1)
                    cond.notify_all()
                    pending.discard(idx)
            if pending:
                cond.wait(timeout=_POLL_INTERVAL_S)

    return results
