"""Concurrent check runner. See architecture.md §9.1. PHASE 2 (integration).

Depends on agent.checks.base.CHECKS being populated (Phase 1 check modules
imported) and a PlatformContext from agent.platform.detect.
"""
import concurrent.futures
import time

# Importing these modules populates agent.checks.base.CHECKS as a side
# effect of their @register decorators (§9.1). agent/checks/__init__.py is
# intentionally empty, so the registrations happen here instead.
import agent.checks.db_query  # noqa: F401
import agent.checks.file_regex  # noqa: F401
import agent.checks.http_uptime  # noqa: F401
import agent.checks.package  # noqa: F401
import agent.checks.permission  # noqa: F401
import agent.checks.service_state  # noqa: F401
import agent.checks.user_group  # noqa: F401
from agent.checks.base import CHECKS
from common.schema import CheckSpec, CollectorStatus, Evidence


def _run_one(spec: CheckSpec, ctx: "agent.platform.base.PlatformContext") -> Evidence:
    """Instantiate and run the check for `spec`. Raises on unknown type or
    any check-level failure; timeouts are handled by the caller via
    future.result(timeout=...)."""
    check_cls = CHECKS[spec.type]
    check = check_cls()
    return check.collect(spec, ctx)


def run_all(checks: list, ctx: "agent.platform.base.PlatformContext") -> list:
    """Run every CheckSpec concurrently (thread pool), each wrapped with its
    own timeout_s. A hung check yields Evidence(status=TIMEOUT) and never
    stalls the run. Returns list[Evidence] in the same order as `checks`.

    NOTE on the timeout guarantee: a hung check is recorded as TIMEOUT and the
    result is returned promptly, but CPython cannot forcibly kill the worker
    thread running it (a blocked syscall or a runaway C-level regex will keep
    running). We therefore shut the executor down with wait=False and
    cancel_futures=True so a not-yet-started or runaway worker never blocks
    run_all's return (an earlier `with ... as executor:` form called
    shutdown(wait=True) on exit and could hang here indefinitely). The leaked
    worker is a daemon-by-nature pool thread that dies with the process.
    """
    def _timeout_evidence(spec: CheckSpec, elapsed: float) -> Evidence:
        return Evidence(
            check_id=spec.id,
            check_type=spec.type,
            host_id=spec.host_id,
            status=CollectorStatus.TIMEOUT,
            raw={},
            reason=(
                f"check {spec.id!r} exceeded timeout_s={spec.timeout_s}s "
                f"(took {elapsed:.2f}s)"
            ),
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )

    results: list = [None] * len(checks)

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=min(20, max(1, len(checks)))
    )
    try:
        future_to_idx = {}
        submitted_at = {}
        for idx, spec in enumerate(checks):
            if spec.type not in CHECKS:
                results[idx] = Evidence(
                    check_id=spec.id,
                    check_type=spec.type,
                    host_id=spec.host_id,
                    status=CollectorStatus.ERROR,
                    raw={},
                    reason=f"unknown check type: {spec.type!r}",
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )
                continue
            future = executor.submit(_run_one, spec, ctx)
            future_to_idx[future] = idx
            submitted_at[future] = time.monotonic()

        # Bound the whole run to ~max(timeout_s) (§9.1 "never stalls the run"):
        # a hung check is recorded TIMEOUT, but the run as a whole must not
        # stall for the SUM of the hung checks' timeouts. Each check's budget
        # is measured from its SUBMISSION time (not from when this loop happens
        # to collect it), so a check that queued behind the 20-worker cap is not
        # spuriously marked TIMEOUT before it ever started.
        deadline = time.monotonic() + max(
            (c.timeout_s for c in checks if c.type in CHECKS), default=0
        )
        pending = set(future_to_idx)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            done, pending = concurrent.futures.wait(pending, timeout=remaining)
            for future in done:
                idx = future_to_idx[future]
                spec = checks[idx]
                elapsed = time.monotonic() - submitted_at[future]
                if elapsed >= spec.timeout_s:
                    # Ran past its own budget (or only surfaced at the global
                    # deadline after never starting): a hung check.
                    results[idx] = _timeout_evidence(spec, elapsed)
                    continue
                try:
                    results[idx] = future.result(timeout=0)
                except Exception as exc:
                    results[idx] = Evidence(
                        check_id=spec.id,
                        check_type=spec.type,
                        host_id=spec.host_id,
                        status=CollectorStatus.ERROR,
                        raw={},
                        reason=f"check {spec.id!r} raised: {exc}",
                        collected_monotonic=time.monotonic(),
                        collected_wall_claim=time.time(),
                    )
            if not done:
                # The deadline elapsed with nothing newly finished.
                break

        # Anything still pending when the global deadline hit never finished in
        # time -- record TIMEOUT rather than leaving a hole in the results.
        for future in pending:
            idx = future_to_idx[future]
            spec = checks[idx]
            results[idx] = _timeout_evidence(
                spec, time.monotonic() - submitted_at[future]
            )
    finally:
        # wait=False: do NOT block on runaway worker threads here. Cancel any
        # not-yet-started futures so they never begin. A genuinely stuck worker
        # (blocked syscall / runaway regex) keeps running but cannot delay this
        # function's return -- exactly the "never stalls the run" contract.
        executor.shutdown(wait=False, cancel_futures=True)

    return results
