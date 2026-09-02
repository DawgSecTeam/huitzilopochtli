"""Concurrent check runner. See architecture.md §9.1."""
import concurrent.futures
import time

# Populate CHECKS registry via decorator side-effects.
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
    """Run checks concurrently; hung checks yield TIMEOUT and never stall the run."""
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
                break

        for future in pending:
            idx = future_to_idx[future]
            spec = checks[idx]
            results[idx] = _timeout_evidence(
                spec, time.monotonic() - submitted_at[future]
            )
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return results
