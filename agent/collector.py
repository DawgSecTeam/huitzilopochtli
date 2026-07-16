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
    """
    results: list = [None] * len(checks)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(20, max(1, len(checks)))
    ) as executor:
        future_to_idx = {}
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

        for future, idx in future_to_idx.items():
            spec = checks[idx]
            try:
                results[idx] = future.result(timeout=spec.timeout_s)
            except concurrent.futures.TimeoutError:
                results[idx] = Evidence(
                    check_id=spec.id,
                    check_type=spec.type,
                    host_id=spec.host_id,
                    status=CollectorStatus.TIMEOUT,
                    raw={},
                    reason=(
                        f"check {spec.id!r} exceeded timeout_s={spec.timeout_s}s"
                    ),
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )
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

    return results
