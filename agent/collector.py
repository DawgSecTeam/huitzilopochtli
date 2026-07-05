"""Concurrent check runner. See architecture.md §9.1. PHASE 2 (integration).

Depends on agent.checks.base.CHECKS being populated (Phase 1 check modules
imported) and a PlatformContext from agent.platform.detect.
"""
from common.schema import CheckSpec, Evidence


def run_all(checks: list, ctx: "agent.platform.base.PlatformContext") -> list:
    """Run every CheckSpec concurrently (thread pool), each wrapped with its
    own timeout_s. A hung check yields Evidence(status=TIMEOUT) and never
    stalls the run. Returns list[Evidence] in the same order as `checks`.
    """
    raise NotImplementedError
