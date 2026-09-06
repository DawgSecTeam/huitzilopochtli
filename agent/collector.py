"""Concurrent check runner. See architecture.md §9.1."""
import concurrent.futures
import threading
import time
import weakref

from common.schema import CheckSpec, CollectorStatus, Evidence

# Extra time past the global deadline granted to checks that finished just
# past their own timeout_s; bounded so the run still terminates (§9.1).
_LATE_GRACE_S = 2.0

# Populate CHECKS registry via decorator side-effects.
import agent.checks.db_query  # noqa: F401
import agent.checks.file_regex  # noqa: F401
import agent.checks.forensics  # noqa: F401
import agent.checks.http_uptime  # noqa: F401
import agent.checks.package  # noqa: F401
import agent.checks.permission  # noqa: F401
import agent.checks.service_state  # noqa: F401
import agent.checks.user_group  # noqa: F401
from agent.checks.base import CHECKS


def _run_one(spec: CheckSpec, ctx: "agent.platform.base.PlatformContext") -> Evidence:
    """Instantiate and run the check for `spec`. Raises on unknown type or
    any check-level failure; timeouts are handled by the caller via
    future.result(timeout=...)."""
    check_cls = CHECKS[spec.type]
    check = check_cls()
    return check.collect(spec, ctx)


class _DaemonThreadPoolExecutor(concurrent.futures.ThreadPoolExecutor):
    """ThreadPoolExecutor whose worker threads are daemonized.

    A check that ignores its deadline (e.g. a subprocess-less hang) can never
    be cancelled from outside; daemon threads let the one-shot honor-mode run
    still exit instead of blocking forever on a hung worker (§9.1). Mirrors
    the stdlib _adjust_thread_count so the daemon flag lands before
    Thread.start(), where it is required; re-verify on stdlib upgrades.

    Version-tolerant: 3.14 passes a worker context
    (``_create_worker_context``) as the second _worker arg, while 3.12
    passes ``(work_queue, initializer, initargs)`` and has no
    ``_create_worker_context``. Probe for the method instead of the version
    so the same zipapp runs on the box's 3.12 and the dev machine's 3.14.
    """

    def _adjust_thread_count(self):
        # if idle threads are available, don't spin new threads
        if self._idle_semaphore.acquire(timeout=0):
            return

        # When the executor gets lost, the weakref callback will wake up
        # the worker threads.
        def weakref_cb(_, q=self._work_queue):
            q.put(None)

        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = '%s_%d' % (self._thread_name_prefix or self,
                                      num_threads)
            if hasattr(self, "_create_worker_context"):
                args = (weakref.ref(self, weakref_cb),
                        self._create_worker_context(),
                        self._work_queue)
            else:  # Python <= 3.13: no worker-context support.
                args = (weakref.ref(self, weakref_cb),
                        self._work_queue,
                        self._initializer,
                        self._initargs)
            t = threading.Thread(name=thread_name, target=concurrent.futures.thread._worker,
                                  args=args)
            t.daemon = True
            t.start()
            self._threads.add(t)
            concurrent.futures.thread._threads_queues[t] = self._work_queue


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

    def _finalize(idx: int, future) -> None:
        """Collect a completed future: real evidence if the check produced
        it (even late — a finished check's answer is not discarded for being
        merely slow), error evidence on raise, timeout evidence if the check
        violated its contract (returned nothing)."""
        spec = checks[idx]
        try:
            outcome = future.result(timeout=0)
        except Exception as exc:
            results[idx] = Evidence(
                check_id=spec.id, check_type=spec.type, host_id=spec.host_id,
                status=CollectorStatus.ERROR, raw={},
                reason=f"check {spec.id!r} raised: {exc}",
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
            return
        if not isinstance(outcome, Evidence):
            results[idx] = _timeout_evidence(
                spec, time.monotonic() - submitted_at[future]
            )
        else:
            results[idx] = outcome

    executor = _DaemonThreadPoolExecutor(
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
                # Grace window: a check that finished just past its own
                # timeout_s still has real evidence; give slow-but-finite
                # checks one short chance to land before we call them hung.
                done, pending = concurrent.futures.wait(
                    pending, timeout=_LATE_GRACE_S
                )
                for future in done:
                    _finalize(future_to_idx[future], future)
                break
            done, pending = concurrent.futures.wait(pending, timeout=remaining)
            for future in done:
                # A check that completed keeps its evidence even if it blew
                # past its own timeout_s — the result is real and dropping it
                # would discard a correct answer for being merely slow.
                _finalize(future_to_idx[future], future)

        for future in pending:
            idx = future_to_idx[future]
            spec = checks[idx]
            results[idx] = _timeout_evidence(
                spec, time.monotonic() - submitted_at[future]
            )
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    return results
