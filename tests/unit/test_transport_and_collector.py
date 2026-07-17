"""Regression tests for agent/transport.py (BUG-A1) and agent/collector.py (BUG-A2).

BUG-A1: a permanent (non-200, e.g. 409 replay / 403) rejection of the *current*
(new) bundle used to raise a bare Exception out of TransportClient.checkin,
killing the ranked loop; because last_seq was already persisted before the send,
every restart regenerated the same seq and 409'd again -> permanent crash-loop.
The fix catches Exception on the new-bundle send path (mirroring the queued-
bundle path) and returns None so the loop advances its cadence.

BUG-A2: collector.run_all documented "a hung check yields TIMEOUT and never
stalls the run", but the `with ThreadPoolExecutor(...) as executor:` block calls
shutdown(wait=True) on exit, which blocks until a runaway worker thread
finishes -- so any genuinely hung check hung run_all. The fix uses an explicit
executor + shutdown(wait=False, cancel_futures=True).
"""
import time
from unittest.mock import patch

import agent.collector as collector
from agent.transport import TransportClient, _NetworkFailure
from common.schema import Bundle, Category, CheckSpec, CollectorStatus, Evidence


class FakeIdentity:
    box_id = "box-1"
    private_key = b"\x01" * 32


def _bundle():
    return Bundle(
        box_id="box-1", seq=7, boot_id="boot-1", agent_version="x",
        scenario_name="sc", scenario_version=1, evidence=[],
        created_wall_claim=0.0,
    )


# --- BUG-A1: permanent rejection of the new bundle ---------------------------


def test_checkin_permanent_rejection_of_new_bundle_returns_none(tmp_path, capsys):
    """A 409/403-style permanent rejection of the new bundle must NOT raise --
    it returns None so _run_ranked keeps looping. Previously it escaped checkin
    and crash-looped the agent."""
    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path=str(tmp_path / "q"))

    def boom(_canonical_bytes):
        # Mirror _send_canonical's permanent-rejection path: a bare Exception
        # (e.g. "HTTP 409") for a non-200 response.
        raise Exception("checkin failed: HTTP 409: replay")

    with patch.object(client, "_send_canonical", side_effect=boom):
        result = client.checkin(_bundle())

    assert result is None
    # And it must NOT have been re-queued (that would crash-loop next cycle).
    assert not (tmp_path / "q").exists()
    # A warning is logged.
    err = capsys.readouterr().err
    assert "permanent rejection" in err


def test_checkin_transient_failure_of_new_bundle_queues_it(tmp_path):
    """A _NetworkFailure on the new bundle still queues it for later retry
    (existing behavior, must be preserved)."""
    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path=str(tmp_path / "q"))

    with patch.object(client, "_send_canonical", side_effect=_NetworkFailure("down")):
        result = client.checkin(_bundle())

    assert result is None
    q = client._read_queue()
    assert len(q) == 1  # queued for retry, not dropped


def test_checkin_success_returns_response(tmp_path):
    """Happy path still works: an empty queue + a successful send returns the
    parsed response object."""
    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path=str(tmp_path / "q"))
    sentinel = object()

    with patch.object(client, "_send_canonical", return_value=sentinel):
        result = client.checkin(_bundle())

    assert result is sentinel


# --- BUG-A2: a hung check must not stall run_all -----------------------------


class _HungCheck:
    """A registered check whose collect() blocks past the spec timeout
    (simulates a runaway regex / stuck syscall). The collector's timeout must
    record TIMEOUT and run_all must return promptly instead of hanging on
    shutdown(wait=True).

    The block is SHORT (1.5s, just past the 0.5s timeout) so the pool worker
    self-exits shortly after run_all returns -- this keeps the test's process
    from being pinned by a non-daemon ThreadPoolExecutor worker (CPython can't
    interrupt a blocked worker, and pool workers are non-daemon). The real
    production risk (a permanently stuck worker) is about run_all not blocking,
    which this test asserts via the wall-clock bound below."""
    type_key = "_hung_for_test"

    def collect(self, spec, ctx):
        import threading
        # Block 1.5s; spec timeout is 0.5s -> run_all records TIMEOUT at ~0.5s
        # while this worker keeps running until ~1.5s, then exits on its own.
        threading.Event().wait(timeout=1.5)


def test_run_all_does_not_hang_on_runaway_check(monkeypatch):
    # Register the hung check type for the duration of the test.
    from agent.checks.base import CHECKS
    monkeypatch.setitem(CHECKS, "_hung_for_test", _HungCheck)

    spec = CheckSpec(
        id="hung-1", type="_hung_for_test", category=Category.VULN,
        host_id="h", collect_params={}, display_title="t",
        display_max_points=1, timeout_s=0.5,
    )

    t0 = time.monotonic()
    results = collector.run_all([spec], ctx=None)
    dt = time.monotonic() - t0

    # Before the fix this hung ~30s on shutdown(wait=True). With the fix it
    # returns shortly after the 0.5s timeout.
    assert dt < 5, f"run_all stalled for {dt:.1f}s -- shutdown(wait=True) hang"
    assert len(results) == 1
    assert results[0].status == CollectorStatus.TIMEOUT
    assert "hung-1" in results[0].reason


def test_run_all_unknown_check_type_yields_error_without_submitting():
    spec = CheckSpec(
        id="bad-1", type="no_such_type", category=Category.VULN,
        host_id="h", collect_params={}, display_title="t",
        display_max_points=1, timeout_s=1.0,
    )
    results = collector.run_all([spec], ctx=None)
    assert len(results) == 1
    assert results[0].status == CollectorStatus.ERROR
    assert "unknown check type" in results[0].reason


def test_run_all_returns_results_in_input_order():
    # Several fast checks; results must align to checks order regardless of
    # thread scheduling. The check echoes spec.id into the evidence reason so
    # each result is distinguishable.
    class _Echo:
        type_key = "_echo_for_test"
        def collect(self, spec, ctx):
            return Evidence(
                check_id=spec.id, check_type=spec.type, host_id=spec.host_id,
                status=CollectorStatus.OK, raw={"id": spec.id}, reason=f"ok-{spec.id}",
                collected_monotonic=time.monotonic(), collected_wall_claim=time.time(),
            )

    with patch.dict(collector.CHECKS, {"_echo_for_test": _Echo}, clear=False):
        specs = [
            CheckSpec(id=f"f{i}", type="_echo_for_test", category=Category.VULN,
                      host_id="h", collect_params={}, display_title="t",
                      display_max_points=1, timeout_s=2.0)
            for i in range(3)
        ]
        results = collector.run_all(specs, ctx=None)

    assert [r.check_id for r in results] == ["f0", "f1", "f2"]
    assert all(r.status == CollectorStatus.OK for r in results)
    assert [r.raw["id"] for r in results] == ["f0", "f1", "f2"]
