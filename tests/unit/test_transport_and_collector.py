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


# --- BUG-A5: 5xx/429 must be queued-and-retried, not dropped -----------------


def _http_error(code):
    """Build a urllib.error.HTTPError whose .read() yields a body, the shape
    urllib.request.urlopen raises for any non-200 response."""
    import io
    import urllib.error
    return urllib.error.HTTPError(
        url="http://engine.example/checkin", code=code, msg="boom",
        hdrs={}, fp=io.BytesIO(b"error body"),
    )


def test_send_canonical_5xx_is_transient_network_failure():
    # BUG-A5: a 503/504/5xx (engine restart/overload) is transient and must
    # raise _NetworkFailure so checkin() queues the bundle for retry -- NOT a
    # permanent rejection that drops the scored evidence.
    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path="/tmp/unused-q")
    with patch("agent.transport.urllib.request.urlopen",
               side_effect=_http_error(503)):
        try:
            client._send_canonical(b'{"x":1}')
            raise AssertionError("expected _NetworkFailure for 503")
        except _NetworkFailure:
            pass  # correct: queued-and-retried


def test_send_canonical_429_is_transient_network_failure():
    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path="/tmp/unused-q")
    with patch("agent.transport.urllib.request.urlopen",
               side_effect=_http_error(429)):
        try:
            client._send_canonical(b'{"x":1}')
            raise AssertionError("expected _NetworkFailure for 429")
        except _NetworkFailure:
            pass


def test_send_canonical_4xx_is_permanent_rejection():
    # A genuine logic/identity rejection (409 replay) stays a bare Exception:
    # it must NOT be re-queued (it can never succeed).
    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path="/tmp/unused-q")
    with patch("agent.transport.urllib.request.urlopen",
               side_effect=_http_error(409)):
        try:
            client._send_canonical(b'{"x":1}')
            raise AssertionError("expected a permanent rejection for 409")
        except _NetworkFailure:
            raise AssertionError("409 must NOT be a _NetworkFailure")
        except Exception:
            pass  # correct: permanent


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


def test_run_all_multiple_hung_checks_do_not_sum_timeouts(monkeypatch):
    # BUG-A3: timeouts were measured per future.result() call, SEQUENTIALLY, so
    # N hung checks stalled the run by N×timeout_s (and queued checks could be
    # marked TIMEOUT before ever running). The global-deadline fix bounds the
    # whole run to ~max(timeout_s): two hung 0.5s checks must return in ~0.5s,
    # not ~1.0s.
    from agent.checks.base import CHECKS
    monkeypatch.setitem(CHECKS, "_hung_for_test", _HungCheck)

    specs = [
        CheckSpec(
            id=f"hung-{i}", type="_hung_for_test", category=Category.VULN,
            host_id="h", collect_params={}, display_title="t",
            display_max_points=1, timeout_s=0.5,
        )
        for i in range(2)
    ]

    t0 = time.monotonic()
    results = collector.run_all(specs, ctx=None)
    dt = time.monotonic() - t0

    assert dt < 5, f"run_all stalled {dt:.1f}s -- hung checks summed timeouts"
    assert len(results) == 2
    assert all(r.status == CollectorStatus.TIMEOUT for r in results)


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


def test_run_all_caps_workers_at_20():
    # Without a cap, max_workers scaled 1:1 with len(checks), so a scenario
    # with hundreds of checks would spin up hundreds of threads. Cap at 20.
    # Uses a wrapper that records max_workers then delegates to the real
    # ThreadPoolExecutor so the run completes normally.
    class _Echo:
        type_key = "_echo_for_cap_test"
        def collect(self, spec, ctx):
            return Evidence(
                check_id=spec.id, check_type=spec.type, host_id=spec.host_id,
                status=CollectorStatus.OK, raw={}, reason="ok",
                collected_monotonic=time.monotonic(), collected_wall_claim=time.time(),
            )

    captured = {}
    real_tpe = collector.concurrent.futures.ThreadPoolExecutor

    class _RecordingTPE(real_tpe):
        def __init__(self, *args, **kwargs):
            captured["max_workers"] = kwargs.get("max_workers")
            super().__init__(*args, **kwargs)

    specs = [
        CheckSpec(id=f"c{i}", type="_echo_for_cap_test", category=Category.VULN,
                  host_id="h", collect_params={}, display_title="t",
                  display_max_points=1, timeout_s=2.0)
        for i in range(50)  # 50 checks would otherwise spawn 50 threads
    ]
    with patch.dict(collector.CHECKS, {"_echo_for_cap_test": _Echo}, clear=False):
        with patch.object(collector.concurrent.futures, "ThreadPoolExecutor", _RecordingTPE):
            results = collector.run_all(specs, ctx=None)

    assert captured["max_workers"] == 20
    assert len(results) == 50
    assert all(r.status == CollectorStatus.OK for r in results)
