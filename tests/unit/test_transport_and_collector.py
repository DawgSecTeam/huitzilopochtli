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

import pytest
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


def test_checkin_permanent_rejection_of_new_bundle_raises(tmp_path, capsys):
    """A 409/403-style permanent rejection of the new bundle must raise
    PermanentRejection so _run_ranked can keep the loop alive, resync seq from
    the engine, and keep the last-known report. It must NOT be re-queued (that
    would replay-reject forever)."""
    from agent.transport import PermanentRejection

    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path=str(tmp_path / "q"))

    def boom(_canonical_bytes):
        raise PermanentRejection("checkin failed: permanent HTTP 409: replay",
                                 status=409, last_seq=6)

    with patch.object(client, "_send_canonical", side_effect=boom):
        with pytest.raises(PermanentRejection) as exc_info:
            client.checkin(_bundle())

    assert exc_info.value.last_seq == 6
    # And it must NOT have been re-queued (that would replay-loop next cycle).
    assert not (tmp_path / "q").exists()


def test_permanent_rejection_of_queued_bundle_still_sends_current(tmp_path, capsys):
    """A stale queued bundle that the engine permanently rejects (e.g. a 409
    replay after a crash) is dropped -- but the flush must carry on to the
    later queue entries and the current bundle. Raising out of the flush lost
    the current cycle's evidence even though its seq was already persisted
    (round-3 S5 finding)."""
    from agent.transport import PermanentRejection

    client = TransportClient("http://engine.example", FakeIdentity(),
                             queue_path=str(tmp_path / "q"))
    client._write_queue(['{"stale":1}', '{"queued_ok":2}'])
    sent = []
    sentinel = type("Resp", (), {"directives": []})()

    def send(canonical_bytes):
        sent.append(canonical_bytes)
        if canonical_bytes == b'{"stale":1}':
            raise PermanentRejection("checkin failed: permanent HTTP 409: replay",
                                     status=409, last_seq=6)
        return sentinel

    with patch.object(client, "_send_canonical", side_effect=send):
        with patch.object(client, "_with_directives",
                          side_effect=lambda resp, _d: resp):
            result = client.checkin(_bundle())

    assert result is sentinel
    assert len(sent) == 3  # stale (rejected), queued_ok, then the current bundle
    assert b'"seq":7' in sent[-1]
    assert client._read_queue() == []
    assert "dropping queued bundle" in capsys.readouterr().err


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


def test_run_all_caps_active_checks_at_20():
    # A scenario with hundreds of checks must not run them all at once.
    import threading
    lock = threading.Lock()
    counters = {"active": 0, "peak": 0}

    class _SlowEcho:
        type_key = "_slow_echo_cap"
        def collect(self, spec, ctx):
            with lock:
                counters["active"] += 1
                counters["peak"] = max(counters["peak"], counters["active"])
            time.sleep(0.03)
            with lock:
                counters["active"] -= 1
            return Evidence(
                check_id=spec.id, check_type=spec.type, host_id=spec.host_id,
                status=CollectorStatus.OK, raw={}, reason="ok",
                collected_monotonic=time.monotonic(), collected_wall_claim=time.time(),
            )

    specs = [
        CheckSpec(id=f"c{i}", type="_slow_echo_cap", category=Category.VULN,
                  host_id="h", collect_params={}, display_title="t",
                  display_max_points=1, timeout_s=2.0)
        for i in range(50)
    ]
    with patch.dict(collector.CHECKS, {"_slow_echo_cap": _SlowEcho}, clear=False):
        results = collector.run_all(specs, ctx=None)

    assert len(results) == 50
    assert all(r.status == CollectorStatus.OK for r in results)
    assert 1 < counters["peak"] <= 20, counters


def test_many_checks_are_not_timed_out_before_they_start():
    """Regression: one global max(timeout_s) deadline starved queued checks.

    140 checks that each finish well within their own 1s timeout must all be
    OK, even though the whole run takes longer than any single timeout.
    """
    class _Quick:
        type_key = "_quick_for_starvation"
        def collect(self, spec, ctx):
            time.sleep(0.02)
            return Evidence(
                check_id=spec.id, check_type=spec.type, host_id=spec.host_id,
                status=CollectorStatus.OK, raw={}, reason="ok",
                collected_monotonic=time.monotonic(), collected_wall_claim=time.time(),
            )

    specs = [
        CheckSpec(id=f"q{i}", type="_quick_for_starvation", category=Category.VULN,
                  host_id="h", collect_params={}, display_title="t",
                  display_max_points=1, timeout_s=1.0)
        for i in range(140)
    ]
    with patch.dict(collector.CHECKS, {"_quick_for_starvation": _Quick}, clear=False):
        results = collector.run_all(specs, ctx=None)

    assert all(r.status == CollectorStatus.OK for r in results), (
        "checks were timed out before they ever ran")


# --- 1.0: bounded queue, dead-lettering, bundle sizing ----------------------

def _client(tmp_path):
    return TransportClient("http://engine.example", FakeIdentity(),
                           queue_path=str(tmp_path / "q"))


def test_queue_file_is_private_and_capped(tmp_path, monkeypatch):
    import json
    import os
    import agent.transport as transport
    monkeypatch.setattr(transport, "_MAX_QUEUE_BUNDLES", 3)
    client = _client(tmp_path)
    for seq in range(1, 6):
        client._append_queue(json.dumps({"seq": seq}))
    lines = client._read_queue()
    assert [json.loads(line)["seq"] for line in lines] == [3, 4, 5]
    assert (os.stat(client.queue_path).st_mode & 0o777) == 0o600


def test_repeated_server_errors_are_counted_and_dead_lettered(tmp_path):
    import json
    client = _client(tmp_path)
    line = json.dumps({"seq": 7})
    assert [client._bump_failure(line) for _ in range(3)] == [1, 2, 3]
    client._dead_letter(line, "boom")
    client._clear_failure(line)
    assert client._read_failures() == {}
    import json as _json
    dead = _json.loads((tmp_path / "q.dead").read_text())
    assert dead["reason"] == "boom"
    assert _json.loads(dead["payload"])["seq"] == 7


def test_oversized_bundle_is_shrunk_below_engine_cap(tmp_path):
    import agent.transport as transport
    client = _client(tmp_path)
    bundle = _bundle()
    bundle.evidence = [
        Evidence(check_id="big", check_type="command_json", host_id="h",
                 status=CollectorStatus.OK,
                 raw={"data": {"text": "x" * 900_000}},
                 reason="ok", collected_monotonic=0.0, collected_wall_claim=0.0),
    ]
    changed = client._shrink_bundle(bundle)
    assert changed
    from common.canon import canonicalize
    import dataclasses
    assert len(canonicalize(dataclasses.asdict(bundle))) <= transport.MAX_BUNDLE_BYTES


# --- extended check-in response fields (rank / event clock / uptime ticks) ---


def _response_payload(**over):
    payload = {
        "server_time": 500.0,
        "score": {
            "scenario_name": "sc", "scenario_version": 1, "total": 13,
            "results": [],
            "sla_status": [
                {"check_id": "web", "state": "UP", "accrued_points": 3,
                 "history": ["DOWN", "UP"]},
            ],
            "computed_at": 500.0,
        },
        "directives": [],
        "next_checkin_s": 60,
        "last_seq": 7,
        "rank": 2,
        "rank_total": 6,
    }
    payload.update(over)
    return payload


def test_parse_checkin_response_carries_rank_and_uptime_history():
    from agent.transport import _parse_checkin_response
    resp = _parse_checkin_response(_response_payload())
    assert (resp.rank, resp.rank_total) == (2, 6)
    assert resp.score.sla_status[0].history == ["DOWN", "UP"]


def test_parse_checkin_response_tolerates_legacy_engine_fields():
    from agent.transport import _parse_checkin_response
    payload = _response_payload()
    payload.pop("rank")
    payload.pop("rank_total")
    payload["score"]["sla_status"][0].pop("history")
    resp = _parse_checkin_response(payload)
    assert resp.rank is None and resp.rank_total is None
    assert resp.score.sla_status[0].history == []


def test_parse_checkin_response_sanitizes_history_and_rank():
    from agent.transport import _parse_checkin_response
    payload = _response_payload(rank=True, rank_total="6")
    payload["score"]["sla_status"][0]["history"] = ["up", "bogus", "DOWN", 7]
    resp = _parse_checkin_response(payload)
    assert resp.rank is None and resp.rank_total is None
    assert resp.score.sla_status[0].history == ["UP", "DOWN"]
