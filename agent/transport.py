"""Push-only transport client with queue-and-forward. Ranked mode only.
See architecture.md §9.5.

FROZEN signature (agreed for parallel build); body is a PHASE 1 TASK.
"""
import base64
import dataclasses
import json
import os
import socket
import sys
import ssl
import urllib.error
import urllib.request

from common.canon import canonicalize
from common.crypto import signing
from common.schema import (
    Bundle,
    Category,
    CheckinResponse,
    CheckResult,
    Directive,
    ScoreBreakdown,
    SlaStatus,
)

_TIMEOUT_S = 10


def _parse_checkin_response(data: dict) -> CheckinResponse:
    """Reconstruct a CheckinResponse (with nested dataclasses) from the raw
    JSON-decoded dict returned by the engine (§14.2)."""
    score_data = data.get("score") or {}

    results = [
        CheckResult(
            check_id=r["check_id"],
            category=Category(r["category"]),
            awarded_points=r["awarded_points"],
            passed=r["passed"],
            reason=r["reason"],
        )
        for r in score_data.get("results", [])
    ]

    sla_status = [
        SlaStatus(
            check_id=s["check_id"],
            state=s["state"],
            accrued_points=s["accrued_points"],
        )
        for s in score_data.get("sla_status", [])
    ]

    score = ScoreBreakdown(
        scenario_name=score_data.get("scenario_name"),
        scenario_version=score_data.get("scenario_version"),
        # Default numeric fields so a response that omits `score` (or its
        # `total`) renders as "Total: 0" rather than the confusing "Total: None"
        # in the report. A well-formed engine always includes these.
        total=score_data.get("total", 0) or 0,
        results=results,
        sla_status=sla_status,
        computed_at=score_data.get("computed_at"),
    )

    directives = [
        Directive(
            event_id=d["event_id"],
            action=d["action"],
            params=d.get("params", {}),
        )
        for d in data.get("directives", [])
    ]

    return CheckinResponse(
        server_time=data["server_time"],
        score=score,
        directives=directives,
        next_checkin_s=data["next_checkin_s"],
        last_seq=data["last_seq"],
    )


def _is_retryable_status(status: int) -> bool:
    """A transient server/rate-limit response is retryable (queue-and-forward);
    4xx codes (403 bad sig, 409 replay, 410 expired, 400 malformed, §14.2) are
    permanent logic rejections and must NOT be re-queued (they can never
    succeed)."""
    return status >= 500 or status == 429


class _NetworkFailure(Exception):
    """Internal marker: a send attempt failed for transient/network reasons."""


class _ResponseParseFailure(Exception):
    """Internal marker: the engine returned HTTP 200 but the body didn't
    parse into a CheckinResponse (missing/renamed field, malformed JSON).

    This is NOT a rejection of the bundle — the engine may well have
    accepted and scored it. Treated like _NetworkFailure (retry later)
    rather than a permanent rejection, so a transient/format bug on the
    engine side doesn't silently drop scored evidence."""


class TransportClient:
    def __init__(self, engine_url: str, identity: "agent.identity.Identity",
                 queue_path: str):
        """queue_path is an append-only local file used to persist signed
        bundles that failed to send, preserving seq/evidence, for retry on
        the next cycle (§9.5)."""
        self.engine_url = engine_url.rstrip("/")
        self.identity = identity
        self.queue_path = queue_path

    # -- queue file helpers ------------------------------------------------

    def _read_queue(self) -> list:
        if not os.path.exists(self.queue_path):
            return []
        with open(self.queue_path, "r", encoding="utf-8") as f:
            return [line for line in (l.rstrip("\n") for l in f) if line]

    def _write_queue(self, lines: list) -> None:
        # Write to a temp file and atomically rename into place, so a crash
        # mid-write can never leave a truncated/corrupt queue that would poison
        # every subsequent flush. os.replace is atomic on POSIX within a dir.
        tmp_path = self.queue_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line)
                f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.queue_path)

    def _append_queue(self, canonical_line: str) -> None:
        with open(self.queue_path, "a", encoding="utf-8") as f:
            f.write(canonical_line)
            f.write("\n")

    # -- wire send ----------------------------------------------------------

    def _send_canonical(self, canonical_bytes: bytes) -> CheckinResponse:
        """POST already-canonicalized bundle bytes to the engine.

        Raises _NetworkFailure on transient network errors, or a plain
        Exception on a non-200 response (§14.2: bad signature / replay /
        version mismatch are logic bugs, not transient failures).
        """
        sig = signing.sign(self.identity.private_key, canonical_bytes)
        headers = {
            "Content-Type": "application/json",
            "X-HUITZILOPOCHTLI-Sig": base64.b64encode(sig).decode("ascii"),
            "X-HUITZILOPOCHTLI-Box": self.identity.box_id,
        }
        req = urllib.request.Request(
            f"{self.engine_url}/checkin",
            data=canonical_bytes,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                status = resp.status
                resp_body = resp.read()
        except urllib.error.HTTPError as e:
            # Non-200. A 5xx/429 is transient (engine restart/overload) and
            # must be queued-and-retried, NOT dropped. Only genuine logic/
            # identity rejections (403 bad sig, 409 replay, 410 expired, 400
            # malformed -- §14.2) are permanent.
            body = e.read()
            if _is_retryable_status(e.code):
                raise _NetworkFailure(
                    f"checkin failed: transient HTTP {e.code}: {body!r}"
                ) from e
            raise Exception(
                f"checkin failed: HTTP {e.code}: {body!r}"
            ) from e
        except (
            urllib.error.URLError,
            ConnectionError,
            ConnectionRefusedError,
            TimeoutError,
            socket.timeout,
            socket.gaierror,
            ssl.SSLError,
            OSError,
        ) as e:
            raise _NetworkFailure(str(e)) from e

        if status != 200:
            if _is_retryable_status(status):
                raise _NetworkFailure(
                    f"checkin failed: transient HTTP {status}: {resp_body!r}"
                )
            raise Exception(f"checkin failed: HTTP {status}: {resp_body!r}")

        try:
            data = json.loads(resp_body.decode("utf-8"))
            return _parse_checkin_response(data)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            raise _ResponseParseFailure(str(e)) from e

    # -- public API -----------------------------------------------------

    def checkin(self, bundle: Bundle) -> CheckinResponse:
        """Sign bundle's canonical form, POST to <engine_url>/checkin over TLS.

        On success: flush any previously-queued bundles first (in seq order),
        then send `bundle`, return the parsed CheckinResponse.
        On network failure: append `bundle` to the queue file and return None.
        """
        queued = self._read_queue()
        # Work on a copy and persist it once at the end (or once on early
        # exit below), rather than rewriting + fsyncing the whole queue file
        # after every single entry. The old per-pop write made draining an
        # N-bundle backlog O(n^2) file I/O; a batch write is O(n).
        remaining = list(queued)

        while remaining:
            line = remaining[0]
            canonical_bytes = line.encode("utf-8")
            try:
                self._send_canonical(canonical_bytes)
            except (_NetworkFailure, _ResponseParseFailure):
                # Stop flushing; queue the new bundle behind what's left
                # (don't send it out of order), persist, and bail out. A
                # parse failure means we can't tell whether the engine
                # accepted this bundle, so retry it rather than drop it —
                # if it was already accepted, the retry will cleanly hit a
                # 409 replay and get dropped by the branch below instead.
                new_canonical = canonicalize(dataclasses.asdict(bundle))
                self._write_queue(remaining)
                self._append_queue(new_canonical.decode("utf-8"))
                return None
            except Exception as e:
                # A permanent (non-transient) rejection of a QUEUED bundle, most
                # commonly a 409 replay: the engine already recorded this seq
                # (e.g. we crashed after it accepted the check-in but before we
                # popped the queue). Retrying it forever would make the agent
                # crash-loop on every restart. It can never succeed, so drop the
                # poison bundle and keep flushing the rest instead of letting the
                # exception kill the agent.
                print(
                    f"WARNING: dropping un-sendable queued bundle (permanent "
                    f"rejection): {e}",
                    file=sys.stderr,
                )
                remaining.pop(0)
                continue

            # Successfully flushed; drop it and move on.
            remaining.pop(0)

        # Queue fully drained (everything sent or dropped as poison): persist
        # the (now-empty) queue once, if anything changed.
        if remaining != queued:
            self._write_queue(remaining)

        # Queue empty (or fully flushed): send the new bundle.
        canonical_bytes = canonicalize(dataclasses.asdict(bundle))
        try:
            return self._send_canonical(canonical_bytes)
        except (_NetworkFailure, _ResponseParseFailure):
            # See the matching comment in the flush loop above: a parse
            # failure doesn't tell us whether the engine accepted this
            # bundle, so queue it for retry instead of dropping it.
            self._append_queue(canonical_bytes.decode("utf-8"))
            return None
        except Exception as e:
            # A permanent (non-transient) rejection of the NEW bundle, e.g. a
            # 409 replay (the engine already recorded this seq after it accepted
            # the check-in but before the caller persisted last_seq) or a 403.
            # Mirrors the queued-bundle path above: it can never succeed, so
            # drop it and let the loop advance its cadence rather than letting
            # the exception kill the ranked loop. CRUCIALLY do NOT re-queue it:
            # that would make the agent crash-loop on every cycle/restart.
            # The caller has already persisted identity.last_seq before calling
            # checkin (see agent/__main__.py), so the next cycle builds a fresh,
            # strictly-greater seq and the run continues.
            print(
                f"WARNING: dropping un-sendable bundle (permanent rejection): {e}",
                file=sys.stderr,
            )
            return None
