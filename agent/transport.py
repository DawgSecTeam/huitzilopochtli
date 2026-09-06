"""Push-only transport client with queue-and-forward. Ranked mode only.
See architecture.md §9.5.
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
    """5xx/429 are transient and retryable; 4xx are permanent rejections."""
    return status >= 500 or status == 429


class _NetworkFailure(Exception):
    """Internal marker: a send attempt failed for transient/network reasons."""


class _ResponseParseFailure(Exception):
    """Engine returned 200 but body didn't parse; retry rather than drop."""


class PermanentRejection(Exception):
    """The engine permanently rejected a bundle (non-retryable 4xx; §14.2:
    bad signature / replay / version mismatch are logic bugs, not transient
    failures). The bundle was NOT accepted; callers must not advance seq on
    their own. For replay rejections the engine's authoritative last_seq is
    attached so the caller can resync a desynced local counter."""

    def __init__(self, message: str, status: int = 0, last_seq=None):
        super().__init__(message)
        self.status = status
        self.last_seq = last_seq


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
        # Atomic write via temp file + rename.
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

        Raises _NetworkFailure on transient network errors and
        PermanentRejection on a non-retryable 4xx response.
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
            if _is_retryable_status(e.code):
                raise _NetworkFailure(
                    f"checkin failed: transient HTTP {e.code}: {e.read()!r}"
                ) from e
            raise self._permanent_rejection(e.code, e.read()) from e
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
            raise self._permanent_rejection(status, resp_body)

        try:
            data = json.loads(resp_body.decode("utf-8"))
            return _parse_checkin_response(data)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            raise _ResponseParseFailure(str(e)) from e

    @staticmethod
    def _permanent_rejection(status: int, body: bytes) -> PermanentRejection:
        """Build a PermanentRejection, extracting the engine's authoritative
        last_seq from a replay-style error body when present."""
        last_seq = None
        try:
            data = json.loads(body.decode("utf-8"))
            if isinstance(data, dict) and isinstance(data.get("last_seq"), int):
                last_seq = data["last_seq"]
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        return PermanentRejection(
            f"checkin failed: permanent HTTP {status}: {body!r}",
            status=status,
            last_seq=last_seq,
        )

    # -- public API -----------------------------------------------------

    def checkin(self, bundle: Bundle) -> CheckinResponse:
        """Sign bundle's canonical form, POST to <engine_url>/checkin over TLS.

        On success: flush any previously-queued bundles first (in seq order),
        then send `bundle`, return the parsed CheckinResponse. The response to
        a successfully flushed queued bundle is authoritative too — the most
        recent successful response from any send is returned.

        On network failure: append `bundle` to the queue file and return None.
        On _ResponseParseFailure (engine accepted the bundle but the response
        body was unusable): nothing is queued (a replay would 409 forever) and
        None is returned; the bundle counts as accepted.
        Raises PermanentRejection when the engine rejects a bundle with a
        non-retryable 4xx; the rejected bundle is dropped, earlier queued
        bundles are preserved.
        """
        queued = self._read_queue()
        remaining = list(queued)
        last_response = None  # most recent successful response from any send

        while remaining:
            line = remaining[0]
            try:
                last_response = self._send_canonical(line.encode("utf-8"))
            except _NetworkFailure:
                new_canonical = canonicalize(dataclasses.asdict(bundle))
                self._write_queue(remaining)
                self._append_queue(new_canonical.decode("utf-8"))
                return None
            except _ResponseParseFailure as e:
                # Engine accepted this queued bundle (HTTP 200) but the body
                # didn't parse; retrying it would only earn a 409 replay.
                print(
                    f"WARNING: dropping queued bundle the engine accepted but "
                    f"whose response didn't parse: {e}",
                    file=sys.stderr,
                )
            except PermanentRejection as e:
                self._write_queue(remaining[1:])
                raise
            remaining.pop(0)

        if remaining != queued:
            self._write_queue(remaining)

        canonical_bytes = canonicalize(dataclasses.asdict(bundle))
        try:
            return self._send_canonical(canonical_bytes)
        except _NetworkFailure:
            # Queue the new bundle for next cycle, then return the flushed
            # queued bundle's response — it is the most recent authoritative
            # engine response (score, directives).
            self._append_queue(canonical_bytes.decode("utf-8"))
            return last_response
        except _ResponseParseFailure as e:
            # Engine accepted the current bundle (HTTP 200) but the response
            # body didn't parse. Do NOT queue it: the next cycle would replay
            # an accepted bundle and be permanently 409-rejected.
            print(
                f"WARNING: engine accepted bundle seq={bundle.seq} but its "
                f"response didn't parse (not queued): {e}",
                file=sys.stderr,
            )
            return None
        except PermanentRejection:
            raise
