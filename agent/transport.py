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
        remaining = list(queued)

        while remaining:
            line = remaining[0]
            canonical_bytes = line.encode("utf-8")
            try:
                self._send_canonical(canonical_bytes)
            except (_NetworkFailure, _ResponseParseFailure):
                new_canonical = canonicalize(dataclasses.asdict(bundle))
                self._write_queue(remaining)
                self._append_queue(new_canonical.decode("utf-8"))
                return None
            except Exception as e:
                print(
                    f"WARNING: dropping un-sendable queued bundle (permanent "
                    f"rejection): {e}",
                    file=sys.stderr,
                )
                remaining.pop(0)
                continue

            remaining.pop(0)

        if remaining != queued:
            self._write_queue(remaining)

        canonical_bytes = canonicalize(dataclasses.asdict(bundle))
        try:
            return self._send_canonical(canonical_bytes)
        except (_NetworkFailure, _ResponseParseFailure):
            self._append_queue(canonical_bytes.decode("utf-8"))
            return None
        except Exception as e:
            print(
                f"WARNING: dropping un-sendable bundle (permanent rejection): {e}",
                file=sys.stderr,
            )
            return None
