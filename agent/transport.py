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
    CollectorStatus,
    CheckResult,
    Directive,
    ScoreBreakdown,
    SlaStatus,
)

_TIMEOUT_S = 10

# Engine request bodies are capped at 1 MiB. Leave headroom for the canonical
# envelope and for JSON escaping, and shrink oversized evidence client-side
# rather than sending a bundle the engine will permanently reject.
MAX_BUNDLE_BYTES = 900_000
_MAX_QUEUE_BUNDLES = 500
_MAX_QUEUE_BYTES = 64 * 1024 * 1024
_MAX_QUEUED_ATTEMPTS = 3


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

    def _directives(key):
        return [
            Directive(
                event_id=d["event_id"],
                action=d["action"],
                params=d.get("params", {}),
            )
            for d in data.get(key) or []
        ]

    directives = _directives("directives")
    # Absent from engines that predate at-least-once delivery.
    issued_directives = _directives("issued_directives")

    return CheckinResponse(
        server_time=data["server_time"],
        score=score,
        directives=directives,
        next_checkin_s=data["next_checkin_s"],
        last_seq=data["last_seq"],
        issued_directives=issued_directives,
    )


def _is_retryable_status(status: int) -> bool:
    """5xx/429 are transient and retryable; 4xx are permanent rejections."""
    return status >= 500 or status == 429


class FatalTransportError(Exception):
    """A configuration error (bad TLS certificate) that retrying cannot fix."""


class _NetworkFailure(Exception):
    """Internal marker: a send attempt failed for transient/network reasons."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


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
        self._fail_path = queue_path + ".fail"
        self._dead_path = queue_path + ".dead"

    # -- queue file helpers ------------------------------------------------

    def _read_queue(self) -> list:
        if not os.path.exists(self.queue_path):
            return []
        try:
            if os.path.getsize(self.queue_path) > _MAX_QUEUE_BYTES:
                print(
                    f"WARNING: transport queue {self.queue_path!r} exceeds "
                    f"{_MAX_QUEUE_BYTES} bytes; keeping the newest "
                    f"{_MAX_QUEUE_BUNDLES} bundles",
                    file=sys.stderr,
                )
        except OSError:
            pass
        with open(self.queue_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line for line in (l.rstrip("\n") for l in f) if line]
        if len(lines) > _MAX_QUEUE_BUNDLES:
            lines = lines[-_MAX_QUEUE_BUNDLES:]
        return lines

    def _write_queue(self, lines: list) -> None:
        # Atomic write via temp file + rename, mode 0600 (bundles carry
        # evidence, including forensics answers).
        tmp_path = self.queue_path + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for line in lines:
                    f.write(line)
                    f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            os.replace(tmp_path, self.queue_path)
        except BaseException:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise

    def _append_queue(self, canonical_line: str) -> None:
        fd = os.open(self.queue_path,
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(canonical_line)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        # Enforce the size cap by trimming the oldest entries.
        lines = self._read_queue()
        if len(lines) > _MAX_QUEUE_BUNDLES:
            self._write_queue(lines[-_MAX_QUEUE_BUNDLES:])

    @staticmethod
    def _line_seq(line: str):
        try:
            value = json.loads(line)
            seq = value.get("seq")
            return seq if isinstance(seq, int) and not isinstance(seq, bool) else None
        except (ValueError, AttributeError):
            return None

    def _read_failures(self) -> dict:
        try:
            with open(self._fail_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): int(v) for k, v in data.items()
                if isinstance(v, int) and not isinstance(v, bool) and v >= 0}

    def _write_failures(self, failures: dict) -> None:
        if not failures:
            try:
                os.remove(self._fail_path)
            except OSError:
                pass
            return
        tmp = self._fail_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(failures, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._fail_path)

    def _bump_failure(self, line: str) -> int:
        seq = self._line_seq(line)
        if seq is None:
            return _MAX_QUEUED_ATTEMPTS  # malformed queue entry: drop it
        failures = self._read_failures()
        key = str(seq)
        count = failures.get(key, 0) + 1
        failures[key] = count
        self._write_failures(failures)
        return count

    def _clear_failure(self, line: str) -> None:
        seq = self._line_seq(line)
        if seq is None:
            return
        failures = self._read_failures()
        if failures.pop(str(seq), None) is not None:
            self._write_failures(failures)

    def _dead_letter(self, line: str, reason: str) -> None:
        """Append a permanently-rejected bundle to a local dead-letter file."""
        try:
            fd = os.open(self._dead_path,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps({"reason": reason, "payload": line}) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as exc:
            print(f"WARNING: could not write dead-letter file: {exc}",
                  file=sys.stderr)

    @staticmethod
    def _shrink_bundle(bundle: Bundle) -> bool:
        """Shrink evidence until the canonical bundle fits the engine cap.

        Returns True if anything was changed. Truncation is always visible in
        the evidence reason; a check whose raw data had to be dropped becomes
        ERROR so it fails closed instead of silently scoring garbage.
        """
        def _truncate_strings(value, limit: int):
            if isinstance(value, str):
                return value if len(value) <= limit else value[:limit]
            if isinstance(value, dict):
                return {k: _truncate_strings(v, limit) for k, v in value.items()}
            if isinstance(value, list):
                return [_truncate_strings(v, limit) for v in value]
            return value

        changed = False
        if len(canonicalize(dataclasses.asdict(bundle))) <= MAX_BUNDLE_BYTES:
            return False
        for ev in bundle.evidence:
            ev.reason = str(ev.reason)[:500]
            ev.raw = _truncate_strings(ev.raw, 2000)
            changed = True
        if len(canonicalize(dataclasses.asdict(bundle))) <= MAX_BUNDLE_BYTES:
            return changed

        # Still too large: drop raw payloads largest-first, turning those
        # checks into explicit ERROR evidence rather than an unsendable bundle.
        def _raw_size(ev):
            return len(canonicalize(ev.raw))

        for ev in sorted(bundle.evidence, key=_raw_size, reverse=True):
            ev.raw = {}
            ev.status = CollectorStatus.ERROR
            ev.reason = "evidence dropped: bundle exceeded the transport size cap"
            if len(canonicalize(dataclasses.asdict(bundle))) <= MAX_BUNDLE_BYTES:
                break
        return True

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
                    f"checkin failed: transient HTTP {e.code}: {e.read()!r}",
                    status=e.code,
                ) from e
            raise self._permanent_rejection(e.code, e.read()) from e
        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                raise FatalTransportError(
                    f"engine TLS certificate verification failed: {e.reason}"
                ) from e
            raise _NetworkFailure(str(e)) from e
        except (
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
                    f"checkin failed: transient HTTP {status}: {resp_body!r}",
                    status=status,
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

    @staticmethod
    def _with_directives(response, extra: list):
        """Prepend `extra` directives to response.directives (duplicates are
        fine: the caller skips event_ids it already ran). None stays None:
        with no usable response there is nothing to attach them to, and the
        engine re-sends them via issued_directives on the next check-in."""
        if response is not None and extra:
            seen = {d.event_id for d in response.directives}
            response.directives = (
                [d for d in extra if d.event_id not in seen] + response.directives
            )
        return response

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
        A queued bundle the engine permanently rejects (non-retryable 4xx) is
        dropped and the flush continues. Raises PermanentRejection only when
        the current `bundle` is rejected; it is dropped, not queued.
        """
        self._shrink_bundle(bundle)
        queued = self._read_queue()
        remaining = list(queued)
        last_response = None  # most recent successful response from any send
        # Directives from flushed queued bundles' responses. The first
        # check-in after a fire time gets the directive, and that may be a
        # queued bundle whose response is superseded below -- carry them
        # into whatever response we return so none is dropped.
        flushed_directives = []

        while remaining:
            line = remaining[0]
            try:
                last_response = self._send_canonical(line.encode("utf-8"))
                flushed_directives.extend(last_response.directives)
                self._clear_failure(line)
            except _NetworkFailure as exc:
                # A 5xx on a queued bundle may be deterministic (e.g. a bad
                # stored rubric): retrying it at the head forever blocks all
                # later evidence. Give it a few tries, then dead-letter it.
                # 503 is the engine's explicit "busy, retry" signal and must
                # never consume an attempt.
                if exc.status >= 500 and exc.status != 503:
                    if self._bump_failure(line) >= _MAX_QUEUED_ATTEMPTS:
                        print(
                            f"WARNING: dead-lettering queued bundle after "
                            f"{_MAX_QUEUED_ATTEMPTS} server errors: {exc}",
                            file=sys.stderr,
                        )
                        self._dead_letter(line, str(exc))
                        self._clear_failure(line)
                        remaining.pop(0)
                        continue
                new_canonical = canonicalize(dataclasses.asdict(bundle))
                self._write_queue(remaining)
                self._append_queue(new_canonical.decode("utf-8"))
                return self._with_directives(last_response, flushed_directives)
            except _ResponseParseFailure as e:
                # Engine accepted this queued bundle (HTTP 200) but the body
                # didn't parse; retrying it would only earn a 409 replay.
                print(
                    f"WARNING: dropping queued bundle the engine accepted but "
                    f"whose response didn't parse: {e}",
                    file=sys.stderr,
                )
                self._clear_failure(line)
            except PermanentRejection as e:
                # A stale queued bundle (e.g. a replay after a crash) is dead,
                # but later entries and the current bundle are not: drop it
                # and keep flushing. Raising here lost the current cycle's
                # evidence even though its seq was already persisted.
                print(
                    f"WARNING: dropping queued bundle the engine permanently "
                    f"rejected: {e}",
                    file=sys.stderr,
                )
                self._clear_failure(line)
            remaining.pop(0)

        if remaining != queued:
            self._write_queue(remaining)

        canonical_bytes = canonicalize(dataclasses.asdict(bundle))
        try:
            return self._with_directives(
                self._send_canonical(canonical_bytes), flushed_directives)
        except _NetworkFailure:
            # Queue the new bundle for next cycle, then return the flushed
            # queued bundle's response — it is the most recent authoritative
            # engine response (score, directives).
            self._append_queue(canonical_bytes.decode("utf-8"))
            return self._with_directives(last_response, flushed_directives)
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
