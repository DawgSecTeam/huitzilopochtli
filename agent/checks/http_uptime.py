"""`http_uptime` check type (SLA-capable). See architecture.md §9.2.

GET against a local URL using stdlib http.client only.
collect_params: {"url": str}.
Evidence.raw shape: {"status": int | None, "body": str, "error": str | None}.
Note: expected-status / body-substring matching live in the RUBRIC matcher,
not here — this check only reports what it observed (the actual status code
and a bounded excerpt of the response body). It never pre-judges a match,
since it has no access to rubric expectations (collect/evaluate split, §2.1-2.2).
"""
import http.client
import time
import urllib.parse

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence

_BODY_LIMIT = 4096


@register("http_uptime")
class HttpUptimeCheck(Check):
    type_key = "http_uptime"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        url = spec.collect_params["url"]
        collected_monotonic = time.monotonic()
        collected_wall_claim = time.time()

        status = None
        body = ""
        error = None
        conn_status = CollectorStatus.OK
        reason = ""

        conn = None
        try:
            parts = urllib.parse.urlsplit(url)
            scheme = parts.scheme.lower()
            if scheme == "https":
                conn_cls = http.client.HTTPSConnection
            else:
                conn_cls = http.client.HTTPConnection

            host = parts.hostname
            if host is None:
                raise ValueError(f"URL has no host: {url!r}")
            default_port = 443 if scheme == "https" else 80
            port = parts.port or default_port

            path = parts.path or "/"
            if parts.query:
                path = f"{path}?{parts.query}"

            conn = conn_cls(host, port, timeout=spec.timeout_s)
            conn.request("GET", path)
            resp = conn.getresponse()
            status = resp.status
            raw_body = resp.read(_BODY_LIMIT + 1)
            body = raw_body[:_BODY_LIMIT].decode("utf-8", errors="replace")

            reason = f"GET {url} -> {status}"
        except Exception as exc:  # noqa: BLE001 - collector must never raise
            conn_status = CollectorStatus.ERROR
            error = str(exc)
            status = None
            body = ""
            reason = error or "connection failed"
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass

        raw = {"status": status, "body": body, "error": error}

        return Evidence(
            check_id=spec.id,
            check_type=self.type_key,
            host_id=spec.host_id,
            status=conn_status,
            raw=raw,
            reason=reason,
            collected_monotonic=collected_monotonic,
            collected_wall_claim=collected_wall_claim,
        )
