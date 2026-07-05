"""`db_query` check type (SLA-capable). See architecture.md §9.2.

Runs a fixed test query on a local socket. DB driver must remain
optional/stdlib-friendly — since no pure-Python driver is guaranteed
available for a given DB engine, this check is implemented as a
socket-connect probe only (degradation path per §9.2), rather than a
DB-engine-specific SQL query. This keeps the check DB-engine-agnostic.

collect_params: {"host": str, "port": int}.
Evidence.raw shape: {"ok": bool, "error": str | None}.
"""
import socket
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("db_query")
class DbQueryCheck(Check):
    type_key = "db_query"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        host = spec.collect_params["host"]
        port = spec.collect_params["port"]

        try:
            try:
                sock = socket.create_connection((host, port), timeout=spec.timeout_s)
            except socket.gaierror as exc:
                raw = {"ok": False, "error": str(exc)}
                reason = f"could not resolve host {host!r} for {host}:{port}: {exc}"
                return Evidence(
                    check_id=spec.id,
                    check_type=self.type_key,
                    host_id=spec.host_id,
                    status=CollectorStatus.OK,
                    raw=raw,
                    reason=reason,
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )
            except OSError as exc:
                raw = {"ok": False, "error": str(exc)}
                reason = f"connection refused to {host}:{port}: {exc}"
                return Evidence(
                    check_id=spec.id,
                    check_type=self.type_key,
                    host_id=spec.host_id,
                    status=CollectorStatus.OK,
                    raw=raw,
                    reason=reason,
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )
            else:
                sock.close()
                raw = {"ok": True, "error": None}
                reason = f"connected to {host}:{port}"
                return Evidence(
                    check_id=spec.id,
                    check_type=self.type_key,
                    host_id=spec.host_id,
                    status=CollectorStatus.OK,
                    raw=raw,
                    reason=reason,
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )
        except Exception as exc:  # genuinely unexpected failure
            return Evidence(
                check_id=spec.id,
                check_type=self.type_key,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"ok": False, "error": str(exc)},
                reason=f"unexpected error probing {host}:{port}: {exc}",
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
