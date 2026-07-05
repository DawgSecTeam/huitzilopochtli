"""`db_query` check type (SLA-capable). See architecture.md §9.2.

PHASE 1 TASK: implement collect(). Runs a fixed test query on a local socket.
DB driver must remain optional/stdlib-friendly — if no pure-Python driver is
available for the target DB, degrade to a socket-connect probe.
collect_params: {"host": str, "port": int, "query": str | None, ...} (type-specific).
Evidence.raw shape: {"ok": bool, "error": str | None}.
"""
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("db_query")
class DbQueryCheck(Check):
    type_key = "db_query"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        raise NotImplementedError
