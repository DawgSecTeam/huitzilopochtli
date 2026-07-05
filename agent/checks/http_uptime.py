"""`http_uptime` check type (SLA-capable). See architecture.md §9.2.

PHASE 1 TASK: implement collect(). GET against a local URL using stdlib
http.client only.
collect_params: {"url": str}.
Evidence.raw shape: {"status": int | None, "body_match": bool, "error": str | None}.
Note: body-match substring/expected-status live in the RUBRIC matcher, not
here — this check only reports what it observed.
"""
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("http_uptime")
class HttpUptimeCheck(Check):
    type_key = "http_uptime"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        raise NotImplementedError
