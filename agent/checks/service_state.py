"""`service_state` check type. See architecture.md §9.2, §9.3.

PHASE 1 TASK: implement collect(). Queries the init system via
ctx.service_active(name) / ctx.service_enabled(name) (agent.platform.base.PlatformContext
— already frozen; this file does not need platform/systemd.py or openrc.py
bodies to exist, only the ABC).
collect_params: {"service": str}.
Evidence.raw shape: {"active": bool, "enabled": bool}.
"""
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("service_state")
class ServiceStateCheck(Check):
    type_key = "service_state"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        raise NotImplementedError
