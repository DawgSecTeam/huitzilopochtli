"""`service_state` check type. See architecture.md §9.2, §9.3.

PHASE 1 TASK: implement collect(). Queries the init system via
ctx.service_active(name) / ctx.service_enabled(name) (agent.platform.base.PlatformContext
— already frozen; this file does not need platform/systemd.py or openrc.py
bodies to exist, only the ABC).
collect_params: {"service": str}.
Evidence.raw shape: {"active": bool, "enabled": bool}.
"""
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("service_state")
class ServiceStateCheck(Check):
    type_key = "service_state"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        name = spec.collect_params.get("service")
        if not name:
            return Evidence(
                check_id=spec.id,
                check_type=self.type_key,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"active": False, "enabled": False},
                reason="collect_params missing required 'service'",
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )

        try:
            active = ctx.service_active(name)
            enabled = ctx.service_enabled(name)
        except Exception as exc:
            return Evidence(
                check_id=spec.id,
                check_type=self.type_key,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"active": False, "enabled": False},
                reason=str(exc),
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )

        return Evidence(
            check_id=spec.id,
            check_type=self.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.OK,
            raw={"active": active, "enabled": enabled},
            reason=f"{name} active={active} enabled={enabled}",
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )
