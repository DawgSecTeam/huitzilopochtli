"""`package` check type. See architecture.md §9.2, §9.3.

PHASE 1 TASK: implement collect(). Queries the package manager via
ctx.package_installed(name) (agent.platform.base.PlatformContext — already
frozen; does not need platform/pkg.py's body to exist, only the ABC).
collect_params: {"package": str}.
Evidence.raw shape: {"installed": bool, "version": str | None}.
"""
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("package")
class PackageCheck(Check):
    type_key = "package"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        name = spec.collect_params.get("package")

        try:
            installed, version = ctx.package_installed(name)

            if installed:
                reason = f"{name} installed, version {version}"
            else:
                reason = f"{name} package not installed"

            return Evidence(
                check_id=spec.id,
                check_type=spec.type,
                host_id=spec.host_id,
                status=CollectorStatus.OK,
                raw={"installed": installed, "version": version},
                reason=reason,
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
        except Exception as exc:
            return Evidence(
                check_id=spec.id,
                check_type=spec.type,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"installed": False, "version": None},
                reason=str(exc),
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
