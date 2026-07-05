"""`package` check type. See architecture.md §9.2, §9.3.

PHASE 1 TASK: implement collect(). Queries the package manager via
ctx.package_installed(name) (agent.platform.base.PlatformContext — already
frozen; does not need platform/pkg.py's body to exist, only the ABC).
collect_params: {"package": str}.
Evidence.raw shape: {"installed": bool, "version": str | None}.
"""
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("package")
class PackageCheck(Check):
    type_key = "package"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        raise NotImplementedError
