"""`command_json` check type (Linux/POSIX). See architecture.md §9.2.

collect_params: {"script": str (POSIX sh), "timeout_s": number (optional,
overrides the spec timeout for the subprocess ceiling)}.
Evidence.raw shape: {"data": <parsed JSON or None>, "text": str (stdout)}.

The POSIX counterpart to powershell_json: the escape hatch for evidence
with no first-class check type (live firewall state, sockets, sysctls).
The script MUST be read-only and MUST emit a single JSON document on
stdout; anything else is ERROR evidence (fails closed at scoring).
Params are signed-manifest operator input (§16); the adversary allowlist
has no path here (§2.7).
"""
import json
import subprocess
import sys
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("command_json")
class CommandJsonCheck(Check):
    type_key = "command_json"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        if sys.platform == "win32":
            return self._error(
                spec, "command_json is POSIX-only; use powershell_json on Windows"
            )

        script = spec.collect_params.get("script")
        if not script:
            return self._error(spec, "collect_params missing required 'script'")

        try:
            timeout = float(spec.collect_params.get("timeout_s", spec.timeout_s))
        except (TypeError, ValueError):
            return self._error(spec, "collect_params has non-numeric 'timeout_s'")

        try:
            proc = subprocess.run(
                ["/bin/sh", "-c", script],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=max(timeout, 5.0),
            )
        except subprocess.TimeoutExpired:
            return self._error(spec, f"script exceeded {timeout}s")
        except OSError as exc:
            return self._error(spec, f"could not run /bin/sh: {exc}")

        out = (proc.stdout or "").strip()
        if proc.returncode != 0 and not out:
            return self._error(
                spec, f"script exited {proc.returncode}: "
                      f"{(proc.stderr or '').strip()[:200]}"
            )
        if not out:
            return self._error(spec, "script produced no output")

        try:
            data = json.loads(
                out,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON constant {value}")),
            )
        except ValueError:
            return self._error(spec, "script output was not a JSON document")

        return Evidence(
            check_id=spec.id,
            check_type=self.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.OK,
            raw={"data": data, "text": out[:10_000]},
            reason="script output parsed",
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )

    @staticmethod
    def _error(spec: CheckSpec, reason: str) -> Evidence:
        return Evidence(
            check_id=spec.id,
            check_type=CommandJsonCheck.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.ERROR,
            raw={"data": None, "text": None},
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )
