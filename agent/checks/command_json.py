"""`command_json` check type (Linux/POSIX). See architecture.md §9.2.

collect_params: {"script": str (POSIX sh), "timeout_s": number (optional,
overrides the spec timeout for the subprocess ceiling)}.
Evidence.raw shape: {"data": <parsed JSON or None>, "text": str (stdout)}.

The POSIX counterpart to powershell_json: the escape hatch for hardening
evidence that has no first-class check type -- live firewall state
(`iptables-save`, `nft list ruleset`, `ufw status verbose`), listening
sockets (`ss -tlnp`), sysctl values. The script MUST be read-only and MUST
emit a single JSON document on stdout; anything else is ERROR-status
evidence, which fails closed at scoring time.

Trust model is unchanged from the other check types: the manifest is signed
by the authoring key (§16), so collect_params are operator-authored, not
adversary-controlled -- the adversary allowlist (§2.7) has no path here.
Scripts still stay read-only by convention: collection must be
side-effect-free (§9.1).
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
                capture_output=True, text=True,
                timeout=max(timeout, 5.0),
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
            data = json.loads(out)
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
