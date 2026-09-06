"""Thin subprocess wrappers around the nakon CLI.

boxbuilder treats nakon as a CLI dependency (never imports it as a library) --
consistent with how tezcatlipoca consumes nakon and with nakon's documented CLI contract
(see the pinned `vendor/nakon/README.md` submodule).

Contract (mirrors tezcatlipoca):
  - `nakon build --json` prints exactly ONE JSON line on stdout (the summary),
    after any log lines. We parse stdout.splitlines()[-1].
  - `nakon deploy --json` prints a single JSON object on stdout.
  - Logs go to stderr; the result goes to stdout. So `--json | jq` works.

Build needs vulndb reachable + nakon[build]; deploy needs only nakon[deploy]
(paramiko), no vulndb. We run nakon with cwd=NAKON_DIR so it can read its own
.env / config (vulndb creds, bundles dir).
"""
import json
import os
import subprocess
import sys
from pathlib import Path


class NakonError(Exception):
    """Raised when a nakon subprocess fails or emits unparseable JSON."""

    def __init__(self, message: str, *, returncode: int = 0, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def resolve_nakon_dir(explicit: str = None) -> str:
    """Find the nakon repo dir: explicit arg > $NAKON_DIR > vendor/nakon submodule >
    sibling ../nakon checkout (dev). Validates nakon/cli.py."""
    if explicit:
        candidates = [explicit]
    elif os.environ.get("NAKON_DIR"):
        candidates = [os.environ["NAKON_DIR"]]
    else:
        here = os.path.dirname(__file__)
        candidates = [
            os.path.normpath(os.path.join(here, "..", "vendor", "nakon")),  # submodule
            os.path.normpath(os.path.join(here, "..", "..", "nakon")),       # sibling checkout
        ]
    for path in candidates:
        if os.path.isfile(os.path.join(path, "nakon", "cli.py")):
            return path
    raise NakonError(
        f"nakon repo not found (looked for nakon/cli.py in {candidates}). "
        "Set --nakon-dir or $NAKON_DIR."
    )


def _run_nakon(args: list, nakon_dir: str, timeout: int) -> subprocess.CompletedProcess:
    """Run `python3 -m nakon ...` with cwd=nakon_dir, capturing output.

    Raises NakonError on non-zero exit. Returns the CompletedProcess otherwise.
    """
    cmd = [sys.executable, "-m", "nakon", *args]
    try:
        result = subprocess.run(
            cmd,
            cwd=nakon_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise NakonError(f"failed to invoke nakon: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise NakonError(
            f"nakon timed out after {timeout}s: {' '.join(args)}",
            returncode=124,
            stderr=(e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")),
        ) from e

    if result.returncode != 0:
        raise NakonError(
            f"nakon {' '.join(args)} exited {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()[:500]}",
            returncode=result.returncode,
            stderr=result.stderr,
        )
    return result


def build_bundle(
    nakon_dir: str,
    config_path: str,
    out_dir: str = "bundles",
    rebuild: bool = False,
    timeout: int = 900,
) -> dict:
    """Run `nakon build --json`. Returns the parsed summary dict.

    Shape: {"bundle_id", "path", "cached", "plans", "machines"}.
    `path` is absolute (nakon writes it relative to cwd=nakon_dir; we resolve).
    """
    args = ["build", "--config", str(config_path), "--out", str(out_dir), "--json"]
    if rebuild:
        args.append("--rebuild")
    result = _run_nakon(args, nakon_dir, timeout)

    stdout = result.stdout.strip()
    if not stdout:
        raise NakonError("nakon build produced no JSON output", stderr=result.stderr)
    try:
        info = json.loads(stdout.splitlines()[-1])
    except json.JSONDecodeError as e:
        try:
            info = json.loads(stdout)
        except json.JSONDecodeError:
            raise NakonError(
                f"nakon build emitted unparseable JSON: {e}", stderr=result.stderr
            ) from e
    if not isinstance(info, dict):
        raise NakonError(
            f"nakon build emitted {type(info).__name__} instead of a JSON object",
            stderr=result.stderr,
        )

    # nakon's `path` is relative to its cwd; make it absolute for the caller.
    if info.get("path") and not os.path.isabs(info["path"]):
        info["path"] = os.path.normpath(os.path.join(nakon_dir, info["path"]))
    return info


def deploy_bundle(
    nakon_dir: str,
    bundle_path: str,
    config_path: str,
    only: list = None,
    strict: bool = False,
    keep_remote: bool = False,
    timeout: int = 1800,
) -> dict:
    """Run `nakon deploy --json`. Returns the parsed outcome dict.

    Shape: {"bundle_id", "machines":[...], "failures": N, "ok": bool, "log_dir"}.
    Raises NakonError on non-zero exit (deploy exits 1 on failure under
    --strict / NAKON_STRICT).
    """
    args = ["deploy", "--bundle", str(bundle_path), "--config", str(config_path), "--json"]
    if only:
        args += ["--only", *only]
    if strict:
        args.append("--strict")
    if keep_remote:
        args.append("--keep-remote")
    result = _run_nakon(args, nakon_dir, timeout)

    stdout = result.stdout.strip()
    if not stdout:
        raise NakonError("nakon deploy produced no JSON output", stderr=result.stderr)
    try:
        outcome = json.loads(stdout.splitlines()[-1])
    except json.JSONDecodeError as e:
        try:
            outcome = json.loads(stdout)
        except json.JSONDecodeError:
            raise NakonError(
                f"nakon deploy emitted unparseable JSON: {e}", stderr=result.stderr
            ) from e
    if not isinstance(outcome, dict):
        raise NakonError(
            f"nakon deploy emitted {type(outcome).__name__} instead of a JSON object",
            stderr=result.stderr,
        )
    return outcome


def derive_deploy_config(agent_nakon_config: dict, machine_name: str, host: str,
                         user: str, password: str, port: int = 22) -> dict:
    """Address reconciliation: take the vuln list from the agent's nakon
    config for the named machine, but rewrite the address to come from the
    provider handle (the provider is the single source of truth for where the
    box actually is).

    Returns a fresh one-machine nakon config suitable for `nakon deploy`.
    Raises KeyError if `machine_name` is not in the agent config.
    """
    src = None
    for m in agent_nakon_config.get("machines", []):
        if m.get("name") == machine_name:
            src = m
            break
    if src is None:
        raise KeyError(
            f"machine {machine_name!r} not found in nakon config "
            f"(have: {[m.get('name') for m in agent_nakon_config.get('machines', [])]})"
        )

    return {
        "machines": [
            {
                "id": src.get("id", 1),
                "name": src["name"],
                "ip": host,
                "os": src.get("os", "linux"),
                "user": user,
                "password": password,
                "port": port,
                "configurations": list(src.get("configurations", [])),
            }
        ]
    }


def first_machine_name(agent_nakon_config: dict) -> str:
    """The machine boxbuilder targets. v1 is single-box; pick the first."""
    machines = agent_nakon_config.get("machines", [])
    if not machines:
        raise ValueError("nakon config has no machines")
    return machines[0]["name"]
