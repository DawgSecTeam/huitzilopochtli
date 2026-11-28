"""Thin subprocess wrappers around the nakon CLI (a dependency, never
imported as a library; see the pinned vendor/nakon submodule). Contract:
--json puts the result on stdout (logs on stderr): `build` one summary
line, `deploy` one object. Run with cwd=NAKON_DIR so nakon reads its own
.env; build needs vulndb + nakon[build], deploy only nakon[deploy]."""
import json
import os
import subprocess
import sys


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
            os.path.normpath(os.path.join(here, "..", "vendor", "nakon")),
            os.path.normpath(os.path.join(here, "..", "..", "nakon")),
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


def catalog_check(nakon_dir: str, config_path: str, timeout: int = 300) -> dict:
    """`nakon catalog check --config ... --json` (read-only): the one check
    boxbuilder cannot do offline. Raises NakonError on non-zero exit."""
    result = _run_nakon(["catalog", "check", "--config", str(config_path), "--json"],
                        nakon_dir, timeout)
    stdout = result.stdout.strip()
    if not stdout:
        return {}
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        try:
            parsed = json.loads(stdout.splitlines()[-1])
        except json.JSONDecodeError as e:
            raise NakonError(f"nakon catalog check emitted unparseable JSON: {e}",
                             stderr=result.stderr) from e
    return parsed if isinstance(parsed, dict) else {"result": parsed}


def build_bundle(
    nakon_dir: str,
    config_path: str,
    out_dir: str = "bundles",
    timeout: int = 900,
) -> dict:
    """`nakon build --json` -> summary dict {"bundle_id","path","plans",
    "machines"}; `path` is made absolute (builds are fresh, no cache)."""
    args = ["build", "--config", str(config_path), "--out", str(out_dir), "--json"]
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
    """`nakon deploy --json` -> {"bundle_id","machines","failures","ok",
    "log_dir"}; raises NakonError on non-zero exit (strict mode)."""
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
    """Build a one-machine `nakon deploy` config: vuln list from the agent's
    config for `machine_name` (KeyError if absent), address from the provider
    handle — the handle is the single source of truth for where the box is."""
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
