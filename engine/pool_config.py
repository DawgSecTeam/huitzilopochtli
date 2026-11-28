"""Per-box deployment values for the engine's box-folder source.

Committed ``boxes/<box>/scenario.yaml`` files carry ``${VAR}`` placeholders;
one global env var cannot serve boxes cloning different templates, so the
engine reads a local gitignored map (see pools_path, mode 0600) keyed by
scenario name:

    scenarios:
      "<scenario name>": {template_vm_id: ..., template_vm_password: ...}

A box with no entry falls back to ``${VAR}`` expansion. The file never lives
in the repository.
"""
import os
import threading

import yaml

DEFAULT_PATH = "/etc/huitzilopochtli/pools.yaml"


class PoolConfigError(ValueError):
    """The local pool map is unreadable or malformed."""


def pools_path() -> str:
    return os.environ.get("HUITZILOPOCHTLI_POOLS_FILE", DEFAULT_PATH)


def source_stamp() -> tuple:
    """(path, mtime_ns, size, mode, uid) for the scan cache; a missing file
    is (path, 0, 0, 0, 0). Mode and owner ride the key because chown/chmod
    move neither mtime nor size — a pools file that becomes unreadable
    mid-run must still invalidate the cached scan.
    """
    path = pools_path()
    try:
        st = os.stat(path)
    except OSError:
        return (path, 0, 0, 0, 0)
    return (path, st.st_mtime_ns, st.st_size, st.st_mode, st.st_uid)


def load_overrides(path: str = None) -> dict:
    """Scenario name -> pool mapping. A missing file means no overrides."""
    path = path or pools_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f.read())
    except FileNotFoundError:
        return {}
    except OSError as exc:
        # A root-owned 0600 file on a huitz-run engine is the classic case:
        # the engine sees the path but cannot read it, so say who must be
        # able to read it instead of leaving a bare errno behind.
        hint = ""
        if isinstance(exc, PermissionError):
            hint = (f" (the engine runs as {os.environ.get('USER', '?')}; "
                    f"make the file readable by that user)")
        raise PoolConfigError(f"{path}: {exc}{hint}") from exc
    except yaml.YAMLError as exc:
        raise PoolConfigError(f"{path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PoolConfigError(f"{path}: expected a mapping with 'scenarios'")
    scenarios = data.get("scenarios") or {}
    if not isinstance(scenarios, dict):
        raise PoolConfigError(f"{path}: 'scenarios' must be a mapping")
    out = {}
    for name, pool in scenarios.items():
        if not isinstance(name, str) or not name.strip():
            raise PoolConfigError(f"{path}: scenario names must be non-empty strings")
        if not isinstance(pool, dict) or not pool:
            raise PoolConfigError(f"{path}: scenario {name!r} must map to a pool object")
        out[name] = dict(pool)
    return out


def apply_overrides(parsed: dict, overrides: dict) -> dict:
    """Replace ``ranked.pool`` for the scenario named in the box file."""
    if not isinstance(parsed, dict) or not overrides:
        return parsed
    scenario = parsed.get("scenario") or {}
    name = scenario.get("name") if isinstance(scenario, dict) else None
    pool = overrides.get(name) if isinstance(name, str) else None
    if not pool:
        return parsed
    ranked = parsed.get("ranked")
    if not isinstance(ranked, dict):
        return parsed
    out = dict(parsed)
    out_ranked = dict(ranked)
    out_ranked["pool"] = dict(pool)
    out["ranked"] = out_ranked
    return out
