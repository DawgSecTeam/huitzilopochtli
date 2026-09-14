"""`registry_value` check type (Windows). See architecture.md §9.2.

collect_params: {"hive": str ("HKLM"|"HKCU"|"HKCR"|"HKU"|"HKCC"),
                 "key": str (subkey path, raw string, no leading backslash),
                 "value": str (value name, "" for the default value)}.
Evidence.raw shape: {"present": bool, "value": str|int|None, "type": str|None}.

Reads via winreg (stdlib) with the 64-bit view preferred and the 32-bit view
as fallback, so checks are stable regardless of the agent's own bitness. A
missing key/value is OK-status evidence with present=false -- never an ERROR
-- so "this insecure value must not exist" checks can match on present/value
directly and fail closed correctly.
"""
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence

_HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}


def _read_value(hive, key_path: str, value_name: str):
    """(present, value, type_name) -- 64-bit view first, 32-bit fallback."""
    try:
        import winreg
    except ImportError:
        raise RuntimeError("registry_value requires Windows (winreg)")
    for access in (winreg.KEY_READ | winreg.KEY_WOW64_64KEY, winreg.KEY_READ):
        try:
            with winreg.OpenKey(hive, key_path, 0, access) as key:
                value, type_id = winreg.QueryValueEx(key, value_name)
                return True, _json_safe(value), _type_name(type_id)
        except FileNotFoundError:
            return False, None, None
        except OSError:
            continue  # e.g. WOW64 access denied on some keys -- retry 32-bit
    return False, None, None


_TYPE_NAMES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 11: "REG_QWORD",
}


def _type_name(type_id: int) -> str:
    return _TYPE_NAMES.get(type_id, f"REG_UNKNOWN({type_id})")


def _json_safe(value):
    """Registry values must survive Evidence JSON serialization: REG_BINARY
    (and any other bytes) become a hex string."""
    if isinstance(value, bytes):
        return value.hex()
    return value


@register("registry_value")
class RegistryValueCheck(Check):
    type_key = "registry_value"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        hive_name = spec.collect_params.get("hive")
        key_path = spec.collect_params.get("key")
        value_name = spec.collect_params.get("value", "")
        if not hive_name or not key_path:
            return self._error(
                spec, "collect_params missing required 'hive' and 'key'"
            )
        hive_attr = _HIVES.get(str(hive_name).upper())
        if hive_attr is None:
            return self._error(
                spec, f"unknown hive {hive_name!r} (want one of {sorted(_HIVES)})"
            )

        try:
            import winreg  # noqa: F401 -- presence gate for the whole type
        except ImportError:
            return self._error(spec, "registry_value requires Windows (winreg)")

        try:
            hive = getattr(winreg, hive_attr)
            present, value, type_name = _read_value(hive, key_path, value_name)
        except Exception as exc:
            return self._error(spec, f"collection error: {exc}")

        reason = (
            f"{hive_name}\\{key_path}\\{value_name or '(default)'} present, "
            f"type={type_name}, value={value!r}"
            if present
            else f"{hive_name}\\{key_path} (or its '{value_name}' value) not present"
        )
        return Evidence(
            check_id=spec.id,
            check_type=self.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.OK,
            raw={"present": present, "value": value, "type": type_name},
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )

    @staticmethod
    def _error(spec: CheckSpec, reason: str) -> Evidence:
        return Evidence(
            check_id=spec.id,
            check_type=RegistryValueCheck.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.ERROR,
            raw={"present": None, "value": None, "type": None},
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )
