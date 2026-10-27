"""Cross-file consistency checks for a practice box.

boxbuilder deliberately does not pair vulns with checks: the author writes both
halves. This is the mechanical half of that discipline — it proves the two
halves still agree, so a box cannot ship a planted finding that nothing scores
(the classic silent failure: a hand-typed path drifts between ``nakon.json``
and the scenario's ``collect`` params and the check either never passes or
passes for free).

Three severities:

``error``    a planted value is scored nowhere. The finding is ungradeable.
``error``    the build inputs do not validate for either target.
``warning``  a scored path that nothing plants (often legitimate: environment
             facts like /etc/shadow), an asset the theme references is missing,
             or a configuration that only exists in the remote catalog.
"""
import json
import os
import re

# Var-name suffixes whose values identify something on the box (a path, a file,
# an account, a unit) and must therefore appear in the paired check.
_IDENTIFYING_SUFFIXES = (
    "_PATH", "_FILE", "_DIR", "_NAME", "_USER", "_USERNAME", "_ACCOUNT",
    "_SERVICE", "_UNIT", "_DROPIN", "_LINE", "_TARGET", "_BINARY", "_LIB",
    "PATH", "FILE", "USER", "USERNAME",
)

# Values that never identify a planted artefact.
_IGNORED_VAR_PARTS = (
    "CONTENT", "TEXT", "SCRIPT", "COMMAND", "CMD", "BODY", "PUBLIC_KEY",
    "PRIVATE_KEY", "PASSWORD", "HASH", "SQL", "MODE", "SCHEDULE", "TIME",
    "PORT", "COUNT", "SLEEP", "INTERVAL", "B64", "CERT", "EXTRA_LINE",
)

# A var whose value is the planted artefact itself: a drift here is always a
# bug (the check reads a path the plant no longer writes).
_PRIMARY_PATH_KEYS = frozenset({"FILE_PATH", "DIR", "TARGET_FILE", "LIB_PATH"})

_MAX_IDENTIFIER_LEN = 200

# Values that are too generic to prove a pairing.
_GENERIC_VALUES = frozenset({
    "root", "admin", "linux", "ubuntu", "windows", "yes", "no", "true", "false",
    "www-data", "nobody",
})


def _looks_identifying(key: str, value: str) -> bool:
    if not isinstance(value, str):
        return False
    value = value.strip()
    if len(value) < 3 or len(value) > _MAX_IDENTIFIER_LEN or value in _GENERIC_VALUES:
        return False
    if "=" in value:  # a config line, not an identifier
        return False
    if _is_ipv4(value):
        return True
    if value.isdigit() or value.replace(".", "").isdigit():
        return False
        return False
    upper = key.upper()
    if any(part in upper for part in _IGNORED_VAR_PARTS):
        return False
    # An absolute path is the strongest identifier there is: it is what the
    # paired check reads, and what historically drifted between the two files.
    if value.startswith("/") or (len(value) > 2 and value[1] == ":" and value[2] in "\\/"):
        return True
    if " " in value:
        return False
    return (upper.endswith(_IDENTIFYING_SUFFIXES)
            or "/" in value
            or "." in value)


def _configuration_items(machine: dict):
    for item in machine.get("configurations") or []:
        if isinstance(item, str):
            yield item, {}
        elif isinstance(item, dict) and item.get("name"):
            yield item["name"], (item.get("vars") or {})


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _normalise(text: str) -> str:
    """Compare Windows and POSIX paths with the same rule."""
    return text.replace("\\\\", "/").replace("\\", "/")


def _check_text(check: dict) -> str:
    """Everything the check asserts about the box, as one searchable string."""
    expect = {k: v for k, v in (check.get("expect") or {}).items() if k != "points"}
    return _normalise(json.dumps({"collect": check.get("collect") or {},
                                  "expect": expect}, sort_keys=True, default=str))


def _ancestors(path: str) -> list:
    """Parent directories of a path, deepest first, stopping before the root."""
    sep = "/"
    parts = path.split(sep)
    out = []
    for end in range(len(parts) - 1, 1, -1):
        ancestor = sep.join(parts[:end])
        if len(ancestor) >= 8:
            out.append(ancestor)
    return out


def _mentioned(value: str, blobs: list) -> bool:
    """True when some check names this value (or its longest distinctive token)."""
    needle = _normalise(value)
    if any(needle in blob for _, blob in blobs):
        return True
    is_path = needle.startswith("/") or (len(needle) > 2 and needle[1] == ":")
    if is_path:
        # A check that scores a directory covers everything under it (removing
        # the tree removes the file); a sibling path must not match.
        for ancestor in _ancestors(needle):
            pattern = re.compile(re.escape(ancestor) + r"(?![A-Za-z0-9._/-])")
            if any(pattern.search(blob) for _, blob in blobs):
                return True
        return False
    tokens = [t for t in needle.replace(":", "/").replace("\\", "/").split("/")
              if len(t) >= 6]
    tokens += [label for label in needle.replace("/", ".").split(".")
               if len(label) >= 6 and not label.isdigit()]
    return bool(tokens) and any(token in blob for token in tokens
                                for _, blob in blobs)


def _effective(spec) -> dict:
    from authoring.scenario_modes import merge_effective
    return merge_effective(spec.scenario, spec.mode,
                           engine_url=spec.engine_url_override,
                           source=spec.scenario_path)


def _effective_checks(spec) -> list:
    return list(_effective(spec)["checks"])


def _forensics_blobs(spec) -> list:
    """Forensics questions/answers also justify a planted artefact's existence."""
    blobs = []
    for question in _effective(spec)["forensics"]:
        if not isinstance(question, dict):
            continue
        text = _normalise(" ".join(str(question.get(key) or "") for key in
                                   ("id", "question", "answer", "answers")))
        blobs.append((f"forensics:{question.get('id')}", text))
    return blobs


def _catalog_errors(spec, nakon_dir: str = None) -> tuple:
    """Ask nakon to validate the authored config against the catalog.

    This is the only check that needs the network (nakon reads vulndb). It is
    opted into with --catalog because a purely offline lint must stay usable.
    """
    import tempfile

    from boxbuilder import nakon

    try:
        ndir = nakon.resolve_nakon_dir(nakon_dir)
    except nakon.NakonError as exc:
        return [f"catalog check unavailable: {exc}"], ["catalog check skipped"]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(spec.nakon_config, f, indent=2)
        path = f.name
    try:
        result = nakon.catalog_check(ndir, path)
    except nakon.NakonError as exc:
        return [f"nakon catalog check failed: {exc}"], []
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    errors, warnings, seen = [], [], set()
    for box in result.get("boxes") or []:
        for problem in box.get("problems") or []:
            if not isinstance(problem, dict):
                continue
            message = str(problem.get("message") or problem)
            if message in seen:
                continue  # the same config selected N times repeats its warning
            seen.add(message)
            where = problem.get("config") or "catalog"
            line = f"nakon catalog check: {where}: {message}"
            if problem.get("level") == "error":
                errors.append(line)
            else:
                warnings.append(line)
    return errors, warnings


def lint_box(spec, seed_dir: str = None, catalog: bool = False,
             nakon_dir: str = None) -> dict:
    """Run every consistency check against one box. Returns a report dict."""
    from boxbuilder import vulndb
    from boxbuilder.spec import validate_inputs

    errors, warnings = [], []

    for target in ("honor", "ranked"):
        try:
            validate_inputs(spec.scenario, spec.nakon_config, mode=target)
        except ValueError as exc:
            message = str(exc)
            if "no ranked variant" in message or "cannot be built as an honor" in message:
                continue
            if target == "ranked" and "unset environment variable" in message:
                # Deployment secrets (a pool template) are not a consistency
                # problem; the box lints fine, it just cannot be built here.
                warnings.append(f"ranked build needs deployment env: {message}")
                continue
            errors.append(f"{target}: {message}")

    checks = _effective_checks(spec)
    if not checks:
        errors.append("scenario has no checks")

    check_ids = [c.get("id") for c in checks if isinstance(c, dict)]
    if len(check_ids) != len(set(check_ids)):
        errors.append("duplicate check ids in the effective scenario")

    blobs = [(c.get("id"), _check_text(c)) for c in checks if isinstance(c, dict)]
    evidence = blobs + _forensics_blobs(spec)
    machine = spec.nakon_machines()[0] if spec.nakon_machines() else {}
    planted = []
    catalog_only = []
    seed_text = []
    for name, variables in _configuration_items(machine):
        if not (vulndb.has_vuln_seed(name) or vulndb.has_theme_seed(name)):
            catalog_only.append(name)
        else:
            try:
                seed = vulndb.load_seed_definition(name)
            except (FileNotFoundError, ValueError):
                seed = None
            if seed:
                seed_text.append(_normalise(json.dumps(seed, default=str)))

        identifiers = [(key, value) for key, value in variables.items()
                       if _looks_identifying(key, value)]
        planted.extend((name, key, value) for key, value in identifiers)

        # A configuration is graded when at least one of the things it plants
        # is named by a check. Supporting details (a payload path behind a unit,
        # a share name behind a permission) need not appear themselves.
        if identifiers and not any(_mentioned(value, evidence) for _, value in identifiers):
            # The seed may hardcode the artefact (a GPP file path, a share the
            # check greps by content). Worth flagging, but it cannot be proven
            # mechanically, so it does not fail the build.
            warnings.append(
                f"{name}: planted {_describe(identifiers)} but no check or "
                f"forensics question names any of it -- confirm this finding is used")

        for key, value in identifiers:
            if key.upper() in _PRIMARY_PATH_KEYS and not _mentioned(value, evidence):
                errors.append(
                    f"{name}.{key}={_short(value)} is the planted artefact but no "
                    f"check reads it (or its directory) and no forensics question "
                    f"asks about it")

    # Reverse direction: a scored path under a writable data root that nothing
    # plants. Restricted to those roots so environment facts (/etc/passwd,
    # /etc/shadow, sshd_config) do not drown the report.
    planted_values = {_normalise(value) for _, _, value in planted}
    said = set()
    for cid, blob in blobs:
        for token in _absolute_paths(blob):
            if token in planted_values or token in said:
                continue
            said.add(token)
            if not token.startswith(("/opt/", "/home/", "/srv/", "/var/backups/", "/var/media/")):
                continue
            if any(token in value or value in token for value in planted_values):
                continue
            if any(token in blob for blob in seed_text):
                continue  # a bundled seed hardcodes this artefact
            warnings.append(f"{cid}: scores {token} but nothing plants it")

    theme = spec.theme
    for key in ("wallpaper", "readme", "logo"):
        rel = theme.get(key)
        if not rel:
            continue
        path = rel if os.path.isabs(rel) else os.path.join(spec.base_dir, rel)
        if not os.path.isfile(path):
            errors.append(f"theme.{key} is missing: {path}")

    if catalog_only:
        warnings.append(
            "configurations with no bundled seed (catalog-only): "
            + ", ".join(sorted(set(catalog_only))))

    if catalog:
        catalog_errors, catalog_warnings = _catalog_errors(spec, nakon_dir)
        errors.extend(catalog_errors)
        warnings.extend(catalog_warnings)

    return {
        "ok": not errors,
        "box": os.path.basename(os.path.dirname(spec.scenario_path)),
        "scenario": os.path.basename(spec.scenario_path),
        "modes": sorted({spec.mode}),
        "checks": len(checks),
        "planted": len(planted),
        "errors": errors,
        "warnings": warnings,
    }


def _short(value: str, limit: int = 80) -> str:
    value = value.replace("\n", " ")
    return value if len(value) <= limit else value[:limit] + "..."


def _describe(identifiers: list, limit: int = 2) -> str:
    parts = [f"{key}={_short(value, 40)}" for key, value in identifiers[:limit]]
    more = "" if len(identifiers) <= limit else f" (+{len(identifiers) - limit} more)"
    return ", ".join(parts) + more


def _absolute_paths(blob: str) -> list:
    """Absolute paths mentioned anywhere in a check blob."""
    found, seen = [], set()
    for token in blob.replace('"', " ").replace("\\", " ").split():
        if token.startswith("/") and len(token) > 3 and token not in seen:
            seen.add(token)
            found.append(token.rstrip(".,'\")"))
    return found
