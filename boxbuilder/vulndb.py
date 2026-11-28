"""boxbuilder's vulndb catalog client — a thin wrapper around the
vulndb-cli subprocess (the sanctioned client; the HTTP contract lives
there). Semantics: ensure_configuration is create-if-missing (sync=True
converges drifted rows onto the bundled seed); ensure_attachment is
content-addressed: identical bytes reuse one attachment."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

_DEFAULT_VULNDB_URL = "http://127.0.0.1:3000"
_BOXBUILDER_DIR = os.path.dirname(os.path.abspath(__file__))
_THEME_SEED_DIR = os.path.join(_BOXBUILDER_DIR, "vulndb_theme_configs")
_VULN_SEED_DIR = os.path.join(_BOXBUILDER_DIR, "vulndb_vuln_configs")


class VulndbError(Exception):
    """Raised when a vulndb-cli subprocess fails or emits unparseable JSON."""

    def __init__(self, message: str, *, returncode: int = 0, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def resolve_vulndb_url(explicit: str = None) -> str:
    """explicit arg > $VULNDB_UI_URL > http://127.0.0.1:3000 — the same env var name and default
    vulndb-cli itself uses, so one VULNDB_UI_URL in the environment covers both tools."""
    return explicit or os.environ.get("VULNDB_UI_URL") or _DEFAULT_VULNDB_URL


def resolve_vulndb_cli_dir(explicit: str = None) -> str:
    """Find the vulndb-cli repo dir: explicit arg > $VULNDB_CLI_DIR > vendor/vulndb-cli submodule
    > sibling ../vulndb-cli checkout (dev). Validates vulndb_cli/cli.py."""
    if explicit:
        candidates = [explicit]
    elif os.environ.get("VULNDB_CLI_DIR"):
        candidates = [os.environ["VULNDB_CLI_DIR"]]
    else:
        here = os.path.dirname(__file__)
        candidates = [
            os.path.normpath(os.path.join(here, "..", "vendor", "vulndb-cli")),
            os.path.normpath(os.path.join(here, "..", "..", "vulndb-cli")),
        ]
    for path in candidates:
        if os.path.isfile(os.path.join(path, "vulndb_cli", "cli.py")):
            return path
    raise VulndbError(
        f"vulndb-cli repo not found (looked for vulndb_cli/cli.py in {candidates}). "
        "Set $VULNDB_CLI_DIR."
    )


def load_seed_definition(name: str, seed_dir: str = None) -> dict:
    """Read a bundled catalog seed by name: theme seeds in
    ``vulndb_theme_configs``, planting seeds in ``vulndb_vuln_configs``
    (no dir argument = the theme dir, for theme.py's callers)."""
    search_dirs = [seed_dir] if seed_dir else [_THEME_SEED_DIR, _VULN_SEED_DIR]
    for directory in search_dirs:
        path = os.path.join(directory, f"{name}.json")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                definition = json.load(f)
            if definition.get("name") != name:
                raise VulndbError(
                    f"seed {path} declares name {definition.get('name')!r}, expected {name!r}"
                )
            return definition
    raise FileNotFoundError(
        f"no bundled catalog seed named {name!r} in {', '.join(search_dirs)}"
    )


def load_vuln_seed_definition(name: str) -> dict:
    """Read a bundled planting seed from ``boxbuilder/vulndb_vuln_configs``."""
    return load_seed_definition(name, seed_dir=_VULN_SEED_DIR)


def has_vuln_seed(name: str) -> bool:
    """True when boxbuilder ships a planting seed for this configuration."""
    return os.path.isfile(os.path.join(_VULN_SEED_DIR, f"{name}.json"))


def has_theme_seed(name: str) -> bool:
    """True when boxbuilder ships a theming seed for this configuration."""
    return os.path.isfile(os.path.join(_THEME_SEED_DIR, f"{name}.json"))


def ensure_vuln_seeds(base_url: str, configurations: list, timeout: int = 60) -> list:
    """Create-if-missing the selected vulns that have a local
    vulndb_vuln_configs seed; catalog-authored names are left alone."""
    ensured = []
    seen = set()
    for item in configurations:
        name = item if isinstance(item, str) else (item or {}).get("name")
        if not name or name in seen:
            continue
        seen.add(name)
        path = os.path.join(_VULN_SEED_DIR, f"{name}.json")
        if not os.path.isfile(path):
            continue
        ensure_configuration(base_url, load_vuln_seed_definition(name), timeout=timeout)
        ensured.append(name)
    return ensured


def _run_vulndb_cli(args: list, base_url: str, stdin_str: str = None,
                    timeout: int = 60, cli_dir: str = None):
    """`python3 -m vulndb_cli <args> --url <base> --yes` (cwd=cli_dir),
    parsing the last stdout JSON line; None on empty output. --yes always:
    no TTY here, and every write was already boxbuilder's decision."""
    cli_dir = cli_dir or resolve_vulndb_cli_dir()
    cmd = [sys.executable, "-m", "vulndb_cli", *args, "--url", base_url, "--yes"]
    try:
        result = subprocess.run(
            cmd, cwd=cli_dir, capture_output=True, text=True,
            input=stdin_str, timeout=timeout,
        )
    except FileNotFoundError as e:
        raise VulndbError(f"failed to invoke vulndb-cli: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise VulndbError(
            f"vulndb-cli timed out after {timeout}s: {' '.join(args)}",
            returncode=124,
            stderr=(e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")),
        ) from e

    if result.returncode != 0:
        raise VulndbError(
            f"vulndb-cli {' '.join(args)} exited {result.returncode}: "
            f"{(result.stderr or result.stdout).strip()[:500]}",
            returncode=result.returncode, stderr=result.stderr,
        )
    stdout = result.stdout.strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout.splitlines()[-1])
    except json.JSONDecodeError as last_line_error:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as full_output_error:
            raise VulndbError(
                f"vulndb-cli emitted unparseable JSON: {last_line_error}",
                stderr=result.stderr,
            ) from full_output_error


def list_configurations(base_url: str, timeout: int = 60) -> list:
    """Every configuration (each with its `attachments` array) via `vulndb-cli list --json`."""
    result = _run_vulndb_cli(["list", "--json"], base_url, timeout=timeout)
    return result if isinstance(result, list) else []


def create_configuration(base_url: str, definition: dict, timeout: int = 60) -> dict:
    """`vulndb-cli create --file -` (definition on stdin). Returns the inserted row."""
    row = _run_vulndb_cli(["create", "--file", "-"], base_url,
                          stdin_str=json.dumps(definition), timeout=timeout)
    if not isinstance(row, dict):
        raise VulndbError(f"vulndb-cli create returned no row: {row!r}")
    return row


def _find_by_name(configurations: list, name: str):
    for c in configurations:
        if c.get("name") == name:
            return c
    return None


def update_configuration(base_url: str, definition: dict, timeout: int = 60) -> dict:
    """`vulndb-cli update <name> --file -`: a full-replace PUT of the seed
    doc converges the row. No JSON on no-op, so the seed definition is
    returned then (callers only need name/attachments)."""
    ref = definition.get("name")
    if not ref:
        raise VulndbError("update_configuration needs a definition with a 'name'")
    row = _run_vulndb_cli(["update", ref, "--file", "-"], base_url,
                          stdin_str=json.dumps(definition), timeout=timeout)
    if isinstance(row, dict):
        row.setdefault("attachments", [])
        return row
    return dict(definition, attachments=definition.get("attachments") or [])


# Seed fields the catalog row mirrors; drift here is what
# ensure_configuration(sync=True) converges. Attachments never participate:
# they're content-addressed uploads, not seed content.
_SEED_FIELDS = ("name", "description", "platform", "category", "type", "run_as",
                "script", "depends_on")


def _seed_drift(existing: dict, definition: dict) -> bool:
    """True when the catalog row differs from the bundled seed on any seed field."""
    return any(key in definition and existing.get(key) != definition[key]
               for key in _SEED_FIELDS)


def ensure_configuration(base_url: str, definition: dict, timeout: int = 60,
                         sync: bool = False) -> dict:
    """Idempotent create-if-missing by name; never overwrites by default.
    sync=True additionally converges a row whose seed fields (never
    attachments) drifted from the bundled seed — how seed edits ship."""
    existing = _find_by_name(list_configurations(base_url, timeout=timeout), definition["name"])
    if existing is not None:
        if sync and _seed_drift(existing, definition):
            return update_configuration(base_url, definition, timeout=timeout)
        return existing
    row = create_configuration(base_url, definition, timeout=timeout)
    row.setdefault("attachments", [])
    return row


def _sha256_file(path: str, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def upload_attachment(base_url: str, configuration: dict, local_path: str, filename: str,
                      timeout: int = 120) -> dict:
    """Upload local_path's bytes as `filename` via `vulndb-cli upload`.
    vulndb-cli keys the attachment by the uploaded file's basename, so the
    temp file is staged under the content-addressed name."""
    d = tempfile.mkdtemp(prefix="vulndb-upload-")
    try:
        staged = os.path.join(d, filename)
        with open(local_path, "rb") as src, open(staged, "wb") as dst:
            shutil.copyfileobj(src, dst)
        ref = configuration.get("name") or str(configuration["id"])
        return _run_vulndb_cli(["upload", ref, staged], base_url, timeout=timeout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def ensure_attachment(base_url: str, configuration: dict, local_path: str,
                      timeout: int = 120) -> str:
    """Idempotent upload keyed by `<sha256[:16]>-<basename>`: identical bytes
    reuse, different bytes create. Returns the filename for use as a `vars`
    value (e.g. WALLPAPER_FILENAME)."""
    digest = _sha256_file(local_path)
    filename = f"{digest[:16]}-{os.path.basename(local_path)}"
    for a in configuration.get("attachments") or []:
        if a.get("original_name") == filename:
            return filename
    upload_attachment(base_url, configuration, local_path, filename, timeout=timeout)
    return filename
