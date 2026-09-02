"""boxbuilder's client for the vulndb catalog — a thin wrapper around the vulndb-cli subprocess.

boxbuilder used to talk to vulndb-ui's HTTP API directly with a hand-rolled stdlib http.client
client. It now shells out to `python3 -m vulndb_cli` instead — vulndb-cli is the sanctioned,
versioned client for that API (a submodule at vendor/vulndb-cli), so the raw HTTP contract lives
in exactly one place. No code here opens a socket to vulndb-ui anymore.

The public surface theme.py relies on is unchanged (resolve_vulndb_url, load_seed_definition,
list_configurations, create_configuration, ensure_configuration, ensure_attachment, VulndbError),
and so are the semantics: ensure_configuration is idempotent create-if-missing (never overwrites),
and ensure_attachment is content-addressed (`<sha256[:16]>-<basename>`) so identical bytes reuse
one attachment and different bytes always upload a new one.
"""
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
            os.path.normpath(os.path.join(here, "..", "vendor", "vulndb-cli")),  # submodule
            os.path.normpath(os.path.join(here, "..", "..", "vulndb-cli")),       # sibling checkout
        ]
    for path in candidates:
        if os.path.isfile(os.path.join(path, "vulndb_cli", "cli.py")):
            return path
    raise VulndbError(
        f"vulndb-cli repo not found (looked for vulndb_cli/cli.py in {candidates}). "
        "Set $VULNDB_CLI_DIR."
    )


def load_seed_definition(name: str, seed_dir: str = None) -> dict:
    """Read a bundled static catalog seed by name.

    Theme seeds remain in ``vulndb_theme_configs``; box-specific planting seeds live in
    ``vulndb_vuln_configs``.  When no directory is supplied, the theme directory is kept as
    the backwards-compatible default for callers such as ``theme.py``.
    """
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


def ensure_vuln_seeds(base_url: str, configurations: list, timeout: int = 60) -> list:
    """Ensure bundled planting seeds selected by a nakon configuration exist in vulndb.

    Only names with a local ``vulndb_vuln_configs/<name>.json`` seed are touched; catalog
    entries authored elsewhere are left to the catalog as-is.  The operation is
    create-if-missing and never overwrites an existing row.
    """
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
    """Run `python3 -m vulndb_cli <args> --url <base> --yes` (cwd=cli_dir so a checkout resolves),
    and return the parsed JSON of the last stdout line, or None for empty output.

    --yes is always passed: boxbuilder runs non-interactively (no TTY), and every write vulndb-cli
    does here is one boxbuilder already decided to make.
    """
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
        raise VulndbError(f"vulndb-cli timed out after {timeout}s: {' '.join(args)}",
                          returncode=124) from e

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
        # Older/compact vulndb-cli versions emit one JSON object per line; newer versions
        # pretty-print arrays/objects.  Keep the fast last-line path, then fall back to the
        # complete stdout document just as the nakon wrapper does.
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


def ensure_configuration(base_url: str, definition: dict, timeout: int = 60) -> dict:
    """Idempotent: find `definition["name"]` in the live catalog; create it if absent. Never
    updates an existing row — an author who wants to change a seeded script edits it themselves
    via vulndb-ui/vulndb-cli; boxbuilder only ever ensures presence, never overwrites."""
    existing = _find_by_name(list_configurations(base_url, timeout=timeout), definition["name"])
    if existing is not None:
        return existing
    row = create_configuration(base_url, definition, timeout=timeout)
    # A freshly created row has no attachments yet; normalize so ensure_attachment's check is
    # uniform whether the row came from list (has attachments) or create (none).
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
    """Attach local_path's bytes to `configuration`, stored under `filename` (the content-
    addressed name), via `vulndb-cli upload`.

    vulndb-cli stores the attachment under the uploaded file's basename, so we stage a temp file
    named `filename` to preserve the content-addressed name (identical bytes always reuse one
    attachment). `configuration` is the dict from ensure_configuration (needs a name or id).
    """
    d = tempfile.mkdtemp(prefix="vulndb-upload-")
    try:
        staged = os.path.join(d, filename)
        with open(local_path, "rb") as src, open(staged, "wb") as dst:
            dst.write(src.read())
        ref = configuration.get("name") or str(configuration["id"])
        return _run_vulndb_cli(["upload", ref, staged], base_url, timeout=timeout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def ensure_attachment(base_url: str, configuration: dict, local_path: str,
                      timeout: int = 120) -> str:
    """Idempotent: filename is content-addressed (`<sha256[:16]>-<basename>`), so identical bytes
    always reuse the same attachment and different bytes always upload a new one. `configuration`
    is the dict returned by ensure_configuration() (must have an "id"; "attachments" is optional/
    absent on a freshly created row, treated as empty). Returns the filename either way, for use
    as a `vars` value (e.g. WALLPAPER_FILENAME).
    """
    digest = _sha256_file(local_path)
    filename = f"{digest[:16]}-{os.path.basename(local_path)}"
    for a in configuration.get("attachments") or []:
        if a.get("original_name") == filename:
            return filename
    upload_attachment(base_url, configuration, local_path, filename, timeout=timeout)
    return filename
