"""Thin stdlib HTTP client for vulndb-ui's catalog API (vulndb-interfaces/server.js).

Mirrors boxbuilder/engine.py's pattern: stdlib http.client only, no requests/urllib3,
one low-level request helper feeding thin public functions. Unlike the huitz engine's
admin API, vulndb-ui has NO authentication -- confirmed against its server.js (no auth/
token middleware at all): "the catalog is shared team state; anything with network
access can read and write it" (vulndb-interfaces/docs/api.md). So there is no token
header here, unlike engine.py's X-HUITZILOPOCHTLI-Admin-Token.

boxbuilder uses this to make box theming self-contained in this project + the vulndb
catalog: it never touches nakon's source. Theming is four small, generic, reusable
catalog configurations (see boxbuilder/vulndb_theme_configs/) that boxbuilder ensures
exist (idempotent create-if-missing, never overwrites an existing row) and, for the two
that take a file (wallpaper/readme), one content-addressed attachment per distinct file
ever themed (also idempotent -- re-theming with the same bytes uploads nothing new).

Known, accepted growth tradeoff: attachments are never pruned automatically here, so
theme-wallpaper/theme-readme accumulate one attachment per distinct file across every
scenario ever compiled. nakon fetches *all* of a configuration's attachments per build
(unchanged, existing nakon behavior) -- acceptable for now; prune stale ones via
vulndb-ui/vulndb-cli if it becomes a problem.
"""
import hashlib
import json
import os
import ssl
from typing import Optional
from urllib.parse import urlsplit

_DEFAULT_VULNDB_URL = "http://127.0.0.1:3000"
_SEED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulndb_theme_configs")


class VulndbError(Exception):
    def __init__(self, message: str, *, status_code: int = 0, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def resolve_vulndb_url(explicit: Optional[str] = None) -> str:
    """explicit arg > $VULNDB_UI_URL > http://127.0.0.1:3000 -- the same env var name
    and default vulndb-cli itself uses (vulndb-interfaces/cli.js), so one VULNDB_UI_URL
    set in the environment already covers both tools."""
    return explicit or os.environ.get("VULNDB_UI_URL") or _DEFAULT_VULNDB_URL


def load_seed_definition(name: str) -> dict:
    """Read one of the bundled static seed definitions (boxbuilder/vulndb_theme_configs/
    <name>.json) -- the source of truth for the four theme catalog configurations."""
    path = os.path.join(_SEED_DIR, f"{name}.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _split_url(url: str):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise VulndbError(f"vulndb url must be http(s)://, got {url!r}")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, host, port


def _http_request(scheme: str, host: str, port: int, method: str, path: str,
                  body: bytes, headers: dict, timeout: int):
    """One raw HTTP request. Returns (status, parsed_json_or_dict)."""
    import http.client

    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                                context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", "replace")
            status = resp.status
        finally:
            conn.close()
    except OSError as e:
        raise VulndbError(f"could not reach vulndb-ui at {scheme}://{host}:{port}: {e}") from e

    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {"raw": raw}
    return status, parsed


def _json_request(base_url: str, method: str, path: str, body: Optional[dict] = None,
                  timeout: int = 30):
    scheme, host, port = _split_url(base_url)
    payload = json.dumps(body).encode("utf-8") if body is not None else b""
    headers = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
    status, parsed = _http_request(scheme, host, port, method, path, payload, headers, timeout)
    if status >= 400:
        msg = parsed.get("error") if isinstance(parsed, dict) else None
        msg = msg or (parsed.get("raw") if isinstance(parsed, dict) else None) or f"HTTP {status}"
        raise VulndbError(f"vulndb-ui {method} {path} failed: {msg}",
                          status_code=status, body=json.dumps(parsed))
    return parsed


def list_configurations(base_url: str, timeout: int = 30) -> list:
    """GET /api/configurations -- the whole table (no ?limit), each row embedding its
    own `attachments` array (docs/api.md)."""
    result = _json_request(base_url, "GET", "/api/configurations", timeout=timeout)
    if isinstance(result, list):
        return result
    if isinstance(result, dict) and isinstance(result.get("configurations"), list):
        return result["configurations"]
    raise VulndbError(f"unexpected /api/configurations response shape: {result!r}")


def create_configuration(base_url: str, definition: dict, timeout: int = 30) -> dict:
    """POST /api/configurations. Returns the inserted row (no `attachments` key yet --
    a freshly created configuration has none)."""
    return _json_request(base_url, "POST", "/api/configurations", body=definition, timeout=timeout)


def _find_by_name(configurations: list, name: str) -> Optional[dict]:
    for c in configurations:
        if c.get("name") == name:
            return c
    return None


def ensure_configuration(base_url: str, definition: dict, timeout: int = 30) -> dict:
    """Idempotent: find `definition["name"]` in the live catalog; create it from
    `definition` if absent. Never updates an existing row -- an author who wants to
    change a seeded script edits it themselves via vulndb-ui/vulndb-cli; boxbuilder only
    ever ensures presence, never overwrites."""
    existing = _find_by_name(list_configurations(base_url, timeout=timeout), definition["name"])
    if existing is not None:
        return existing
    return create_configuration(base_url, definition, timeout=timeout)


def _sha256_file(path: str, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _multipart_body(boundary: str, field_name: str, filename: str, data: bytes) -> bytes:
    """Hand-built single-part multipart/form-data body -- stdlib has no multipart
    client. Field name is "file", matching vulndb-ui's server.js exactly
    (`upload.single('file')`, multer)."""
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
    return head + data + tail


def upload_attachment(base_url: str, configuration_id, local_path: str, filename: str,
                      timeout: int = 60) -> dict:
    """POST /api/configurations/{id}/attachments as multipart/form-data. Returns
    {id, configuration_id, original_name, mime_type, size_bytes}."""
    with open(local_path, "rb") as f:
        data = f.read()
    boundary = "----huitzilopochtliBoundary" + _sha256_file(local_path)[:16]
    body = _multipart_body(boundary, "file", filename, data)
    scheme, host, port = _split_url(base_url)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    status, parsed = _http_request(
        scheme, host, port, "POST", f"/api/configurations/{configuration_id}/attachments",
        body, headers, timeout,
    )
    if status >= 400:
        msg = parsed.get("error") if isinstance(parsed, dict) else f"HTTP {status}"
        raise VulndbError(f"upload attachment {filename!r} failed: {msg}",
                          status_code=status, body=json.dumps(parsed))
    return parsed


def ensure_attachment(base_url: str, configuration: dict, local_path: str,
                      timeout: int = 60) -> str:
    """Idempotent: filename is content-addressed (`<sha256[:16]>-<basename>`), so
    identical bytes always reuse the same attachment and different bytes always upload a
    new one -- the same cache-correctness property as everywhere else in this project's
    content-addressed caching. `configuration` is the dict returned by
    ensure_configuration() (must have an "id"; "attachments" is optional/absent on a
    freshly created row, treated as empty). Returns the filename either way, for use as
    a `vars` value (e.g. WALLPAPER_FILENAME).
    """
    digest = _sha256_file(local_path)
    filename = f"{digest[:16]}-{os.path.basename(local_path)}"
    for a in configuration.get("attachments") or []:
        if a.get("original_name") == filename:
            return filename
    upload_attachment(base_url, configuration["id"], local_path, filename, timeout=timeout)
    return filename
