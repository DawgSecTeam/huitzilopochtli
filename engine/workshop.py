"""Minimal stdlib client for workshop-vm-distribution's claim API.

The engine asks the workshop portal to claim a VM from a pool and returns the
Guacamole URL. It never receives Proxmox credentials.
"""
import json
import urllib.error
import urllib.request
from typing import Optional


class WorkshopError(Exception):
    pass


def _call(base_url: str, method: str, path: str, body: Optional[dict] = None,
          timeout: float = 15.0, headers: Optional[dict] = None) -> dict:
    url = base_url.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    h = {"Content-Type": "application/json"} if data else {}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:
            parsed = {}
        raise WorkshopError(parsed.get("detail") or f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise WorkshopError(f"workshop portal unreachable: {exc}") from exc


def claim_vm(base_url: str, pool_code: str, *, code: Optional[str] = None,
             secret: Optional[str] = None, back_url: str = "",
             timeout: float = 15.0) -> dict:
    """POST /api/claim. Returns {url,...} or {status:'provisioning',ticket}.

    With ``code`` and ``secret`` the claim is *pre-bound*: the portal keeps the
    one-time join code and runs ``huitz join`` inside the guest when the player
    opens the VM link, so the player never types anything. ``open_url`` in the
    reply is the stable portal link to hand the player; ``url`` is the raw,
    short-lived Guacamole session URL.
    """
    body: dict = {"code": pool_code}
    headers = None
    if code and secret:
        body["prebind"] = {"code": code, "back_url": back_url}
        headers = {"X-Huitz-Secret": secret}
    return _call(base_url, "POST", "/api/claim", body, timeout, headers)


def push_prebind(base_url: str, uid: str, code: str, *, secret: str,
                 back_url: str = "", timeout: float = 10.0) -> dict:
    """Rotate the join code held by the portal for an already-claimed VM."""
    return _call(base_url, "POST", "/api/prebind",
                 {"uid": uid, "code": code, "back_url": back_url},
                 timeout, headers={"X-Huitz-Secret": secret})


def release_vm(base_url: str, uid: str, timeout: float = 10.0) -> dict:
    """POST /api/release. The portal destroys the VM and frees the seat."""
    return _call(base_url, "POST", "/api/release", {"uid": uid}, timeout)


def poll_ticket(base_url: str, ticket: str, *, secret: Optional[str] = None,
                timeout: float = 15.0) -> dict:
    """GET /api/redeem/<ticket>. Returns {status:'ready',url,...} or pending.

    ``secret`` identifies the engine to the portal so its own polling is not
    counted against the portal's per-IP rate limit."""
    headers = {"X-Huitz-Secret": secret} if secret else None
    return _call(base_url, "GET", f"/api/redeem/{ticket}", timeout=timeout,
                 headers=headers)


def _admin_headers(admin_password: str) -> dict:
    """Basic auth header for the portal's /api/admin/* endpoints."""
    import base64
    token = base64.b64encode(f"admin:{admin_password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def list_pools(base_url: str, admin_password: str, timeout: float = 10.0) -> list:
    """GET /api/admin/pools (portal Basic auth; username is ignored).

    Each pool carries {code, name, available, total, in_use, config, ...}."""
    return _call(base_url, "GET", "/api/admin/pools", timeout=timeout,
                 headers=_admin_headers(admin_password))


def competition_pool_name(slug: str) -> str:
    """Deterministic per-competition pool name; also the reuse key."""
    return f"huitz-ranked-{slug}"


def find_pool_by_name(pools: list, name: str) -> Optional[dict]:
    for pool in pools:
        if isinstance(pool, dict) and pool.get("name") == name:
            return pool
    return None


def provision_pool(base_url: str, admin_password: str, slug: str, spec: dict,
                   timeout: float = 20.0) -> dict:
    """POST /api/admin/provision: a dedicated pool for one competition.

    ``spec`` is the scenario's validated ``pool`` block; field names pass
    through to the portal 1:1. The portal saves the pool config synchronously
    (generating the pool code) and provisions VMs on a background job, so the
    reply carries only the job id — the code is captured by re-listing pools
    by name right after. Claims work immediately either way: the pool is a
    dispenser and clones on demand.
    """
    name = competition_pool_name(slug)
    body = {
        "pool_name": name,
        "group": spec.get("group") or "Challenge",
        "dispenser": bool(spec.get("dispenser", True)),
        "private": bool(spec.get("private", True)),
        "template_vm_id": spec["template_vm_id"],
        "template_vm_access_method": spec["template_vm_access_method"],
        "template_vm_username": spec["template_vm_username"],
        "template_vm_password": spec["template_vm_password"],
        "vm_count": spec.get("vm_count", 2),
        "guac_link_ttl_seconds": spec.get("guac_link_ttl_seconds", 7200),
    }
    result = _call(base_url, "POST", "/api/admin/provision", body, timeout,
                   headers=_admin_headers(admin_password))
    found = find_pool_by_name(list_pools(base_url, admin_password, timeout), name)
    if not found:
        raise WorkshopError(
            "the portal accepted the provision request but the pool did not appear")
    result["pool_code"] = found["code"]
    return result


def delete_pool(base_url: str, admin_password: str, pool_code: str,
                timeout: float = 10.0) -> None:
    """DELETE /api/admin/pools/<code> (config only; release VMs separately)."""
    _call(base_url, "DELETE", f"/api/admin/pools/{pool_code}", timeout=timeout,
          headers=_admin_headers(admin_password))
