"""Minimal stdlib client for workshop-vm-distribution's claim API.

The engine asks the workshop portal to claim a VM from a pool and returns the
Guacamole URL. It never receives Proxmox credentials.
"""
import json
import time
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
        err = WorkshopError(parsed.get("detail") or f"HTTP {exc.code}")
        err.status = exc.code
        raise err from exc
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
    before = {p.get("code") for p in list_pools(base_url, admin_password, timeout)
              if isinstance(p, dict)}
    result = _call(base_url, "POST", "/api/admin/provision", body, timeout,
                   headers=_admin_headers(admin_password))
    after = list_pools(base_url, admin_password, timeout)
    # Another engine call may create a same-named pool concurrently (and the
    # portal also deletes a config whose provision job was refused). Prefer a
    # code this call did not see before the POST, so a losing call can never
    # hand back a pool that its own 409 cleanup is about to delete.
    found = next((p for p in after if isinstance(p, dict)
                  and p.get("name") == name and p.get("code") not in before),
                 None) or find_pool_by_name(after, name)
    if not found:
        raise WorkshopError(
            "the portal accepted the provision request but the pool did not appear")
    result["pool_code"] = found["code"]
    return result


def pool_snapshot(base_url: str, admin_password: str, pool_code: str,
                  timeout: float = 10.0) -> Optional[dict]:
    """One row from /api/admin/pools by code, or None if the pool is gone.

    Used by the admin pre-deploy path to report ``available``/``total`` while
    a provisioning job fills the pool. A missing pool is a normal answer (an
    ended competition deletes its config), not an error."""
    if not pool_code:
        return None
    for pool in list_pools(base_url, admin_password, timeout):
        if isinstance(pool, dict) and pool.get("code") == pool_code:
            return pool
    return None


def provision_more(base_url: str, admin_password: str, pool_code: str,
                   count: int, timeout: float = 20.0) -> dict:
    """POST /api/admin/redeploy: add ``count`` pre-provisioned clones to a pool.

    The portal provisions on a background job (10 clones at a time), so this
    returns the job reply; callers poll ``pool_snapshot`` for progress. The
    portal also records ``count`` as the pool's new ``vm_count``.
    """
    return _call(base_url, "POST", "/api/admin/redeploy",
                 {"code": pool_code, "count": int(count)}, timeout,
                 headers=_admin_headers(admin_password))


def delete_pool(base_url: str, admin_password: str, pool_code: str,
                timeout: float = 10.0) -> None:
    """DELETE /api/admin/pools/<code> (config only; release VMs separately).

    A 404 means the config is already gone; that is the desired end state, not
    a reason to keep the engine's pin alive forever.
    """
    try:
        _call(base_url, "DELETE", f"/api/admin/pools/{pool_code}",
              timeout=timeout, headers=_admin_headers(admin_password))
    except WorkshopError as exc:
        if getattr(exc, "status", None) == 404:
            return
        raise


def list_vms(base_url: str, admin_password: str, timeout: float = 15.0) -> list:
    """GET /api/admin/pool: every VM the portal knows about.

    Each entry carries {vmid, student_id, pool, claimed, expired, ...}. The
    engine uses this only to find the clones belonging to its own competition
    pool at teardown; it never selects a VM for a claim from this list.
    """
    return _call(base_url, "GET", "/api/admin/pool", timeout=timeout,
                 headers=_admin_headers(admin_password))


def destroy_vms(base_url: str, admin_password: str, vmids,
                timeout: float = 10.0, wait_s: float = 60.0) -> dict:
    """POST /api/admin/destroy (specific VMIDs) and wait for the teardown job.

    The portal runs destruction asynchronously. Waiting here keeps the
    competition-end path honest: when this returns, the competition's own
    clones are gone (or the caller sees ``status != "done"`` and can retry).
    """
    ids = [int(v) for v in vmids if v is not None]
    if not ids:
        return {"status": "done", "vmids": [], "job_id": None}
    # The portal allows one destroy job at a time. Two competitions ended
    # back-to-back (a live load test did exactly that) race here; the second
    # got 409 and the caller dropped the pin, leaking its pool. Wait for the
    # running job to finish instead of failing the cleanup.
    result = None
    for attempt in range(61):
        try:
            result = _call(base_url, "POST", "/api/admin/destroy",
                           {"mode": "specific", "vmids": ids}, timeout,
                           headers=_admin_headers(admin_password))
            break
        except WorkshopError as exc:
            if "already running" not in str(exc).lower() or attempt == 60:
                raise
            time.sleep(5)
    job_id = result.get("job_id")
    if not job_id:
        return {"status": "done", "vmids": ids, "job_id": None}
    deadline = time.monotonic() + max(0.0, wait_s)
    job = {}
    while True:
        job = _call(base_url, "GET", f"/api/admin/job/{job_id}", timeout,
                    headers=_admin_headers(admin_password))
        if job.get("status") in ("done", "error"):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    job["vmids"] = ids
    return job

