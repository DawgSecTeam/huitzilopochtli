"""Admin authentication: HTTP Basic login -> server-side session + CSRF.

The engine itself is stdlib-only; this avoids an external identity provider
for the first round. Cloudflare Tunnel/Access can sit in front later without
changing these routes.
"""
import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional


COOKIE_NAME = "huitz_admin"
SESSION_TTL_S = 8 * 3600


def admin_user() -> str:
    return os.environ.get("HUITZILOPOCHTLI_ADMIN_USER", "admin")


def admin_password() -> str:
    return os.environ.get("HUITZILOPOCHTLI_ADMIN_PASSWORD", "")


def admin_enabled() -> bool:
    return bool(admin_password())


def check_credentials(username: str, password: str) -> bool:
    if not admin_enabled():
        return False
    u_ok = hmac.compare_digest(username.encode("utf-8"),
                               admin_user().encode("utf-8"))
    p_ok = hmac.compare_digest(password.encode("utf-8"),
                               admin_password().encode("utf-8"))
    return u_ok and p_ok


def parse_basic(header: str) -> Optional[tuple]:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header.split(" ", 1)[1].strip(), validate=True)
        user, _, password = raw.decode("utf-8").partition(":")
        return user, password
    except Exception:
        return None


def hash_session(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session(store, username: str):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    store.create_admin_session(
        hash_session(token), username, csrf, time.time() + SESSION_TTL_S
    )
    return token, csrf


def session_from_cookie(store, cookie_header: str):
    token = None
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE_NAME and value:
            token = value
            break
    if not token:
        return None
    return store.get_admin_session(hash_session(token))


def cookie_value(token: str, secure: bool = False) -> str:
    attrs = [
        f"{COOKIE_NAME}={token}", "Path=/", "HttpOnly", "SameSite=Lax",
        f"Max-Age={SESSION_TTL_S}",
    ]
    if secure:
        attrs.append("Secure")
    return "; ".join(attrs)


def clear_cookie() -> str:
    return f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
