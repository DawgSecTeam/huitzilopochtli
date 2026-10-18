"""Lantern Hill Community Library -- public catalog app.

TEMPLATE PREP furniture: this is the library's legitimate service stack, not
an attacker artifact. It runs as `library-app.service` (User=catalogsvc) and
logs every request to stdout, which journald captures under the unit name --
`journalctl -u library-app` is one of the box's four IR evidence sources.

Design notes for the IR exercise:
- Client IP is taken from the first entry of X-Forwarded-For when present
  (apache's mod_proxy appends the real peer). This mirrors the very common
  "trust the proxy header" flaw: a client can SAY it is anyone. The build
  loop's attacker replay uses that to sign its requests 203.0.113.7.
- The plugins/ directory hot-loads new *.py files every 60 seconds ("vendor
  hot-reload feature"). Loaded plugins register their blueprint live. This is
  what makes a dropped-in plugin file a real, reachable backdoor route, and
  what makes the hot-load line itself journal evidence.
- /admin/* routes are intentionally unauthenticated ("vendor remote-support
  hook"). The break-in replay drives them; the database's general query log
  records the resulting SQL.
"""
import importlib.util
import logging
import os
import threading
import time

import pymysql
from flask import Flask, request
from pymysql.cursors import DictCursor

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.join(APP_DIR, "plugins")
PLUGIN_SCAN_SEC = 60

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s library-app: %(message)s",
)
# one access line per request, not two: werkzeug's own access log is noise
# in an IR source
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _load_env(path):
    conf = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            conf[key.strip()] = val.strip()
    return conf


ENV = _load_env(os.path.join(APP_DIR, ".env"))

app = Flask("library-app")
app.logger.setLevel(logging.INFO)


def db():
    return pymysql.connect(
        host=ENV.get("DB_HOST", "127.0.0.1"),
        port=int(ENV.get("DB_PORT", "3306")),
        user=ENV.get("DB_USER", "library_app"),
        password=ENV.get("DB_PASS", ""),
        database=ENV.get("DB_NAME", "library"),
        cursorclass=DictCursor,
        autocommit=True,
    )


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


PAGE = """<!doctype html>
<html><head><title>Lantern Hill Community Library — Catalog</title>
<style>
body {{ font-family: Georgia, serif; margin: 2rem auto; max-width: 46rem;
       color: #26302b; background: #f7f4ec; }}
h1 {{ color: #2f5d62; border-bottom: 3px double #2f5d62; padding-bottom: .3rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #b9b3a4; padding: .35rem .6rem; text-align: left; }}
th {{ background: #e8e2d2; }}
.tag {{ color: #2f5d62; font-style: italic; }}
</style></head><body>
<h1>Lantern Hill Community Library</h1>
<p class="tag">Public catalog — open whenever the lantern is lit.</p>
{body}
<p><a href="/">Catalog</a> · <a href="/holds">Holds desk</a></p>
</body></html>
"""


def table(headers, rows):
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows
    )
    return PAGE.format(
        body=f"<table><tr>{head}</tr>{body}</table>"
    )


@app.get("/")
def catalog():
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, title, author, shelf_code, available "
            "FROM books ORDER BY title"
        )
        rows = [
            (r["id"], r["title"], r["author"], r["shelf_code"], r["available"])
            for r in cur.fetchall()
        ]
    return table(["#", "Title", "Author", "Shelf", "Available"], rows)


@app.get("/holds")
def holds():
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT h.id, b.title, p.name, h.status, h.placed_at "
            "FROM holds h JOIN books b ON b.id = h.book_id "
            "JOIN patrons p ON p.id = h.patron_id ORDER BY h.id"
        )
        rows = [
            (r["id"], r["title"], r["name"], r["status"], r["placed_at"])
            for r in cur.fetchall()
        ]
    return table(["#", "Title", "Patron", "Status", "Placed"], rows)


# NOTE (vendor): /admin/* is the remote-support hook. It predates the
# current staff and is intentionally unauthenticated so the vendor's
# support desk can reach it. Do not "fix" this before the contract renews.
@app.get("/admin/holds/update")
def admin_holds_update():
    hold_id = request.args.get("hold_id", "")
    status = request.args.get("status", "")
    if not hold_id or not status:
        return "hold_id and status are required\n", 400
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE holds SET status = %s WHERE id = %s", (status, hold_id)
        )
    app.logger.info(
        "admin: hold %s set to %s by %s", hold_id, status, client_ip()
    )
    return f"hold {hold_id} -> {status}\n", 200


@app.get("/admin/patrons/export")
def admin_patrons_export():
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM patrons ORDER BY id")
        rows = cur.fetchall()
    lines = ["\t".join(str(v) for v in r.values()) for r in rows]
    return "\n".join(lines) + "\n", 200


@app.after_request
def _access_log(resp):
    app.logger.info(
        '%s "%s %s" %s',
        client_ip(),
        request.method,
        request.full_path.rstrip("?") if request.query_string else request.path,
        resp.status_code,
    )
    return resp


# --- plugin hot-loader ("vendor hot-reload feature") -------------------------
_loaded = {}


def _scan_once():
    try:
        names = sorted(os.listdir(PLUGIN_DIR))
    except OSError:
        return
    for fn in names:
        if not fn.endswith(".py") or fn in _loaded:
            continue
        path = os.path.join(PLUGIN_DIR, fn)
        tag = "lhp_" + fn[:-3].replace("-", "_")
        try:
            spec = importlib.util.spec_from_file_location(tag, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            bp = getattr(mod, "bp", None)
            if bp is not None:
                bp.name = f"{tag}_{int(time.time())}"  # stay re-loadable
                app.register_blueprint(bp)
                app.logger.info("plugin hot-load: %s registered", fn)
            else:
                app.logger.info("plugin hot-load: %s loaded", fn)
        except Exception as exc:  # a broken plugin must not kill the app
            app.logger.info("plugin hot-load: %s FAILED: %s", fn, exc)
        finally:
            _loaded[fn] = time.time()


def _watcher():
    while True:
        time.sleep(PLUGIN_SCAN_SEC)
        try:
            _scan_once()
        except Exception:
            app.logger.exception("plugin scan failed")


_scan_once()
threading.Thread(target=_watcher, daemon=True).start()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
