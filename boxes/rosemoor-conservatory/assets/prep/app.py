#!/usr/bin/env python3
"""GlassBoard -- the Rosemoor glasshouse dashboard (visitor counter + live
sensor board). Flask app; reads its settings from /opt/glassboard/.env and
logs one line per request to stdout, which lands in journald under
glassboard-app.service -- that is what makes the app journal a primary IR
source on this box."""
import os
import subprocess
import sys
from datetime import date

from flask import Flask

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(APP_DIR, ".env")


def load_env(path=ENV_PATH):
    env = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
    return env


ENV = load_env()
DB = {"host": ENV.get("DB_HOST", "127.0.0.1"), "port": ENV.get("DB_PORT", "3306"),
      "user": ENV.get("DB_USER", "glassapp"), "password": ENV.get("DB_PASS", ""),
      "name": ENV.get("DB_NAME", "glassboard")}
REDIS_URL = ENV.get("REDIS_URL", "redis://127.0.0.1:6379/0")

app = Flask(__name__)


def log(msg):
    print("glassboard: " + msg, flush=True)


def mysql(query, args=None):
    cmd = ["mysql", "-h", DB["host"], "-P", DB["port"], "-u", DB["user"],
           "-p" + DB["password"], "-N", "-B", DB["name"], "-e", query]
    if args:
        cmd += ["--", *args]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        log("db error: " + out.stderr.strip()[:200])
        return []
    return [line.split("\t") for line in out.stdout.strip().splitlines() if line]


@app.after_request
def _access_log(resp):
    log("request {} {} -> {}".format(
        __import__("flask").request.method,
        __import__("flask").request.path, resp.status_code))
    return resp


@app.get("/")
def index():
    rows = mysql("SELECT species, latin_name, house, rarity FROM collections ORDER BY id")
    tickets = mysql(
        "SELECT visitor_type, SUM(quantity) FROM tickets WHERE visit_date=%s GROUP BY visitor_type",
        [date.today().isoformat()])
    sensors = mysql(
        "SELECT house, metric, reading FROM sensors ORDER BY house, metric")
    tmap = {r[0]: r[1] for r in tickets}
    smap = {}
    for house, metric, reading in sensors:
        smap.setdefault(house, []).append("{}={}".format(metric, reading))
    counters = {
        "adult": tmap.get("adult", "0"), "child": tmap.get("child", "0"),
        "member": tmap.get("member", "0"),
    }
    items = "".join(
        "<li><b>{}</b> <i>{}</i> — {} ({})</li>".format(
            r[0], r[1], r[2], r[3]) for r in rows)
    boards = "".join(
        "<li><b>{}</b>: {}</li>".format(h, ", ".join(v))
        for h, v in sorted(smap.items()))
    html = """<!doctype html><html><head><title>Rosemoor GlassBoard</title>
<style>body{{font-family:sans-serif;max-width:640px;margin:2rem auto;color:#243}}
h1{{color:#2E7D4F}}</style></head><body>
<h1>Rosemoor GlassBoard</h1>
<p>Today: {} adult / {} child / {} member tickets.</p>
<h2>Live glasshouse conditions</h2><ul>{}</ul>
<h2>Living collections</h2><ul>{}</ul>
<p><small>Session cache: {}</small></p>
</body></html>""".format(counters["adult"], counters["child"], counters["member"],
                         boards, items, "connected" if _redis_ok() else "degraded")
    return html


def _redis_ok():
    try:
        r = subprocess.run(["redis-cli", "ping"], capture_output=True, text=True,
                           timeout=2, check=False)
        return r.stdout.strip() == "PONG"
    except Exception:
        return False


@app.get("/api/tickets")
def api_tickets():
    rows = mysql("SELECT visit_date, visitor_type, quantity FROM tickets ORDER BY id")
    return {"tickets": rows}


@app.get("/api/sensors")
def api_sensors():
    rows = mysql("SELECT house, metric, reading, recorded_at FROM sensors ORDER BY id")
    return {"sensors": rows}


if __name__ == "__main__":
    log("starting GlassBoard; db=%s@%s:%s/%s redis=%s" % (
        DB["user"], DB["host"], DB["port"], DB["name"], REDIS_URL))
    app.run(host="0.0.0.0", port=8080)
