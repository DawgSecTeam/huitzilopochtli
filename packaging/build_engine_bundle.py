#!/usr/bin/env python3
"""Build a versioned engine deployment tarball (stdlib only).

Usage: python3 packaging/build_engine_bundle.py [OUT]
Writes OUT (default dist/huitzilopochtli-engine.tar.gz) containing common/,
engine/, and the committed boxes/ folder (the engine parses box scenarios
itself) so the VM never runs from a git checkout.

A build_info.json is stamped at the bundle root (git commit + build time) so
the running engine can report its exact build on the admin dashboard
(/admin/api/build reads the same file).
"""
import datetime
import io
import json
import os
import subprocess
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _box_permissions(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    """Box directories are read by the engine's unprivileged service user.

    A box directory committed as 0700 (easy to do with a restrictive umask)
    would otherwise be preserved into /opt and silently hide the scenario
    from the engine. Normalize everything under boxes/ to world-readable.
    """
    if ti.name == "boxes" or ti.name.startswith("boxes/"):
        ti.mode = 0o755 if ti.isdir() else 0o644
    return ti


def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, timeout=10,
                             check=True)
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _build_info_entry() -> tarfile.TarInfo:
    payload = json.dumps({
        "commit": _git_commit(),
        "built_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds"),
        "source": "bundle",
    }).encode()
    ti = tarfile.TarInfo("build_info.json")
    ti.size = len(payload)
    ti.mode = 0o644
    ti.mtime = int(time.time())
    return ti, io.BytesIO(payload)


def build(out: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with tarfile.open(out, "w:gz") as tf:
        ti, payload = _build_info_entry()
        tf.addfile(ti, payload)
        for name in ("common", "engine", "boxes"):
            path = os.path.join(ROOT, name)
            if not os.path.isdir(path):
                continue
            for dirpath, dirnames, filenames in os.walk(path):
                # Never ship working-tree build outputs: boxes/*/artifacts*/
                # hold authoring keys and compiled rubrics.
                dirnames[:] = [d for d in dirnames
                               if d != "__pycache__" and not d.startswith("artifacts")
                               and not d.startswith(".")]
                rel = os.path.relpath(dirpath, ROOT)
                tf.add(dirpath, arcname=rel, recursive=False,
                       filter=_box_permissions)
                for fn in filenames:
                    if fn.endswith(".pyc"):
                        continue
                    full = os.path.join(dirpath, fn)
                    tf.add(full, arcname=os.path.join(rel, fn),
                           filter=_box_permissions)
    return out


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist", "huitzilopochtli-engine.tar.gz")
    print(build(out))
