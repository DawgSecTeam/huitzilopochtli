#!/usr/bin/env python3
"""Build a versioned engine deployment tarball (stdlib only).

Usage: python3 packaging/build_engine_bundle.py [OUT]
Writes OUT (default dist/huitzilopochtli-engine.tar.gz) containing common/,
engine/, and engine/deploy/ so the VM never runs from a git checkout.
"""
import os
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build(out: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with tarfile.open(out, "w:gz") as tf:
        for name in ("common", "engine"):
            path = os.path.join(ROOT, name)
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames[:] = [d for d in dirnames if d != "__pycache__"]
                rel = os.path.relpath(dirpath, ROOT)
                tf.add(dirpath, arcname=rel, recursive=False)
                for fn in filenames:
                    if fn.endswith(".pyc"):
                        continue
                    full = os.path.join(dirpath, fn)
                    tf.add(full, arcname=os.path.join(rel, fn))
    return out


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist", "huitzilopochtli-engine.tar.gz")
    print(build(out))
