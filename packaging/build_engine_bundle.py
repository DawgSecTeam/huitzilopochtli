#!/usr/bin/env python3
"""Build a versioned engine deployment tarball (stdlib only).

Usage: python3 packaging/build_engine_bundle.py [OUT]
Writes OUT (default dist/huitzilopochtli-engine.tar.gz) containing common/,
engine/, and the committed boxes/ folder (the engine parses box scenarios
itself) so the VM never runs from a git checkout.
"""
import os
import sys
import tarfile

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


def build(out: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with tarfile.open(out, "w:gz") as tf:
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
