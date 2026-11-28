#!/usr/bin/env python3
"""Build the agent zipapp (.pyz) — on a build machine, not the box:
python3 packaging/build_zipapp.py [output_path].  §17.

Bundles ONLY agent/ + common/ (stdlib + vendored crypto); never engine/
(server-side) or authoring/ (pulls PyYAML the box doesn't have).
"""
import os
import shutil
import sys
import tempfile
import zipapp

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_OUTPUT = os.path.join(_REPO_ROOT, "dist", "agent.pyz")

_PACKAGES = ("agent", "common")

_MAIN = "agent.__main__:main"


def _copy_package(name: str, src_root: str, dst_root: str) -> None:
    src = os.path.join(src_root, name)
    if not os.path.isdir(src):
        raise FileNotFoundError(f"expected package directory not found: {src}")
    dst = os.path.join(dst_root, name)
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )


def build(output_path: str) -> str:
    """Build the zipapp at `output_path`, returning that same path."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="huitzilopochtli-zipapp-") as tmpdir:
        for pkg in _PACKAGES:
            _copy_package(pkg, _REPO_ROOT, tmpdir)

        zipapp.create_archive(
            source=tmpdir,
            target=output_path,
            interpreter="/usr/bin/env python3",
            main=_MAIN,
            compressed=True,
        )

    return output_path


def main() -> None:
    output_path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_OUTPUT
    output_path = build(output_path)
    print(f"built {output_path}")


if __name__ == "__main__":
    main()
