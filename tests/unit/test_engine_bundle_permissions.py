import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_box_dirs_and_files_are_world_readable(tmp_path):
    out = tmp_path / "engine.tar.gz"
    subprocess.run([sys.executable, str(ROOT / "packaging" / "build_engine_bundle.py"),
                    str(out)], check=True, cwd=ROOT)
    with tarfile.open(out) as tf:
        d = tf.getmember("boxes/broadneck-post")
        assert d.isdir()
        assert d.mode & 0o755 == 0o755
        f = tf.getmember("boxes/broadneck-post/scenario.yaml")
        assert f.isfile()
        assert f.mode & 0o444 == 0o444
