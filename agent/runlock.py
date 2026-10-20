"""Best-effort inter-process lock for grade/report publication.

The honor timer and a manual `sudo huitz grade` run the same pipeline. Without
a lock they can both read the same baseline and announce the same change
twice, or one can overwrite the other's report/snapshot mid-write. This is a
cooperative lock for the agent's own processes, not a security boundary.
"""
import os


class AlreadyRunning(Exception):
    """Another grade/report writer holds the lock."""


class RunLock:
    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def acquire(self) -> bool:
        if os.name == "nt":
            try:
                import msvcrt
                self._fh = open(self.path, "a+b")
                self._fh.seek(0, os.SEEK_END)
                if self._fh.tell() == 0:
                    self._fh.write(b"\0")
                    self._fh.flush()
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except (OSError, ImportError):
                self.release()
                return False
        try:
            import fcntl
            self._fh = open(self.path, "a+b")
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (OSError, ImportError):
            self.release()
            return False

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        except (OSError, ImportError):
            pass
        try:
            self._fh.close()
        except OSError:
            pass
        self._fh = None
