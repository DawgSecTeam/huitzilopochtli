"""Package-manager strategy (dpkg/rpm/apk). See architecture.md §9.3.

PHASE 1 TASK: implement package_installed(name) using whichever of
`dpkg -s`, `rpm -q`, `apk info -e` is present on the box. Shared by both
SystemdContext and OpenRCContext (package manager is orthogonal to init
system).
"""


def package_installed(name: str) -> tuple:
    """Returns (installed: bool, version: str | None)."""
    raise NotImplementedError
