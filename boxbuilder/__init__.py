"""boxbuilder: a practice-box factory pairing nakon-planted vulns with
huitzilopochtli hardening scoring: compile -> plant -> install -> package
(see boxbuilder/README.md). Author/build-machine-only tooling, excluded
from the agent zipapp, so it may use third-party deps (PyYAML, paramiko).
"""
from boxbuilder.spec import BoxSpec, load_spec

__all__ = ["BoxSpec", "load_spec"]
