"""boxbuilder: a practice-box factory pairing nakon-planted vulns with
huitzilopochtli hardening scoring.

Four-step pipeline (see boxbuilder/README.md):
  1. compile  -- authoring key + scenario -> manifest/rubric/engine_record +
                 agent.pyz + nakon bundle (needs vulndb)
  2. plant    -- nakon deploy vulns onto the box
  3. install  -- place agent.pyz + manifest (+ rubric for honor) on the box;
                 for ranked, upload the engine record + mint an enrollment token
  4. package  -- export the box image for distribution

Author/build-machine tooling only -- like authoring/ and packaging/, it is
excluded from the agent zipapp (packaging/build_zipapp.py copies only agent/
+ common/), so it may use third-party deps (PyYAML, paramiko).
"""
from boxbuilder.spec import BoxSpec, load_spec

__all__ = ["BoxSpec", "load_spec"]
