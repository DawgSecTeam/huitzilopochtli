"""YAML -> (manifest, rubric, engine scenario record) build pipeline.
See architecture.md §8.

PHASE 1 TASK: implement. May use PyYAML (author-machine only — never
shipped to the box or bundled into the zipapp).
"""


def compile_scenario(yaml_path: str, out_dir: str) -> dict:
    """Pipeline (§8):
      1. Parse scenario YAML.
      2. authoring.validate.validate_scenario_yaml(...) — fail loudly with
         line-referenced errors.
      3. Split into: Manifest (public collection instructions + display
         metadata), Rubric (expected values + points + SLA params), and the
         engine scenario record (rubric + adversary event pool + RNG seed
         source) — engine-only, never distributed to boxes.
      4. Sign the manifest with the authoring private key
         (authoring.sign_scenario.sign_manifest).
      5. Emit manifest.signed.json always; for honor mode also emit the
         rubric to bundle into the box image; for ranked, emit the rubric +
         engine record for out-of-band upload to the engine.

    Returns a dict of output file paths written under out_dir.
    """
    raise NotImplementedError
