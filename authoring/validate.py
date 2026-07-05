"""Author-facing validation. See architecture.md §6.7, §8.

PHASE 1 TASK: implement. Wraps common.schema.validate_manifest /
validate_rubric (structural validation of compiled JSON) with YAML-source
line-number mapping so build failures are line-referenced for the author.
"""


def validate_scenario_yaml(parsed_yaml: dict, source_path: str) -> list:
    """Returns a list of human-readable, line-referenced error strings;
    empty list = valid. Called before compile.py splits the scenario into
    manifest/rubric/engine record."""
    raise NotImplementedError
