"""BoxSpec: the input that ties a nakon-planted box to a huitzilopochtli rubric.

A box spec points at the two *agent-authored* files -- a huitz scenario YAML
(the checks) and a nakon config JSON (the vulns to plant) -- plus a provider
config (how to reach / package the box). Mode (honor|ranked) is NOT duplicated
here: it is read from the scenario YAML's `scenario.mode`, which is the field
the existing authoring validator enforces (authoring/validate.py).

boxbuilder never knows the vuln->check mapping; the agent authors both halves.
See boxbuilder/README.md.
"""
import json
import os
from dataclasses import dataclass, field
from typing import Optional

import yaml


@dataclass
class BoxSpec:
    """Resolved box-building request.

    `scenario_path` and `nakon_config_path` are absolute paths resolved
    relative to the spec file's directory (or CWD if given directly).
    `provider` is a dict shaped per the named provider (see providers/).
    `authoring_key_path` is optional -- if absent, keys.py generates and
    persists one into the artifacts dir.
    """

    scenario_path: str
    nakon_config_path: str
    provider: dict = field(default_factory=dict)
    authoring_key_path: Optional[str] = None
    # Source file dir, for resolving relative paths inside the spec.
    base_dir: str = "."

    # --- derived (cached; populated by load_spec) ---------------------
    scenario: dict = field(default_factory=dict, repr=False)
    nakon_config: dict = field(default_factory=dict, repr=False)

    @property
    def mode(self) -> str:
        """Mode is owned by the scenario, not the spec (single source)."""
        return self.scenario["scenario"]["mode"]

    @property
    def engine_url(self) -> Optional[str]:
        return self.scenario["scenario"].get("engine_url")

    def nakon_machines(self) -> list:
        """The machine list from the agent's nakon config (vulns live here)."""
        return list(self.nakon_config.get("machines", []))


def validate_inputs(scenario: dict, nakon_config: dict) -> None:
    """Structural validation of the two agent-authored inputs.

    Shared by load_spec() (spec-file path) and cli._spec_from_args() (direct
    flags), so both routes fail early on malformed inputs with the same clear
    messages instead of surfacing a cryptic error mid-pipeline.
    """
    if not isinstance(scenario, dict) or "scenario" not in scenario:
        raise ValueError("not a valid huitz scenario (missing 'scenario')")
    if scenario["scenario"].get("mode") not in ("honor", "ranked"):
        raise ValueError(
            f"scenario.mode must be 'honor' or 'ranked', got "
            f"{scenario['scenario'].get('mode')!r}"
        )
    if scenario["scenario"]["mode"] == "ranked" and not scenario["scenario"].get("engine_url"):
        raise ValueError("ranked mode requires scenario.engine_url")
    if not isinstance(nakon_config, dict) or not isinstance(nakon_config.get("machines"), list):
        raise ValueError("nakon config must have a 'machines' list")


def _resolve(path: str, base_dir: str) -> str:
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(base_dir, path))


def load_spec(spec_path: str) -> BoxSpec:
    """Load + validate a box spec YAML.

    The spec is a thin wrapper; structural validation of the *contents*
    (scenario shape, rubric correctness) is delegated to the existing
    authoring validator at compile time. Here we only check the spec itself
    resolves and has the required keys.
    """
    with open(spec_path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"{spec_path}: top-level must be a mapping")

    base_dir = os.path.dirname(os.path.abspath(spec_path))

    for key in ("scenario", "nakon_config"):
        if key not in raw:
            raise ValueError(f"{spec_path}: missing required key '{key}'")

    scenario_path = _resolve(raw["scenario"], base_dir)
    nakon_config_path = _resolve(raw["nakon_config"], base_dir)

    for label, path in (("scenario", scenario_path), ("nakon_config", nakon_config_path)):
        if not os.path.isfile(path):
            raise ValueError(f"{spec_path}: {label} path does not exist: {path}")

    # Load both now so .mode / .nakon_machines() work and we fail early on
    # malformed inputs rather than mid-pipeline.
    with open(scenario_path, "r", encoding="utf-8") as f:
        scenario = yaml.safe_load(f)
    with open(nakon_config_path, "r", encoding="utf-8") as f:
        nakon_config = json.load(f)

    validate_inputs(scenario, nakon_config)

    authoring_key_path = raw.get("authoring_key")
    if authoring_key_path:
        authoring_key_path = _resolve(authoring_key_path, base_dir)

    return BoxSpec(
        scenario_path=scenario_path,
        nakon_config_path=nakon_config_path,
        provider=raw.get("provider") or {},
        authoring_key_path=authoring_key_path,
        base_dir=base_dir,
        scenario=scenario,
        nakon_config=nakon_config,
    )
