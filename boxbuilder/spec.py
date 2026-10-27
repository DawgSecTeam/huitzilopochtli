"""BoxSpec: the input that ties a nakon-planted box to a huitzilopochtli rubric.

A box spec points at the two *agent-authored* files -- a huitz scenario YAML
(the checks) and a nakon config JSON (the vulns to plant) -- plus a provider
config (how to reach / package the box).

One scenario file authors both build targets: its base content is the honor
box, and its optional ``ranked:`` block (engine URL, ranked-only checks,
services, adversary, pool) is the ranked box. The build target is chosen with
``--mode`` (default: the file's ``scenario.mode``), never stored in the spec.

boxbuilder never knows the vuln->check mapping; the agent authors both halves.
See boxbuilder/README.md.
"""
import json
import os
from dataclasses import dataclass, field
from typing import Optional

import yaml

from common.scenario_record import MODES, base_mode, merge_effective
from boxbuilder.os_family import KNOWN_OS, known_os


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

    # --- build-target overrides (None = whatever the scenario authors) ---
    mode_override: Optional[str] = None
    engine_url_override: Optional[str] = None

    # --- derived (cached; populated by load_spec) ---------------------
    scenario: dict = field(default_factory=dict, repr=False)
    nakon_config: dict = field(default_factory=dict, repr=False)

    @property
    def mode(self) -> str:
        """Build target: the override, else the scenario's default mode."""
        return self.mode_override or base_mode(self.scenario)

    @property
    def engine_url(self) -> Optional[str]:
        """Resolved engine address for a ranked build, else None."""
        if self.mode != "ranked":
            return None
        try:
            return merge_effective(self.scenario, "ranked",
                                   engine_url=self.engine_url_override,
                                   source=self.scenario_path)["scenario"]["engine_url"]
        except ValueError:
            return None

    @property
    def theme(self) -> dict:
        """The optional top-level `theme` block (box theming), read through to the
        scenario -- same pattern as .mode/.engine_url. Empty dict, not None, when
        absent, so callers can check truthiness without a None-guard."""
        return self.scenario.get("theme") or {}

    def nakon_machines(self) -> list:
        """The machine list from the agent's nakon config (vulns live here)."""
        return list(self.nakon_config.get("machines", []))


def validate_inputs(scenario: dict, nakon_config: dict, mode: Optional[str] = None,
                    engine_url: Optional[str] = None) -> None:
    """Structural validation of the two agent-authored inputs.

    Shared by load_spec() (spec-file path) and cli._spec_from_args() (direct
    flags), so both routes fail early on malformed inputs rather than
    surfacing a cryptic error mid-pipeline.
    """
    if not isinstance(scenario, dict) or "scenario" not in scenario:
        raise ValueError("not a valid huitz scenario (missing 'scenario')")
    declared = scenario["scenario"].get("mode")
    if declared not in MODES:
        raise ValueError(
            f"scenario.mode must be 'honor' or 'ranked', got {declared!r}")

    target = mode or declared
    if target not in MODES:
        raise ValueError(f"mode must be 'honor' or 'ranked', got {target!r}")

    # Resolve the actual build target now: this is where a ranked build of a
    # scenario with no ranked block, or with no engine URL, fails early.
    merge_effective(scenario, target, engine_url=engine_url)

    if not isinstance(nakon_config, dict) or not isinstance(nakon_config.get("machines"), list):
        raise ValueError("nakon config must have a 'machines' list")
    machines = nakon_config["machines"]
    if len(machines) != 1:
        # v1 targets one box. A multi-machine config would silently deploy only
        # the first machine, which reads as success while leaving boxes bare.
        raise ValueError(
            f"nakon config must describe exactly one machine, got {len(machines)}")
    for idx, machine in enumerate(machines):
        if not isinstance(machine, dict) or not machine.get("name"):
            raise ValueError(
                f"nakon config machines[{idx}] must be an object with a 'name'")
        os_name = machine.get("os")
        if not isinstance(os_name, str) or not os_name.strip():
            raise ValueError(
                f"nakon config machines[{idx}] must set 'os' (one of "
                f"{', '.join(sorted(KNOWN_OS))})")
        if not known_os(os_name):
            raise ValueError(
                f"nakon config machines[{idx}].os {os_name!r} is not a known "
                f"platform (one of {', '.join(sorted(KNOWN_OS))})")
        configured = machine.get("configurations")
        if configured is not None and not isinstance(configured, list):
            raise ValueError(
                f"nakon config machines[{idx}].configurations must be a list")


def _resolve(path: str, base_dir: str) -> str:
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(base_dir, path))


def load_spec(spec_path: str, mode: Optional[str] = None,
              engine_url: Optional[str] = None) -> BoxSpec:
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

    validate_inputs(scenario, nakon_config, mode=mode, engine_url=engine_url)

    authoring_key_path = raw.get("authoring_key")
    if authoring_key_path:
        authoring_key_path = _resolve(authoring_key_path, base_dir)

    return BoxSpec(
        scenario_path=scenario_path,
        nakon_config_path=nakon_config_path,
        provider=raw.get("provider") or {},
        authoring_key_path=authoring_key_path,
        base_dir=base_dir,
        mode_override=mode,
        engine_url_override=engine_url,
        scenario=scenario,
        nakon_config=nakon_config,
    )
