"""The four-step build pipeline. Each step is a pure-ish function returning a
JSON-serializable result dict, so the CLI layer is a thin wrapper that just
adds argparse + stdout/stderr discipline.

Steps are independently callable so an agent (or a test) can run/verify them
piecemeal. The unified `build` in cli.py chains them with resumability.
"""
import json
import os
from typing import Optional

from boxbuilder import keys, nakon
from boxbuilder.spec import BoxSpec

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _load_build_zipapp():
    """Load packaging/build_zipapp.py::build by file path.

    Avoids `from packaging.build_zipapp import build`, which collides with the
    PyPI `packaging` namespace package present in site-packages on many
    interpreters (it shadows the repo's packaging/ dir). importlib by path is
    immune to that.
    """
    import importlib.util
    path = os.path.join(_REPO_ROOT, "packaging", "build_zipapp.py")
    spec = importlib.util.spec_from_file_location("huitzilopochtli.packaging.build_zipapp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build

# On-box install layout, per packaging/README.md. Kept here (not in spec) so
# the provider install step and any future re-arm integration share one constant.
INSTALL_DIR = "/opt/huitzilopochtli"


def compile_box(spec: BoxSpec, artifacts_dir: str, nakon_dir: Optional[str] = None,
                rebuild_bundle: bool = False, log=print) -> dict:
    """Step 1: compile the scenario + build the agent.pyz + build the nakon bundle.

    Reuses authoring/compile.py::compile_scenario (signs the manifest), and
    packaging/build_zipapp.py::build (the agent artifact). Then shells out to
    `nakon build` to produce the vuln bundle (needs vulndb reachable).

    Returns:
      {
        "mode": "honor"|"ranked",
        "authoring_key": <path>,
        "manifest": <artifacts path>,
        "rubric": <artifacts path or null>,   # honor only
        "engine_record": <artifacts path>,
        "authoring_public_key": <artifacts path>,
        "agent_pyz": <artifacts path>,
        "bundle": {"bundle_id", "path", "cached", "plans", "machines"},
      }
    """
    os.makedirs(artifacts_dir, exist_ok=True)

    # 1a. Authoring key (load or generate+persist).
    priv_key, key_path = keys.load_authoring_key(spec.authoring_key_path, artifacts_dir)
    log(f"[boxbuilder] authoring key: {key_path}")

    # 1b. Compile the scenario. Defer the import so a missing PyYAML only
    # surfaces when someone actually compiles (mirrors authoring/ conventions).
    from authoring.compile import compile_scenario

    outputs = compile_scenario(spec.scenario_path, artifacts_dir, priv_key)
    log(f"[boxbuilder] compiled {spec.mode} scenario -> {outputs['manifest']}")

    # 1c. Build the agent zipapp into the artifacts dir. Load the builder by
    # file path rather than `from packaging.build_zipapp import ...`, because a
    # site-packages `packaging` (PyPI namespace package) can shadow the repo's
    # packaging/ dir on some interpreters.
    build_zipapp = _load_build_zipapp()
    agent_pyz = os.path.join(artifacts_dir, "agent.pyz")
    build_zipapp(agent_pyz)
    log(f"[boxbuilder] built agent -> {agent_pyz}")

    # 1d. Build the nakon bundle (vuln planting payload). We write a copy of the
    # agent's nakon config into the artifacts dir so the build input is captured
    # alongside its outputs; address reconciliation happens at deploy time.
    ndir = nakon.resolve_nakon_dir(nakon_dir)
    nakon_cfg_path = os.path.join(artifacts_dir, "nakon-config.json")
    with open(nakon_cfg_path, "w", encoding="utf-8") as f:
        json.dump(spec.nakon_config, f, indent=2)
    bundle = nakon.build_bundle(ndir, nakon_cfg_path, out_dir="bundles",
                                rebuild=rebuild_bundle)
    log(f"[boxbuilder] nakon bundle {bundle['bundle_id'][:12]} "
        f"({'cached' if bundle['cached'] else 'fresh'}, "
        f"{bundle['plans']} plan(s), {bundle['machines']} machine(s))")

    # Record state so plant/install/package can resume without re-deriving it.
    result = {
        "mode": spec.mode,
        "scenario_name": spec.scenario["scenario"]["name"],
        "engine_url": spec.engine_url,
        "authoring_key": key_path,
        "manifest": outputs["manifest"],
        "rubric": outputs.get("rubric"),
        "engine_record": outputs["engine_record"],
        "authoring_public_key": outputs["authoring_public_key"],
        "agent_pyz": agent_pyz,
        "bundle": bundle,
        "bundle_path": bundle["path"],
    }
    _save_state(artifacts_dir, result)
    return result


def _save_state(artifacts_dir: str, state: dict) -> None:
    """Persist a build-state.json so later steps (plant/install/package) and the
    resumable `build` command can pick up where compile left off."""
    os.makedirs(artifacts_dir, exist_ok=True)
    path = os.path.join(artifacts_dir, "build-state.json")
    # build-state.json is build output (paths + bundle id), not secret. The
    # authoring private key is stored separately as authoring.key (0600).
    serializable = {k: v for k, v in state.items() if k != "authoring_key"}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2, default=str)


def plant_box(spec: BoxSpec, artifacts_dir: str, bundle_path: Optional[str] = None,
              nakon_dir: Optional[str] = None, provider_factory=None, log=print) -> dict:
    """Step 2: deploy the vulns onto the box via nakon.

    `bundle_path` defaults to the bundle produced by compile_box (recorded in
    <artifacts_dir>/build-state.json); callers may pass an explicit one.
    `provider_factory` is a callable(name, cfg) -> (provider, handle) used in
    tests to inject a FakeProvider; in production it defaults to the registry.

    Returns:
      {
        "bundle_id": str,
        "machine": {"name","addr","user","port"},
        "deploy": <nakon deploy --json output>,
        "ok": bool,
      }
    """
    import json as _json
    state_path = os.path.join(artifacts_dir, "build-state.json")

    if bundle_path is None:
        # Prefer an explicitly-passed bundle, else fall back to the compile record.
        if os.path.isfile(state_path):
            with open(state_path, "r", encoding="utf-8") as f:
                state = _json.load(f)
            bundle_path = state.get("bundle_path")
        if not bundle_path:
            raise ValueError(
                "no bundle path given and none recorded in build-state.json; "
                "run `compile` first or pass --bundle"
            )

    if not spec.provider.get("name"):
        raise ValueError(
            "plant requires a provider; set provider.name in the spec "
            "(e.g. provider: {name: ssh, host: ..., user: ..., password: ...})"
        )

    # Resolve the provider + start the box handle.
    provider, handle = _resolve_provider(spec.provider, provider_factory, log)
    machine_name = nakon.first_machine_name(spec.nakon_config)
    try:
        # Address reconciliation: take vulns from agent config, address from handle.
        derived = nakon.derive_deploy_config(
            spec.nakon_config, machine_name,
            host=handle.addr, user=handle.user, password=handle.password,
            port=getattr(handle, "port", 22),
        )
        derived_path = os.path.join(artifacts_dir, "nakon-deploy-config.json")
        with open(derived_path, "w", encoding="utf-8") as f:
            _json.dump(derived, f, indent=2)
        log(f"[boxbuilder] planting vulns on {handle.name} ({handle.addr}) via nakon deploy")

        ndir = nakon.resolve_nakon_dir(nakon_dir)
        deploy = nakon.deploy_bundle(ndir, bundle_path, derived_path)
        log(f"[boxbuilder] nakon deploy: {'ok' if deploy['ok'] else 'FAILURES=' + str(deploy['failures'])}")
        return {
            "bundle_id": deploy.get("bundle_id"),
            "machine": {"name": handle.name, "addr": handle.addr,
                        "user": handle.user, "port": getattr(handle, "port", 22)},
            "deploy": deploy,
            "ok": deploy.get("ok", False),
        }
    finally:
        provider.stop(handle)


def _resolve_provider(provider_cfg: dict, provider_factory, log):
    """Return (provider, handle). provider_factory overrides the registry for tests."""
    if provider_factory is not None:
        return provider_factory(provider_cfg.get("name"), provider_cfg)
    # Production path: use the registry. Imported lazily so compile-only callers
    # don't need paramiko installed.
    from boxbuilder.providers import load_provider
    name = provider_cfg.get("name")
    provider = load_provider(name, provider_cfg)
    # Copy non-name keys into the handle config; providers may rename `name` to
    # the machine name themselves, so don't pass the provider's own name through.
    cfg = {k: v for k, v in provider_cfg.items() if k != "name"}
    handle = provider.start(cfg)
    return provider, handle


def install_box(spec: BoxSpec, artifacts_dir: str, compile_result: Optional[dict] = None,
                provider_factory=None, init_kind: Optional[str] = None,
                admin_token: Optional[str] = None, checkin_interval_s: int = 60,
                enrollment_ttl_s: int = 86400, log=print) -> dict:
    """Step 3: place the agent + manifest (+ rubric for honor) on the box and
    enable the init unit. For ranked mode, also upload the engine record and
    mint an enrollment token first.

    `compile_result` defaults to the state recorded by compile_box. `init_kind`
    auto-detects (systemd/openrc) when None. `admin_token` defaults to
    $HUITZILOPOCHTLI_ADMIN_TOKEN (required for ranked).

    Returns:
      {
        "mode": ...,
        "machine": {"name","addr",...},
        "files": [<remote paths placed>],
        "init": "systemd"|"openrc"|"none",
        "ranked": {"scenario_uploaded": bool, "enrollment_token": str|null} | null,
        "ok": True,
      }
    """
    if compile_result is None:
        compile_result = _load_state(artifacts_dir)
        if compile_result is None:
            raise ValueError("no compile result given and no build-state.json; run `compile` first")

    if not spec.provider.get("name"):
        raise ValueError("install requires a provider; set provider.name in the spec")

    mode = compile_result["mode"]
    provider, handle = _resolve_provider(spec.provider, provider_factory, log)
    try:
        # --- ranked: wire the engine first so the token can go in agent_config ---
        ranked = None
        enrollment_token = None
        if mode == "ranked":
            from boxbuilder import engine
            token = engine.resolve_admin_token(admin_token)
            engine_url = compile_result.get("engine_url") or spec.engine_url
            if not engine_url:
                raise ValueError("ranked mode requires engine_url (in scenario or compile state)")
            log(f"[boxbuilder] uploading scenario record to engine {engine_url}")
            engine.upload_scenario(engine_url, token, compile_result["engine_record"])
            enrollment_token = engine.mint_enrollment_token(
                engine_url, token,
                scenario_name=compile_result.get("scenario_name") or spec.scenario["scenario"]["name"],
                ttl_s=enrollment_ttl_s,
            )
            ranked = {"scenario_uploaded": True, "enrollment_token": enrollment_token}
            log("[boxbuilder] minted enrollment token (consumed once on first boot)")

        # --- build the on-box file set + agent_config.json per mode ---
        from boxbuilder import artifacts as artifacts_mod
        scenario_name = compile_result.get("scenario_name") or spec.scenario["scenario"]["name"]
        agent_cfg = artifacts_mod.agent_config_dict(
            scenario_name=scenario_name, mode=mode,
            engine_url=(spec.engine_url if mode == "ranked" else None),
            checkin_interval_s=(checkin_interval_s if mode == "ranked" else None),
            enrollment_token=enrollment_token,
        )
        files = artifacts_mod.on_box_files(compile_result, mode, agent_cfg)

        # --- place files ---
        log(f"[boxbuilder] installing agent ({mode}) on {handle.name} ({handle.addr})")
        # Ensure the install dir exists first.
        mk = handle.run(f"mkdir -p {artifacts_mod.INSTALL_DIR}")
        if not mk.ok:
            raise RuntimeError(f"could not create {artifacts_mod.INSTALL_DIR}: {mk.stderr.strip()}")
        placed = []
        for f in files:
            handle.put(f.local, f.remote, mode=f.mode)
            placed.append(f.remote)
        log(f"[boxbuilder] placed {len(placed)} file(s) under {artifacts_mod.INSTALL_DIR}")

        # --- init unit ---
        if init_kind is None:
            # Auto-detect. The ssh provider exports detect_init; fake providers
            # in tests pass init_kind explicitly to skip this.
            try:
                from boxbuilder.providers.ssh import detect_init
                init_kind = detect_init(handle)
            except Exception:
                init_kind = "none"
        handle.install_init(init_kind)
        log(f"[boxbuilder] init unit: {init_kind}")

        return {
            "mode": mode,
            "machine": {"name": handle.name, "addr": handle.addr,
                        "user": handle.user, "port": getattr(handle, "port", 22)},
            "files": placed,
            "init": init_kind,
            "ranked": ranked,
            "ok": True,
        }
    finally:
        provider.stop(handle)


def _load_state(artifacts_dir: str) -> Optional[dict]:
    """Read build-state.json written by compile_box, or None if absent."""
    path = os.path.join(artifacts_dir, "build-state.json")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def package_box(spec: BoxSpec, artifacts_dir: str, image_out: str, fmt: str = "ova",
                provider_factory=None, log=print) -> dict:
    """Step 4: export the box image for distribution via the provider.

    The SshProvider returns mode="manual" (a remote box can't snapshot itself);
    qemu/proxmox providers will return mode="wrote" with a real image path.

    Returns:
      {
        "image": {"mode":"wrote"|"manual", "path": str|null, "format": str, "instructions": str|null},
        "ok": True,   # always -- manual export is a documented outcome, not failure
      }
    """
    if not spec.provider.get("name"):
        raise ValueError("package requires a provider; set provider.name in the spec")

    provider, handle = _resolve_provider(spec.provider, provider_factory, log)
    try:
        log(f"[boxbuilder] exporting box image ({fmt}) via {spec.provider['name']} provider")
        result = handle.export(image_out, fmt)
        image = {"mode": result.mode, "path": result.path, "format": fmt,
                 "instructions": result.instructions}
        if result.mode == "wrote":
            log(f"[boxbuilder] wrote image -> {result.path}")
        else:
            log(f"[boxbuilder] manual export required (provider can't self-export)")
        return {"image": image, "ok": True}
    finally:
        provider.stop(handle)


# Ordered steps for the unified build. Each entry: (name, runner).
_BUILD_STEPS = ("compile", "plant", "install", "package")


def build_all(spec: BoxSpec, artifacts_dir: str, image_out: Optional[str] = None,
              fmt: str = "ova", from_step: str = "compile",
              nakon_dir: Optional[str] = None, rebuild_bundle: bool = False,
              provider_factory=None, init_kind: Optional[str] = None,
              admin_token: Optional[str] = None, checkin_interval_s: int = 60,
              enrollment_ttl_s: int = 86400, log=print) -> dict:
    """Run the full pipeline (or resume from `from_step`), returning a combined result.

    Resumability: compile writes build-state.json; plant/install/package read it.
    `from_step` skips earlier steps, assuming their state is already on disk.

    Returns a dict keyed by step name, plus top-level ok + completed_step.
    """
    if from_step not in _BUILD_STEPS:
        raise ValueError(f"from_step must be one of {_BUILD_STEPS}, got {from_step!r}")

    results = {"from_step": from_step, "ok": True}
    start_idx = _BUILD_STEPS.index(from_step)

    # 1. compile (or load existing state if resuming past it).
    if start_idx <= 0:
        log("[boxbuilder] === step 1/4: compile ===")
        results["compile"] = compile_box(
            spec, artifacts_dir, nakon_dir=nakon_dir, rebuild_bundle=rebuild_bundle, log=log,
        )
    else:
        state = _load_state(artifacts_dir)
        if state is None:
            raise ValueError(
                f"resuming from {from_step!r} but no build-state.json found in {artifacts_dir}; "
                "run `compile` first"
            )
        results["compile"] = state
        log(f"[boxbuilder] resumed: loaded compile state from {artifacts_dir}")

    # 2. plant.
    if start_idx <= 1:
        log("[boxbuilder] === step 2/4: plant ===")
        results["plant"] = plant_box(
            spec, artifacts_dir, nakon_dir=nakon_dir,
            provider_factory=provider_factory, log=log,
        )
        if not results["plant"].get("ok"):
            results["ok"] = False
            results["completed_step"] = "plant"
            return results

    # 3. install.
    if start_idx <= 2:
        log("[boxbuilder] === step 3/4: install ===")
        results["install"] = install_box(
            spec, artifacts_dir, provider_factory=provider_factory, init_kind=init_kind,
            admin_token=admin_token, checkin_interval_s=checkin_interval_s,
            enrollment_ttl_s=enrollment_ttl_s, log=log,
        )
        if not results["install"].get("ok"):
            results["ok"] = False
            results["completed_step"] = "install"
            return results

    # 4. package.
    if start_idx <= 3:
        log("[boxbuilder] === step 4/4: package ===")
        if not image_out:
            raise ValueError("package step requires --image-out (the output image path)")
        results["package"] = package_box(
            spec, artifacts_dir, image_out=image_out, fmt=fmt,
            provider_factory=provider_factory, log=log,
        )

    results["completed_step"] = _BUILD_STEPS[min(start_idx + 3, 3)] if start_idx < 3 else "package"
    return results
