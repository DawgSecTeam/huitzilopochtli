"""The four-step build pipeline. Each step is a pure-ish function returning a
JSON-serializable result dict, so the CLI layer is a thin wrapper that just
adds argparse + stdout/stderr discipline.

Steps are independently callable so an agent (or a test) can run/verify them
piecemeal. The unified `build` in cli.py chains them with resumability.
"""
import hashlib
import json
import os
from typing import Optional

from boxbuilder import keys, nakon
from boxbuilder.artifacts import INSTALL_DIR  # single source of the install path
from boxbuilder.spec import BoxSpec
from boxbuilder.theme import resolve_theme_configurations

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _load_build_zipapp():
    """Load packaging/build_zipapp.py::build by file path (avoids PyPI shadowing)."""
    import importlib.util
    path = os.path.join(_REPO_ROOT, "packaging", "build_zipapp.py")
    spec = importlib.util.spec_from_file_location("huitzilopochtli.packaging.build_zipapp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build


def compile_box(spec: BoxSpec, artifacts_dir: str, nakon_dir: Optional[str] = None,
                rebuild_bundle: bool = False, vulndb_url: Optional[str] = None,
                log=print) -> dict:
    """Step 1: compile scenario, build agent.pyz, and build nakon bundle."""
    artifacts_dir = os.path.abspath(artifacts_dir)
    os.makedirs(artifacts_dir, exist_ok=True)

    priv_key, key_path = keys.load_authoring_key(spec.authoring_key_path, artifacts_dir)
    log(f"[boxbuilder] authoring key: {key_path}")

    from authoring.compile import compile_scenario

    outputs = compile_scenario(spec.scenario_path, artifacts_dir, priv_key)
    log(f"[boxbuilder] compiled {spec.mode} scenario -> {outputs['manifest']}")

    build_zipapp = _load_build_zipapp()
    agent_pyz = os.path.join(artifacts_dir, "agent.pyz")
    build_zipapp(agent_pyz)
    log(f"[boxbuilder] built agent -> {agent_pyz}")

    ndir = nakon.resolve_nakon_dir(nakon_dir)
    nakon_cfg = dict(spec.nakon_config)
    from boxbuilder import vulndb
    selected_vulns = []
    for machine in nakon_cfg.get("machines", []):
        selected_vulns.extend(machine.get("configurations", []))
    vulndb.ensure_vuln_seeds(vulndb.resolve_vulndb_url(vulndb_url), selected_vulns)
    theme_entries = resolve_theme_configurations(spec, vulndb_url=vulndb_url)
    if theme_entries:
        machines = []
        for m in nakon_cfg.get("machines", []):
            m = dict(m)
            m["configurations"] = list(m.get("configurations", [])) + list(theme_entries)
            machines.append(m)
        nakon_cfg["machines"] = machines
    nakon_cfg_path = os.path.join(artifacts_dir, "nakon-config.json")
    with open(nakon_cfg_path, "w", encoding="utf-8") as f:
        json.dump(nakon_cfg, f, indent=2)
    bundle = nakon.build_bundle(ndir, nakon_cfg_path, out_dir="bundles",
                                rebuild=rebuild_bundle)
    bid = bundle.get("bundle_id")
    log(f"[boxbuilder] nakon bundle {bid[:12] if bid else '?'} "
        f"({'cached' if bundle.get('cached') else 'fresh'}, "
        f"{bundle.get('plans', '?')} plan(s), {bundle.get('machines', '?')} machine(s))")

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
        "fingerprint": _nakon_config_fingerprint(
            spec.scenario["scenario"]["name"], nakon_cfg_path
        ),
    }
    _save_state(artifacts_dir, result)
    return result


def _nakon_config_fingerprint(scenario_name: str, nakon_cfg_path: str) -> dict:
    """Fingerprint the compiled, theme-expanded nakon config so later steps
    can tell artifacts from a previous/different build apart."""
    with open(nakon_cfg_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    return {"scenario_name": scenario_name, "nakon_config_sha256": digest}


def _verify_state_fingerprint(state: dict, spec_scenario_name: str,
                              nakon_cfg_path: str, step: str) -> None:
    """Refuse to reuse artifacts from a different/older build (a stale
    artifacts dir would silently plant and score the WRONG box)."""
    fp = state.get("fingerprint") or {}
    with open(nakon_cfg_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if fp.get("nakon_config_sha256") != digest:
        raise ValueError(
            f"{step}: artifacts dir holds a stale nakon-config.json (its hash "
            f"does not match the one recorded at compile time); re-run "
            f"`compile` or clear the artifacts dir"
        )
    state_name = state.get("scenario_name") or fp.get("scenario_name")
    if state_name and spec_scenario_name and state_name != spec_scenario_name:
        raise ValueError(
            f"{step}: artifacts belong to scenario {state_name!r} but the spec "
            f"is {spec_scenario_name!r}; re-run `compile` with the right spec"
        )


def _save_state(artifacts_dir: str, state: dict) -> None:
    """Persist build-state.json for resumable builds."""
    os.makedirs(artifacts_dir, exist_ok=True)
    path = os.path.join(artifacts_dir, "build-state.json")
    serializable = {k: v for k, v in state.items() if k != "authoring_key"}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2, default=str)


def plant_box(spec: BoxSpec, artifacts_dir: str, bundle_path: Optional[str] = None,
              nakon_dir: Optional[str] = None, provider_factory=None, log=print) -> dict:
    """Step 2: deploy vulns onto the box via nakon."""
    import json as _json
    artifacts_dir = os.path.abspath(artifacts_dir)
    state_path = os.path.join(artifacts_dir, "build-state.json")

    if bundle_path is None:
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

    # compile_box may have appended theme configurations (wallpaper/motd/readme/
    # shortcuts) to the machine's configuration list before building the bundle,
    # so the bundle's request_key was computed over that expanded list. Deriving
    # the deploy config from the *raw* spec.nakon_config here would omit those
    # extras and produce a different request_key that the bundle doesn't
    # contain (nakon deploy looks plans up by request_key, never by machine
    # name). Read back the compiled, theme-expanded config compile_box wrote to
    # artifacts_dir/nakon-config.json when present, falling back to the raw
    # spec config for callers that skip straight to `plant`.
    compiled_nakon_cfg_path = os.path.join(artifacts_dir, "nakon-config.json")
    if os.path.isfile(compiled_nakon_cfg_path):
        # Guard against stale artifacts: a previous/different build's config
        # here would silently plant the WRONG vuln set.
        state = _load_state(artifacts_dir) or {}
        _verify_state_fingerprint(
            state, spec.scenario["scenario"]["name"], compiled_nakon_cfg_path,
            step="plant",
        )
        with open(compiled_nakon_cfg_path, "r", encoding="utf-8") as f:
            effective_nakon_config = _json.load(f)
    else:
        effective_nakon_config = spec.nakon_config

    provider, handle = _resolve_provider(spec.provider, provider_factory, log)
    machine_name = nakon.first_machine_name(effective_nakon_config)
    try:
        derived = nakon.derive_deploy_config(
            effective_nakon_config, machine_name,
            host=handle.addr, user=handle.user, password=handle.password,
            port=getattr(handle, "port", 22),
        )
        derived_path = os.path.join(artifacts_dir, "nakon-deploy-config.json")
        fd = os.open(derived_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            _json.dump(derived, f, indent=2)
            f.flush()
        os.chmod(derived_path, 0o600)
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
    # Pass the FULL cfg (including `name`) through to start(), exactly like the
    # test factory does, so SshProvider can use cfg["name"] for the handle name.
    handle = provider.start(provider_cfg)
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

    # Same stale-artifacts guard as plant: installing a manifest for scenario
    # A on a box planted (or not planted) for scenario B is a silent mismatch.
    compiled_nakon_cfg_path = os.path.join(artifacts_dir, "nakon-config.json")
    if os.path.isfile(compiled_nakon_cfg_path):
        state = compile_result if isinstance(compile_result, dict) else {}
        _verify_state_fingerprint(
            state, spec.scenario["scenario"]["name"], compiled_nakon_cfg_path,
            step="install",
        )

    mode = compile_result["mode"]
    provider, handle = _resolve_provider(spec.provider, provider_factory, log)
    try:
        # --- ranked: wire the engine first so the token can go in agent_config ---
        ranked = None
        enrollment_token = None
        # Single source for the engine address (compile state wins over spec, but
        # they derive from the same scenario); used for both the upload and the
        # on-box agent_config so they can never diverge.
        resolved_engine_url = compile_result.get("engine_url") or spec.engine_url
        if mode == "ranked":
            from boxbuilder import engine
            token = engine.resolve_admin_token(admin_token)
            if not resolved_engine_url:
                raise ValueError("ranked mode requires engine_url (in scenario or compile state)")
            log(f"[boxbuilder] uploading scenario record to engine {resolved_engine_url}")
            engine.upload_scenario(resolved_engine_url, token, compile_result["engine_record"])
            enrollment_token = engine.mint_enrollment_token(
                resolved_engine_url, token,
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
            engine_url=(resolved_engine_url if mode == "ranked" else None),
            checkin_interval_s=(checkin_interval_s if mode == "ranked" else None),
            enrollment_token=enrollment_token,
        )
        files = artifacts_mod.on_box_files(compile_result, mode, agent_cfg)

        # --- place files ---
        log(f"[boxbuilder] installing agent ({mode}) on {handle.name} ({handle.addr})")
        # Ensure the install dir exists first. It is created root-owned (via
        # sudo); if the connecting user is not root, hand the dir to them so the
        # SFTP puts below succeed (SFTP runs as the SSH user, not via sudo).
        mk = handle.run(f"mkdir -p {artifacts_mod.INSTALL_DIR}")
        if not mk.ok:
            raise RuntimeError(f"could not create {artifacts_mod.INSTALL_DIR}: {mk.stderr.strip()}")
        if getattr(handle, "user", "root") != "root":
            ids = handle.run("id -u; id -g", sudo=False)
            parts = ids.stdout.split()
            if not ids.ok or len(parts) < 2:
                raise RuntimeError(
                    f"could not determine uid:gid for {handle.user} on {handle.addr}; "
                    f"cannot make {artifacts_mod.INSTALL_DIR} writable"
                )
            ch = handle.run(f"chown {parts[0]}:{parts[1]} {artifacts_mod.INSTALL_DIR}")
            if not ch.ok:
                raise RuntimeError(
                    f"could not chown {artifacts_mod.INSTALL_DIR} to {parts[0]}:{parts[1]}: "
                    f"{ch.stderr.strip()}"
                )
        placed = []
        for f in files:
            handle.put(f.local, f.remote, mode=f.mode)
            placed.append(f.remote)
        log(f"[boxbuilder] placed {len(placed)} file(s) under {artifacts_mod.INSTALL_DIR}")
        # A score baseline left by a previous install (agent/notify.py) would
        # fire one spurious change alert on the new scenario's first grade;
        # a (re)install starts silent and baselines on first run.
        handle.run(f"rm -f {artifacts_mod.INSTALL_DIR}/score_state.json")

        # --- init unit ---
        if init_kind is None:
            # Auto-detect. The ssh provider exports detect_init; fake providers
            # in tests pass init_kind explicitly to skip this.
            try:
                from boxbuilder.providers.ssh import detect_init
                init_kind = detect_init(handle)
            except Exception as e:
                # Fail-open to "none" is intentional (best-effort detection), but
                # it silently produces a box whose agent never auto-starts, so
                # surface it loudly instead of swallowing it.
                log(f"[boxbuilder] WARNING: could not detect init system ({e}); "
                    f"the agent will not auto-start -- pass --init or enable it manually")
                init_kind = "none"
        handle.install_init(init_kind, mode)
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
              vulndb_url: Optional[str] = None,
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
            spec, artifacts_dir, nakon_dir=nakon_dir, rebuild_bundle=rebuild_bundle,
            vulndb_url=vulndb_url, log=log,
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

    # Track the last step actually run instead of deriving it arithmetically.
    last_run = "compile" if start_idx == 0 else from_step
    if start_idx <= 1:
        log("[boxbuilder] === step 2/4: plant ===")
        results["plant"] = plant_box(
            spec, artifacts_dir, nakon_dir=nakon_dir,
            provider_factory=provider_factory, log=log,
        )
        last_run = "plant"
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
        last_run = "install"
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
        last_run = "package"

    results["completed_step"] = last_run
    return results
