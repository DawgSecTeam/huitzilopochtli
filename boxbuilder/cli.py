"""boxbuilder CLI.

Agent-facing: every subcommand supports `--json`, which prints the result as a
single JSON line on stdout (parseable like nakon's --json). Progress/logs go to
stderr so `boxbuilder <cmd> --json | jq` works.

Usage:
    python3 -m boxbuilder compile --spec box.yaml [--out artifacts/] [--json]
    python3 -m boxbuilder plant   --spec box.yaml --provider-host HOST [--json]
    python3 -m boxbuilder install --spec box.yaml --mode ranked --provider-host HOST [--json]
    python3 -m boxbuilder lint    [--spec box.yaml] [--json]
    python3 -m boxbuilder package --spec box.yaml [--out artifacts/] --image-out box.ova [--json]
    python3 -m boxbuilder build   --spec box.yaml [--image-out box.ova] [--from-step compile|plant|install|package] [--json]
    python3 -m boxbuilder answer-key --scenario scenario.yaml [--out PATH] [--html] [--json]

The build target (honor|ranked) comes from --mode, defaulting to the
scenario's ``scenario.mode``. Provider connection details come from
--provider-* flags or $HUITZILOPOCHTLI_PROVIDER_{HOST,USER,PASSWORD,PORT} and
override whatever the spec file carries, so no deployment address has to be
committed. The spec file may be replaced by direct flags (--scenario,
--nakon-config, --provider-*). See boxbuilder/README.md.
"""
import argparse
import glob
import json
import os
import sys
from typing import Optional

from boxbuilder.lint import lint_box
from boxbuilder.pipeline import (
    _resolve_provider, build_all, compile_box, install_box, package_box, plant_box,
)
from boxbuilder.verify import collect_facts, evaluate, expectations_from, prepare_seal, summarise
from boxbuilder.spec import BoxSpec, load_spec, validate_inputs

_STEPS = ("compile", "plant", "install", "package")


# --- output discipline ----------------------------------------------------
def _emit(result: dict, as_json: bool) -> None:
    """Result -> stdout. --json prints a single line; otherwise a human summary."""
    if as_json:
        # Single line, like nakon, so orchestrators can take stdout.splitlines()[-1].
        sys.stdout.write(json.dumps(result, default=str) + "\n")
        sys.stdout.flush()
        return
    _print_human(result)


def _print_human(result: dict) -> None:
    """Best-effort human summary. Keeps keys visible; not a stable format."""
    for k, v in result.items():
        if isinstance(v, dict):
            sys.stderr.write(f"  {k}:\n")
            for kk, vv in v.items():
                sys.stderr.write(f"    {kk}: {vv}\n")
        else:
            sys.stderr.write(f"  {k}: {v}\n")


def _eprint(*args) -> None:
    print(*args, file=sys.stderr)


# --- spec loading ---------------------------------------------------------
def _target_overrides(args) -> tuple:
    """(mode, engine_url) overrides from flags/env; either may be None."""
    mode = getattr(args, "mode", None)
    engine_url = (getattr(args, "engine_url", None)
                  or os.environ.get("HUITZILOPOCHTLI_ENGINE_URL"))
    return mode, engine_url


def _spec_from_args(args) -> BoxSpec:
    """Load spec from --spec, or assemble one from direct flags."""
    mode, engine_url = _target_overrides(args)

    if args.spec:
        spec = load_spec(args.spec, mode=mode, engine_url=engine_url)
        return _apply_provider_overrides(spec, args)

    # Direct-flag assembly path (no box.yaml).
    if not (args.scenario and args.nakon_config):
        raise SystemExit(
            "provide --spec FILE, or both --scenario and --nakon-config"
        )
    # Build a minimal spec object without a spec file. We still load+validate
    # the scenario/nakon config the same way load_spec does.
    import yaml
    with open(args.scenario, "r", encoding="utf-8") as f:
        scenario = yaml.safe_load(f)
    with open(args.nakon_config, "r", encoding="utf-8") as f:
        nakon_config = json.load(f)
    validate_inputs(scenario, nakon_config, mode=mode, engine_url=engine_url)
    spec = BoxSpec(
        scenario_path=os.path.abspath(args.scenario),
        nakon_config_path=os.path.abspath(args.nakon_config),
        provider={"name": getattr(args, "provider", None) or "ssh"},
        authoring_key_path=os.path.abspath(args.authoring_key) if args.authoring_key else None,
        # Theme assets resolve relative to the scenario's directory, exactly
        # like the spec-file path does (theme.py uses spec.base_dir) — using
        # CWD here would make the same inputs behave differently per invocation.
        base_dir=os.path.dirname(os.path.abspath(args.scenario)),
        mode_override=mode,
        engine_url_override=engine_url,
        scenario=scenario,
        nakon_config=nakon_config,
    )
    return _apply_provider_overrides(spec, args)


def _apply_provider_overrides(spec: BoxSpec, args) -> BoxSpec:
    """Fold --provider-* flags and $HUITZILOPOCHTLI_PROVIDER_* over the spec.

    Connection details are deployment facts, not box authoring: the committed
    spec carries at most a user and a port, and every deploy supplies the
    address (a DHCP clone's IP changes on every rebuild).
    """
    provider = dict(spec.provider or {})
    name = getattr(args, "provider", None)
    if name:
        provider["name"] = name

    env = {
        "host": os.environ.get("HUITZILOPOCHTLI_PROVIDER_HOST"),
        "user": os.environ.get("HUITZILOPOCHTLI_PROVIDER_USER"),
        "password": os.environ.get("HUITZILOPOCHTLI_PROVIDER_PASSWORD"),
        "port": os.environ.get("HUITZILOPOCHTLI_PROVIDER_PORT"),
    }
    flags = {
        "host": getattr(args, "provider_host", None),
        "user": getattr(args, "provider_user", None),
        "password": getattr(args, "provider_password", None),
        "port": getattr(args, "provider_port", None),
    }
    for key in ("host", "user", "password"):
        value = flags[key] or env[key]
        if value:
            provider[key] = value
    port = flags["port"] or env["port"]
    if port:
        provider["port"] = int(port)

    if "user" not in provider:
        provider["user"] = "root"
    if not provider.get("password") and args.command in (
            "plant", "install", "verify", "seal-prepare"):
        # Never prompt on `compile`/`package`; those do not log in.
        import getpass
        provider["password"] = getpass.getpass(
            f"SSH password for {provider.get('user')}@{provider.get('host', '?')}: ")

    spec.provider = provider
    return spec


def _add_spec_inputs(p: argparse.ArgumentParser) -> None:
    """Common inputs shared by every subcommand."""
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--spec", help="box spec YAML (preferred)")
    src.add_argument("--scenario", help="huitz scenario YAML (direct-flag path)")
    p.add_argument("--nakon-config", help="nakon config JSON (direct-flag path)")
    p.add_argument("--mode", choices=("honor", "ranked"),
                   help="build target (default: the scenario's scenario.mode)")
    p.add_argument("--engine-url", help="ranked engine base URL "
                   "(default: $HUITZILOPOCHTLI_ENGINE_URL, then the ranked block)")
    p.add_argument("--authoring-key", help="path to a 32-byte Ed25519 authoring key seed")
    p.add_argument("--nakon-dir", help="nakon repo dir (default: $NAKON_DIR, then vendor/nakon, then ../nakon)")
    p.add_argument("--vulndb-url", help="vulndb-ui base URL, for themed scenarios only "
                                        "(default: $VULNDB_UI_URL then http://127.0.0.1:3000)")
    # Provider flags (consumed by plant/install/package; ignored by compile).
    p.add_argument("--provider", choices=("ssh",), help="box provider (v1: ssh)")
    p.add_argument("--provider-host", help="box address (default: $HUITZILOPOCHTLI_PROVIDER_HOST)")
    p.add_argument("--provider-port", type=int)
    p.add_argument("--provider-user", help="default: $HUITZILOPOCHTLI_PROVIDER_USER, then the spec")
    p.add_argument("--provider-password", help="default: $HUITZILOPOCHTLI_PROVIDER_PASSWORD (prompted otherwise)")
    p.add_argument("--json", action="store_true", help="print result as one JSON line on stdout")


# --- subcommands ----------------------------------------------------------
def cmd_compile(args) -> int:
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    try:
        result = compile_box(
            spec,
            artifacts_dir=out,
            nakon_dir=args.nakon_dir,
            vulndb_url=args.vulndb_url,
            skip_bundle=args.no_bundle,
            log=_eprint,
        )
    except Exception as e:
        _eprint(f"compile failed: {e}")
        if args.json:
            _emit({"ok": False, "error": str(e), "step": "compile"}, as_json=True)
        return 1
    result["ok"] = True
    result["step"] = "compile"
    _emit(result, args.json)
    return 0


def cmd_package(args) -> int:
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    if not args.image_out:
        _eprint("package requires --image-out (the output image path)")
        return 2
    try:
        result = package_box(
            spec, artifacts_dir=out, image_out=args.image_out, fmt=args.format, log=_eprint,
        )
    except Exception as e:
        _eprint(f"package failed: {e}")
        if args.json:
            _emit({"ok": False, "error": str(e), "step": "package"}, as_json=True)
        return 1
    result["step"] = "package"
    _emit(result, args.json)
    return 0 if result.get("ok", False) else 1


def cmd_build(args) -> int:
    if getattr(args, "admin_token", None):
        _eprint("WARNING: --admin-token is visible in process lists and shell "
                "history; prefer $HUITZILOPOCHTLI_ADMIN_TOKEN")
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    try:
        result = build_all(
            spec, artifacts_dir=out, image_out=args.image_out, fmt=args.format,
            from_step=args.from_step, nakon_dir=args.nakon_dir,
            vulndb_url=args.vulndb_url, skip_bundle=args.no_bundle,
            init_kind=args.init,
            admin_token=args.admin_token, checkin_interval_s=args.checkin_interval,
            enrollment_ttl_s=args.enrollment_ttl,
            competition_mode=getattr(args, "competition", False), log=_eprint,
        )
    except Exception as e:
        _eprint(f"build failed: {e}")
        if args.json:
            _emit({"ok": False, "error": str(e),
                   "completed_step": getattr(e, "completed_step", None)},
                  as_json=True)
        return 1
    _emit(result, args.json)
    return 0 if result.get("ok", False) else 1


def cmd_install(args) -> int:
    if getattr(args, "admin_token", None):
        _eprint("WARNING: --admin-token is visible in process lists and shell "
                "history; prefer $HUITZILOPOCHTLI_ADMIN_TOKEN")
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    try:
        result = install_box(
            spec,
            artifacts_dir=out,
            init_kind=args.init,
            admin_token=args.admin_token,
            checkin_interval_s=args.checkin_interval,
            enrollment_ttl_s=args.enrollment_ttl,
            competition_mode=getattr(args, "competition", False),
            log=_eprint,
        )
    except Exception as e:
        _eprint(f"install failed: {e}")
        if args.json:
            _emit({"ok": False, "error": str(e), "step": "install"}, as_json=True)
        return 1
    result["step"] = "install"
    _emit(result, args.json)
    return 0 if result.get("ok", False) else 1


def cmd_plant(args) -> int:
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    try:
        result = plant_box(
            spec,
            artifacts_dir=out,
            bundle_path=args.bundle,
            nakon_dir=args.nakon_dir,
            log=_eprint,
        )
    except Exception as e:
        _eprint(f"plant failed: {e}")
        if args.json:
            _emit({"ok": False, "error": str(e), "step": "plant"}, as_json=True)
        return 1
    result["step"] = "plant"
    _emit(result, args.json)
    return 0 if result.get("ok", False) else 1


def cmd_answer_key(args) -> int:
    from boxbuilder import answerkey

    try:
        result = answerkey.generate(args.scenario, out_path=args.out,
                                    want_html=args.html)
    except Exception as e:
        _eprint(f"answer-key failed: {e}")
        if args.json:
            _emit({"ok": False, "error": str(e), "step": "answer-key"}, as_json=True)
        return 1
    result["step"] = "answer-key"
    _emit(result, args.json)
    return 0


def cmd_lint(args) -> int:
    """Cross-check every box's planted vulns against its scored checks."""
    targets = []
    if args.all:
        root = args.boxes_dir or os.path.join(os.getcwd(), "boxes")
        targets = sorted(glob.glob(os.path.join(root, "*", "box.yaml")))
        if not targets:
            _eprint(f"no box.yaml under {root}")
            return 2
    else:
        targets = [None]

    reports = []
    for target in targets:
        try:
            spec = _spec_from_args(args) if target is None else load_spec(target)
            report = lint_box(spec, catalog=args.catalog,
                             nakon_dir=args.nakon_dir)
        except Exception as exc:
            report = {"ok": False, "box": target or args.spec,
                      "errors": [f"{type(exc).__name__}: {exc}"], "warnings": []}
        reports.append(report)
        status = "ok" if report.get("ok") else "FAILED"
        label = report.get("box") or target
        _eprint(f"[boxbuilder] {label}: {status} "
                f"({len(report.get('errors') or [])} error(s), "
                f"{len(report.get('warnings') or [])} warning(s))")
        for message in report.get("errors") or []:
            _eprint(f"  ERROR   {message}")
        for message in report.get("warnings") or []:
            _eprint(f"  warning {message}")

    failed = any(not report.get("ok") for report in reports)
    _emit({"ok": not failed, "reports": reports}, args.json)
    return 1 if failed else 0


def _with_provider(spec, fn, log=_eprint):
    """Run ``fn(provider, handle)`` and always release the provider."""
    provider, handle = _resolve_provider(spec.provider, None, log)
    try:
        return fn(provider, handle)
    finally:
        provider.stop(handle)


def cmd_verify(args) -> int:
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    try:
        exp = expectations_from(
            spec, out, competition=args.competition,
            expect_total=args.expect_total, for_seal=args.for_seal,
        )

        def run(_provider, handle):
            return summarise(evaluate(collect_facts(handle, spec, out), exp))

        report = _with_provider(spec, run)
    except Exception as exc:
        _eprint(f"verify failed: {exc}")
        if args.json:
            _emit({"ok": False, "error": str(exc), "step": "verify"}, as_json=True)
        return 1

    for check in report["checks"]:
        _eprint(f"  {check['status']:<5} {check['id']:<20} {check['detail']}")
    counts = report["counts"]
    _eprint(f"[boxbuilder] verify: {counts} "
            f"({'ok' if report['ok'] else 'FAILED'})")
    summary = dict(report, step="verify", mode=spec.mode)
    _emit(summary, args.json)
    return 0 if report["ok"] else 1


def cmd_seal_prepare(args) -> int:
    if not args.yes:
        _eprint("seal-prepare mutates the box (stops the agent, wipes state, "
                "empties /etc/machine-id); re-run with --yes")
        return 2
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    try:
        result = _with_provider(
            spec,
            lambda _provider, handle: prepare_seal(
                handle, spec, out, skip_verify=args.skip_verify,
                expect_total=args.expect_total,
            ),
        )
    except Exception as exc:
        _eprint(f"seal-prepare failed: {exc}")
        if args.json:
            _emit({"ok": False, "error": str(exc), "step": "seal-prepare"}, as_json=True)
        return 1

    if result.get("verify"):
        counts = result["verify"]["counts"]
        _eprint(f"[boxbuilder] pre-seal verify: {counts}")
        for check in result["verify"]["checks"]:
            if check["status"] in ("fail", "warn"):
                _eprint(f"  {check['status']:<5} {check['id']:<20} {check['detail']}")
    if result.get("reason"):
        _eprint(f"[boxbuilder] seal-prepare aborted: {result['reason']} "
                f"(fix the failures, or pass --skip-verify)")
    for step in result.get("steps") or []:
        _eprint(f"  {step['status']:<8} {step['id']:<12} {step['detail']}")
    for note in result.get("next") or []:
        _eprint(f"  next: {note}")
    _emit(result, args.json)
    return 0 if result.get("ok") else 1


def _add_verify_flags(p) -> None:
    p.add_argument("--competition", action="store_true",
                   help="expect a ranked competition template (unit stopped, no token)")
    p.add_argument("--expect-total", type=int,
                   help="expected report total (default: 0 for honor, unset for ranked)")
    p.add_argument("--for-seal", action="store_true",
                   help="also require seal hygiene (no identity, no legacy install dir)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boxbuilder",
        description="Build practice boxes: pair nakon-planted vulns with huitzilopochtli scoring.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_compile = sub.add_parser("compile", help="compile scenario + build agent.pyz + build nakon bundle")
    _add_spec_inputs(p_compile)
    p_compile.add_argument("--out", help="artifacts output dir (default: ./artifacts)")
    p_compile.add_argument("--no-bundle", action="store_true",
                           help="skip the nakon bundle (install-only builds: a ranked "
                                "template installs over an already-planted box)")
    p_compile.set_defaults(func=cmd_compile)

    p_plant = sub.add_parser("plant", help="deploy vulns onto the box via nakon")
    _add_spec_inputs(p_plant)
    p_plant.add_argument("--out", help="artifacts dir (default: ./artifacts)")
    p_plant.add_argument("--bundle", help="bundle path (default: recorded by compile)")
    p_plant.set_defaults(func=cmd_plant)

    p_install = sub.add_parser("install",
                               help="place agent + manifest (+ rubric for honor) on the box; "
                                    "ranked also wires the engine")
    _add_spec_inputs(p_install)
    p_install.add_argument("--out", help="artifacts dir (default: ./artifacts)")
    p_install.add_argument("--init", choices=("systemd", "openrc", "none"),
                           help="init system (default: auto-detect)")
    p_install.add_argument("--admin-token", help="engine admin token "
                           "(default: $HUITZILOPOCHTLI_ADMIN_TOKEN; required for ranked)")
    p_install.add_argument("--checkin-interval", type=int, default=60,
                           help="ranked check-in interval seconds (default: 60)")
    p_install.add_argument("--enrollment-ttl", type=int, default=86400,
                           help="enrollment token TTL seconds (default: 86400)")
    p_install.add_argument("--competition", action="store_true",
                           help="ranked competition box: no token; player runs `huitz join`")
    p_install.set_defaults(func=cmd_install)

    p_package = sub.add_parser("package", help="export the box image for distribution")
    _add_spec_inputs(p_package)
    p_package.add_argument("--out", help="artifacts dir (default: ./artifacts)")
    p_package.add_argument("--image-out", required=True, help="output image path")
    p_package.add_argument("--format", choices=("ova", "qcow2", "raw"), default="ova")
    p_package.set_defaults(func=cmd_package)

    p_build = sub.add_parser("build", help="run all four steps with resumability")
    _add_spec_inputs(p_build)
    p_build.add_argument("--out", help="artifacts output dir (default: ./artifacts)")
    p_build.add_argument("--from-step", choices=_STEPS, default="compile",
                         help="resume from this step (default: compile)")
    p_build.add_argument("--init", choices=("systemd", "openrc", "none"),
                         help="init system (default: auto-detect)")
    p_build.add_argument("--admin-token", help="engine admin token "
                           "(default: $HUITZILOPOCHTLI_ADMIN_TOKEN; required for ranked)")
    p_build.add_argument("--checkin-interval", type=int, default=60,
                           help="ranked check-in interval seconds (default: 60)")
    p_build.add_argument("--enrollment-ttl", type=int, default=86400,
                           help="enrollment token TTL seconds (default: 86400)")
    p_build.add_argument("--competition", action="store_true",
                         help="ranked competition box: no token; player runs `huitz join`")
    p_build.add_argument("--no-bundle", action="store_true",
                         help="skip the nakon bundle when compiling")
    p_build.add_argument("--image-out", help="output image path (package step)")
    p_build.add_argument("--format", choices=("ova", "qcow2", "raw"), default="ova")
    p_build.set_defaults(func=cmd_build)

    p_verify = sub.add_parser(
        "verify",
        help="check a live box against its build (files, lineage, init, report, theme)")
    _add_spec_inputs(p_verify)
    p_verify.add_argument("--out", help="artifacts dir holding build-state.json "
                                        "(default: ./artifacts)")
    _add_verify_flags(p_verify)
    p_verify.set_defaults(func=cmd_verify)

    p_seal = sub.add_parser(
        "seal-prepare",
        help="remove per-player state and neutralize the box before sealing")
    _add_spec_inputs(p_seal)
    p_seal.add_argument("--out", help="artifacts dir holding build-state.json")
    _add_verify_flags(p_seal)
    p_seal.add_argument("--skip-verify", action="store_true",
                        help="do not gate on verification passing")
    p_seal.add_argument("--yes", action="store_true",
                        help="required: this mutates the box irreversibly")
    p_seal.set_defaults(func=cmd_seal_prepare)

    p_lint = sub.add_parser(
        "lint",
        help="cross-check nakon plants against scored checks (paths, names, assets)")
    p_lint.add_argument("--spec", help="box spec YAML")
    p_lint.add_argument("--scenario", help="huitz scenario YAML (direct-flag path)")
    p_lint.add_argument("--nakon-config", help="nakon config JSON (direct-flag path)")
    p_lint.add_argument("--mode", choices=("honor", "ranked"),
                        help="build target to lint (default: the scenario's)")
    p_lint.add_argument("--engine-url", help="ranked engine base URL")
    p_lint.add_argument("--all", action="store_true", help="lint every box under boxes/")
    p_lint.add_argument("--boxes-dir", help="box folder for --all (default: ./boxes)")
    p_lint.add_argument("--catalog", action="store_true",
                        help="also validate the selection with `nakon catalog check` "
                             "(needs the nakon checkout and catalog access)")
    p_lint.add_argument("--nakon-dir", help="nakon checkout for --catalog")
    p_lint.add_argument("--json", action="store_true",
                        help="print the reports as one JSON line on stdout")
    p_lint.set_defaults(func=cmd_lint)

    p_answerkey = sub.add_parser(
        "answer-key",
        help="render authored `solution:` walkthroughs into a post-event "
             "answer-key handout (Markdown, + themed HTML with --html)")
    p_answerkey.add_argument("--scenario", required=True,
                             help="huitz scenario YAML")
    p_answerkey.add_argument("--out", help="output Markdown path "
                             "(default: artifacts/answer-keys/<slug>.md)")
    p_answerkey.add_argument("--html", action="store_true",
                             help="also write a themed HTML page next to it")
    p_answerkey.add_argument("--json", action="store_true",
                             help="print result as one JSON line on stdout")
    p_answerkey.set_defaults(func=cmd_answer_key)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Direct-flag path requires --nakon-config when --spec is absent.
    # answer-key is authoring-side only -- it never touches nakon.
    needs_spec = args.command not in ("answer-key", "lint")
    if needs_spec and not args.spec and not args.nakon_config:
        parser.error("provide --spec FILE, or both --scenario and --nakon-config")
    if args.command == "lint" and not (args.all or args.spec or args.scenario):
        parser.error("lint needs --all, --spec FILE, or --scenario + --nakon-config")
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
