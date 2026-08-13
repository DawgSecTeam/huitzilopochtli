"""boxbuilder CLI.

Agent-facing: every subcommand supports `--json`, which prints the result as a
single JSON line on stdout (parseable like nakon's --json). Progress/logs go to
stderr so `boxbuilder <cmd> --json | jq` works.

Usage:
    python3 -m boxbuilder compile --spec box.yaml [--out artifacts/] [--json]
    python3 -m boxbuilder plant   --spec box.yaml [--artifacts artifacts/] [--json]
    python3 -m boxbuilder install --spec box.yaml --artifacts artifacts/ [--json]
    python3 -m boxbuilder package --spec box.yaml --artifacts artifacts/ --out box.ova [--json]
    python3 -m boxbuilder build   --spec box.yaml [--from-step compile|plant|install|package] [--json]

The spec file may be replaced by direct flags (--scenario, --nakon-config,
--provider-*). See boxbuilder/README.md.
"""
import argparse
import json
import os
import sys
from typing import Optional

from boxbuilder import nakon as nakon_mod
from boxbuilder.pipeline import (
    build_all, compile_box, install_box, package_box, plant_box,
)
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
def _spec_from_args(args) -> BoxSpec:
    """Load spec from --spec, or assemble one from direct flags."""
    if args.spec:
        return load_spec(args.spec)

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
    validate_inputs(scenario, nakon_config)
    provider = {}
    if getattr(args, "provider", None):
        provider["name"] = args.provider
        if args.provider_host:
            provider["host"] = args.provider_host
        if args.provider_port:
            provider["port"] = args.provider_port
        if args.provider_user:
            provider["user"] = args.provider_user
        if args.provider_password:
            provider["password"] = args.provider_password
    return BoxSpec(
        scenario_path=os.path.abspath(args.scenario),
        nakon_config_path=os.path.abspath(args.nakon_config),
        provider=provider,
        authoring_key_path=os.path.abspath(args.authoring_key) if args.authoring_key else None,
        base_dir=os.getcwd(),
        scenario=scenario,
        nakon_config=nakon_config,
    )


def _add_spec_inputs(p: argparse.ArgumentParser) -> None:
    """Common inputs shared by every subcommand."""
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--spec", help="box spec YAML (preferred)")
    src.add_argument("--scenario", help="huitz scenario YAML (direct-flag path)")
    p.add_argument("--nakon-config", help="nakon config JSON (direct-flag path)")
    p.add_argument("--authoring-key", help="path to a 32-byte Ed25519 authoring key seed")
    p.add_argument("--nakon-dir", help="nakon repo dir (default: $NAKON_DIR then ../nakon)")
    p.add_argument("--vulndb-url", help="vulndb-ui base URL, for themed scenarios only "
                                        "(default: $VULNDB_UI_URL then http://127.0.0.1:3000)")
    # Provider flags (consumed by plant/install/package; ignored by compile).
    p.add_argument("--provider", choices=("ssh",), help="box provider (v1: ssh)")
    p.add_argument("--provider-host")
    p.add_argument("--provider-port", type=int)
    p.add_argument("--provider-user")
    p.add_argument("--provider-password")
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
            rebuild_bundle=args.rebuild_bundle,
            vulndb_url=args.vulndb_url,
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
    spec = _spec_from_args(args)
    out = args.out or os.path.join(os.getcwd(), "artifacts")
    try:
        result = build_all(
            spec, artifacts_dir=out, image_out=args.image_out, fmt=args.format,
            from_step=args.from_step, nakon_dir=args.nakon_dir,
            rebuild_bundle=args.rebuild_bundle, vulndb_url=args.vulndb_url,
            init_kind=args.init,
            admin_token=args.admin_token, checkin_interval_s=args.checkin_interval,
            enrollment_ttl_s=args.enrollment_ttl, log=_eprint,
        )
    except Exception as e:
        _eprint(f"build failed: {e}")
        if args.json:
            _emit({"ok": False, "error": str(e), "completed_step": None}, as_json=True)
        return 1
    _emit(result, args.json)
    return 0 if result.get("ok", False) else 1


def cmd_install(args) -> int:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boxbuilder",
        description="Build practice boxes: pair nakon-planted vulns with huitzilopochtli scoring.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_compile = sub.add_parser("compile", help="compile scenario + build agent.pyz + build nakon bundle")
    _add_spec_inputs(p_compile)
    p_compile.add_argument("--out", help="artifacts output dir (default: ./artifacts)")
    p_compile.add_argument("--rebuild-bundle", action="store_true",
                           help="force nakon to rebuild even if a matching bundle is cached")
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
    p_build.add_argument("--rebuild-bundle", action="store_true",
                         help="force nakon to rebuild even if a matching bundle is cached")
    p_build.add_argument("--init", choices=("systemd", "openrc", "none"),
                         help="init system (default: auto-detect)")
    p_build.add_argument("--admin-token", help="engine admin token "
                           "(default: $HUITZILOPOCHTLI_ADMIN_TOKEN; required for ranked)")
    p_build.add_argument("--checkin-interval", type=int, default=60,
                           help="ranked check-in interval seconds (default: 60)")
    p_build.add_argument("--enrollment-ttl", type=int, default=86400,
                           help="enrollment token TTL seconds (default: 86400)")
    p_build.add_argument("--image-out", help="output image path (package step)")
    p_build.add_argument("--format", choices=("ova", "qcow2", "raw"), default="ova")
    p_build.set_defaults(func=cmd_build)

    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Direct-flag path requires --nakon-config when --spec is absent.
    if not args.spec and not args.nakon_config:
        parser.error("provide --spec FILE, or both --scenario and --nakon-config")
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
