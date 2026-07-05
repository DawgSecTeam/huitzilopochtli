# Packaging

Phase 3 of DAWGSCORE: turns the already-built `agent/` + `common/`
packages into a deployable artifact for a scored box, plus the
init-system glue and reset tooling. See architecture.md §17 for the
authoritative spec this implements.

Nothing under `agent/`, `common/`, `engine/`, or `authoring/` is
modified by anything in this directory.

## Install layout (on the box)

Per §17, a restricted install dir (default `/opt/dawgscore/`) holds:

```
/opt/dawgscore/
  agent.pyz               # built by build_zipapp.py; agent/+common/ only
  agent_config.json        # §9.7 on-box config (mode, paths, interval)
  manifest.signed.json     # compiled + signed by authoring/compile.py
  rubric.json               # honor mode only -- local scoring rubric
  identity.json             # ranked mode only -- box_id + Ed25519 keys, 0600
  report.html                # written by the agent on each run/check-in
```

The **identity file is kept separate and locked down (mode 0600)**:
it holds the box's private Ed25519 key, which must never leave the
box and should not be group/world readable. `agent/identity.py`
already creates it with 0600 permissions; just make sure the
containing directory's ownership doesn't undermine that (e.g. don't
run the agent as a user other than the one that owns
`/opt/dawgscore/identity.json`).

Honor mode does not use `identity.json` at all (no network, no
engine) -- only `rubric.json` is needed locally, per
`agent/__main__.py`'s `_run_honor`.

## Alpine caveat

Minimal Alpine images ship **without a Python interpreter at all**.
Box provisioning for Alpine/musl targets must run:

```
apk add python3
```

before the agent (or either init script below) can start. This is
also why the zipapp -- not a compiled PyInstaller/Nuitka binary -- is
the default artifact: a binary built against glibc will not run on
Alpine's musl libc, whereas the pure-stdlib `.pyz` runs anywhere a
`python3` is present (Debian, Fedora, Alpine alike).

## Build

From the repo root, on a dev/build machine (not the box):

```
python3 packaging/build_zipapp.py
```

This writes `dist/agent.pyz` (root `.gitignore` already ignores
`*.pyz`, and now also `dist/`). Pass an explicit output path as the
only CLI argument to override:

```
python3 packaging/build_zipapp.py /tmp/agent.pyz
```

The build copies only the `agent/` and `common/` package directories
into a temp dir and hands them to Python's stdlib `zipapp` module with
`main="agent.__main__:main"`. `engine/` and `authoring/` are never
copied in, so the artifact can't accidentally pull in PyYAML (an
authoring-only dependency) or ship server-side code to a box.

## Compile a scenario (author machine, separate from this directory)

Use the existing `authoring/compile.py` `compile_scenario(...)` to
produce `manifest.signed.json` (+ `rubric.json` for honor mode, or
`engine_record.json` for ranked) from a scenario YAML. That output is
what gets copied into `/opt/dawgscore/` alongside the `.pyz` below --
see that module's docstring for details; it is unaffected by this
phase.

## Install (on the box)

1. Build the zipapp (above) and copy `agent.pyz` to
   `/opt/dawgscore/agent.pyz`.
2. Copy the compiled `manifest.signed.json` (and `rubric.json` for
   honor mode) to `/opt/dawgscore/`.
3. Write `/opt/dawgscore/agent_config.json` (§9.7 shape):

   ```json
   {
     "mode": "honor",
     "manifest_path": "/opt/dawgscore/manifest.signed.json",
     "rubric_path": "/opt/dawgscore/rubric.json",
     "identity_path": null,
     "report_path": "/opt/dawgscore/report.html",
     "checkin_interval_s": null
   }
   ```

   (For ranked mode: `"mode": "ranked"`, `"rubric_path": null`,
   `"identity_path": "/opt/dawgscore/identity.json"`, and a real
   `checkin_interval_s`.)

4. Install the init unit for the box's init system:

   - **systemd:**
     ```
     cp packaging/dawgscore-agent.service /etc/systemd/system/
     systemctl daemon-reload
     systemctl enable --now dawgscore-agent
     ```
   - **OpenRC (Alpine):**
     ```
     apk add python3   # if not already present -- see caveat above
     cp packaging/dawgscore-agent.openrc /etc/init.d/dawgscore-agent
     chmod +x /etc/init.d/dawgscore-agent
     rc-update add dawgscore-agent default
     rc-service dawgscore-agent start
     ```

5. Export the configured VM as `.ova`/`.qcow2` for distribution (§17).

Both unit files work for either mode without modification -- the
mode is selected entirely by `agent_config.json`. See the comments in
each unit file for the honor-vs-ranked `Restart=`/backgrounding
tradeoffs.

## Re-arm / reset (take-home replay)

To let a take-home box be replayed without a full redeploy:

```
python3 packaging/rearm.py /opt/dawgscore
```

By default this only deletes the cached report (`report_path` from
`agent_config.json`), leaving box identity and sequence number
untouched -- appropriate for "let me retake this scenario" without
re-enrolling as a new box with the engine. Pass `--reset-identity` to
additionally delete the ranked-mode identity file and its transport
queue, which forces generation of a brand-new box identity (new
`box_id` + Ed25519 keypair, `last_seq` back to 0) on the next ranked
run -- see the comment in `rearm.py` for why that's opt-in rather than
the default.
