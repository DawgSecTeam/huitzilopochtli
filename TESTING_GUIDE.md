# Testing guide — prove it works on your machine

A hands-on walkthrough that runs on one host: no Proxmox, no second machine.
Budget ~15 minutes, most of it waiting on crypto. Run commands from the repo
root; in each shell you use, start with the two variables under Prerequisites.

## 0. Prerequisites

```bash
python3 --version          # 3.10+ (built/tested on 3.14)
pip install -r requirements-dev.txt
REPO="$PWD"                          # run this from the repo root
MANUAL=/tmp/huitzilopochtli-manual
```

Default tier plus optional paramiko/proxmoxer; the shipped code stays stdlib-only.

## 1. Automated tiers

```bash
pytest                     # unit + integration (the default)
pytest -m proxmox          # opt-in live tier; needs tests/proxmox/.env
```

- **`tests/unit/`** — schema/type validation, canonicalization, matchers and
  check plugins, category scoring, Ed25519 vectors, the SLA ledger, the
  adversary oracle, the store, competition/claim logic, and the closed
  adversary action vocabulary.
- **`tests/integration/`** — real `engine.server` and `agent` subprocesses over
  loopback with real sqlite and signing: honor pipeline, ranked enroll/
  restart/crash recovery, protocol errors, admin endpoints, adversary + SLA,
  competition HTTP, zipapp equivalence.
- **`tests/proxmox/`** — real disposable clones, excluded unless you ask for
  it; it skips with a reason when `tests/proxmox/.env` is absent. See
  `tests/README.md`.

**Why it is slow: Ed25519, not a hang.** Every check-in pays a client sign
plus a server verify of the vendored pure-Python implementation, so the ranked
suite takes minutes even though each test is short (`test_ranked_loopback.py`
alone is ~70s). Leave it running. One unit test (the root-write symlink guard)
skips unless you run as root.

## 2. Honor mode, by hand

```bash
mkdir -p "$MANUAL/honor" && cd "$MANUAL/honor"
echo "SECURE_BANNER" > banner.txt
cat > scenario.yaml <<EOF
scenario:
  name: "Manual Test Scenario"
  version: 1
  mode: honor
  hosts: ["localhost"]

checks:
  - id: banner_ok
    type: file_regex
    category: vuln
    display: "Banner present"
    max_points: 10
    collect: {path: $MANUAL/honor/banner.txt, extract: '(SECURE_BANNER)'}
    expect: {equals: "SECURE_BANNER", points: 10}
EOF
```

There is no CLI wrapper for compiling a scenario, so drive the library:

```bash
cd "$REPO"
python3 -c "
import sys, json
sys.path.insert(0, '.')
from authoring.compile import compile_scenario
from common.crypto import signing
priv, pub = signing.keypair()
outputs = compile_scenario('$MANUAL/honor/scenario.yaml', '$MANUAL/honor', priv)
print(json.dumps(outputs, indent=2))
"
```

You should see paths for `manifest`, `rubric`, `engine_record`, and
`authoring_public_key`. Write the agent config and run the agent:

```bash
cat > "$MANUAL/honor/agent_config.json" <<EOF
{"mode": "honor",
 "manifest_path": "$MANUAL/honor/manifest.signed.json",
 "authoring_public_key_path": "$MANUAL/honor/authoring_public_key.b64",
 "rubric_path": "$MANUAL/honor/rubric.json",
 "identity_path": null,
 "report_path": "$MANUAL/honor/report.html",
 "checkin_interval_s": null}
EOF
python3 -m agent "$MANUAL/honor/agent_config.json"; echo "exit code: $?"
grep -o "Total: [0-9]*" "$MANUAL/honor/report.html"
```

Expected: exit code `0`, no output (silence is success), and `Total: 10`.

**Break it on purpose.** Tamper with the signed manifest and confirm the agent
fails closed:

```bash
python3 -c "
import json
p = '$MANUAL/honor/manifest.signed.json'
m = json.load(open(p)); m['scenario_version'] = 999
json.dump(m, open(p, 'w'))
"
rm "$MANUAL/honor/report.html"
python3 -m agent "$MANUAL/honor/agent_config.json"; echo "exit code: $?"
```

Expected: a **non-zero** exit, an error naming `FAILED signature verification`,
and no new `report.html`.

**Re-arm** (the manifest is now permanently tampered; recompile first):

```bash
python3 -c "
import sys
sys.path.insert(0, '.')
from authoring.compile import compile_scenario
from common.crypto import signing
priv, pub = signing.keypair()
compile_scenario('$MANUAL/honor/scenario.yaml', '$MANUAL/honor', priv)
"
python3 -m agent "$MANUAL/honor/agent_config.json"
python3 packaging/rearm.py --config "$MANUAL/honor/agent_config.json"
ls "$MANUAL/honor/report.html"          # expect: No such file
```

## 3. The `huitz` terminal console

The agent zipapp doubles as the box console. With a fresh honor grade in place:

```bash
python3 -m agent score --report "$MANUAL/honor/report.html"
python3 -m agent score --report "$MANUAL/honor/report.html" --json | head -20
python3 -m agent forensics --report "$MANUAL/honor/report.html"
python3 -m agent watch --once --report "$MANUAL/honor/report.html"
```

Expected: a scorecard through a pipe; `--json` prints the `report.json`
snapshot the CLI reads. `huitz grade` re-runs the pipeline as root (it exits 1
with a `sudo huitz grade` hint otherwise); `huitz watch` wants a TTY.

## 4. Ranked mode, by hand

Two shells: the engine in one, everything else in the other.

**Shell 1 — start the engine:**

```bash
HUITZILOPOCHTLI_DB_PATH="$MANUAL/ranked/engine.db" \
HUITZILOPOCHTLI_PORT=8080 HUITZILOPOCHTLI_ADMIN_TOKEN=devtoken \
HUITZILOPOCHTLI_CHECKIN_INTERVAL_S=5 python3 -m engine.server
```

(mkdir `$MANUAL/ranked` first.) Expected: `huitzilopochtli engine listening on
http://127.0.0.1:8080 (...)` plus a no-TLS warning (fine locally). The default
bind is loopback; set `HUITZILOPOCHTLI_BIND=0.0.0.0` for boxes on a network.

**Shell 2 — compile a ranked scenario.** The base is the honor box; the
`ranked:` block adds the engine and any ranked-only content.

```bash
mkdir -p "$MANUAL/ranked/box"
echo "SECURE_BANNER" > "$MANUAL/ranked/box/banner.txt"
cat > "$MANUAL/ranked/scenario.yaml" <<EOF
scenario:
  name: "ManualRankedTest"
  version: 1
  mode: honor
  hosts: ["localhost"]

checks:
  - id: banner_ok
    type: file_regex
    category: vuln
    display: "Banner present"
    max_points: 10
    collect: {path: $MANUAL/ranked/box/banner.txt, extract: '(SECURE_BANNER)'}
    expect: {equals: "SECURE_BANNER", points: 10}

ranked:
  engine_url: "http://127.0.0.1:8080"
EOF

cd "$REPO"
python3 -c "
import sys
sys.path.insert(0, '.')
from authoring.compile import compile_scenario
from common.crypto import signing
priv, pub = signing.keypair()
compile_scenario('$MANUAL/ranked/scenario.yaml', '$MANUAL/ranked/box', priv,
                 mode='ranked')
"
```

Upload the record and mint an enrollment token:

```bash
curl -s -X POST localhost:8080/admin/scenarios \
  -H "Content-Type: application/json" \
  -H "X-HUITZILOPOCHTLI-Admin-Token: devtoken" \
  -d @"$MANUAL/ranked/box/engine_record.json"; echo
curl -s -X POST localhost:8080/admin/tokens \
  -H "Content-Type: application/json" \
  -H "X-HUITZILOPOCHTLI-Admin-Token: devtoken" \
  -d '{"scenario_name": "ManualRankedTest", "ttl_s": 3600}'
```

Expected: `{"ok": true, ...}`, then a JSON blob with a `"token"` — paste it
below. Write the ranked config and run the agent (it loops until stopped):

```bash
cat > "$MANUAL/ranked/box/agent_config.json" <<EOF
{"mode": "ranked",
 "manifest_path": "$MANUAL/ranked/box/manifest.signed.json",
 "authoring_public_key_path": "$MANUAL/ranked/box/authoring_public_key.b64",
 "rubric_path": null,
 "identity_path": "$MANUAL/ranked/box/identity.json",
 "report_path": "$MANUAL/ranked/box/report.html",
 "checkin_interval_s": 5,
 "enrollment_token": "PASTE_YOUR_TOKEN_HERE"}
EOF
python3 -m agent "$MANUAL/ranked/box/agent_config.json"
```

In a **third** shell, watch the board:

```bash
watch -n 2 'curl -s "localhost:8080/leaderboard?scenario=ManualRankedTest"'
```

Expected: within a few seconds a row with `"total": 10` — enroll → sign →
check-in → score over real HTTP.

**Restart does not re-enroll.** `Ctrl-C` the agent and run the same command
again: it resumes checking in immediately because `identity.json` already
exists. Stop the engine and the agent when done.

## 5. Zipapp packaging

```bash
python3 packaging/build_zipapp.py "$MANUAL/agent.pyz"
rm -f "$MANUAL/honor/report.html"
python3 "$MANUAL/agent.pyz" "$MANUAL/honor/agent_config.json"
grep -o "Total: [0-9]*" "$MANUAL/honor/report.html"
```

Expected: `Total: 10`, identical to step 2 — the `.pyz` bundles `agent/` +
`common/` and nothing else.

## 6. Cleanup

```bash
rm -rf "$MANUAL"
```

## Going further

`tests/README.md` covers the Proxmox tier (live check types, Windows, honor
distribution, ranked) and its env vars; `RANKED_TESTING.md` maps ranked
coverage to suites and lists what is still open; `RANKED_COMPETITION.md` is
the operator side.
