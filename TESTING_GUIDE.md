# Manual verification guide

A hands-on walkthrough to confirm Huitzilopochtli actually works, end to end, on your own machine. Everything here runs locally — no Proxmox, no other machines. Expect the whole thing to take 15-20 minutes, most of it waiting on the automated test suite and the (deliberately slow — see below) crypto.

Run every command from the repo root unless noted otherwise.

## 0. Prerequisites

```bash
cd /home/hna/dev/dawgsec/huitzilopochtli
python3 --version        # 3.10+ recommended; this was built/tested on 3.14
pip install --user pytest
```

That's the only new dependency you need for this guide. (`proxmoxer` and `python-dotenv` are only needed if you later attempt the Proxmox tier in `tests/README.md` — not covered here.)

## 1. Automated suite — fastest confidence check

```bash
pytest
```

Expected: `248 passed` in a few minutes. Most of that time is the vendored Ed25519 implementation's cost (~1.5-2 seconds per sign/verify call — a real, documented, measured property of the exact reference implementation vendored in `common/crypto/ed25519.py`, not a bug; see `tests/README.md` for why).

What this covers:
- **`tests/unit/`** (226 tests, ~40s): schema validation, canonical serialization, all 8 matcher predicates, category-based scoring, Ed25519 sign/verify against real RFC 8032 known-answer vectors, the SLA hysteresis ledger, the adversary oracle's determinism, every `Store` method, all 7 check plugins, the platform layer, and the closed adversary action vocabulary (including a check that no network-egress code exists in it at all).
- **`tests/integration/`** (22 tests, ~3 min): the honor-mode pipeline end-to-end, the ranked-mode loopback (enrollment, restart behavior, crash recovery), admin endpoints, TLS + secret persistence, and zipapp/source-tree equivalence.
- **`tests/proxmox/`**: excluded by default (`pytest -m proxmox` to opt in). One test (`test_local_honor_distribution.py`) passes against real cloned Ubuntu/Fedora VMs; the other (`test_ranked_two_machines.py`) is currently blocked on two infrastructure issues documented in `tests/README.md` — not something to chase in this guide.

If this step passes, you already have strong evidence everything works. Steps 2-4 below let you *see* it happen rather than trust a green checkmark.

## 2. Honor mode, by hand

This mirrors `tests/integration/test_honor_pipeline.py`, but you drive it yourself.

```bash
mkdir -p /tmp/huitzilopochtli-manual/honor
cd /tmp/huitzilopochtli-manual/honor

echo "SECURE_BANNER" > banner.txt

cat > scenario.yaml << 'EOF'
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
    collect:
      path: /tmp/huitzilopochtli-manual/honor/banner.txt
      extract: '(SECURE_BANNER)'
    expect:
      equals: "SECURE_BANNER"
      points: 10
EOF
```

Compile it (there's no CLI wrapper for `authoring/compile.py` — it's a library function — so this is a short inline Python snippet):

```bash
cd /home/hna/dev/dawgsec/huitzilopochtli
python3 -c "
import sys, json
sys.path.insert(0, '.')
from authoring.compile import compile_scenario
from common.crypto import signing

priv, pub = signing.keypair()
outputs = compile_scenario(
    '/tmp/huitzilopochtli-manual/honor/scenario.yaml',
    '/tmp/huitzilopochtli-manual/honor',
    priv,
)
print(json.dumps(outputs, indent=2))
"
```

You should see paths printed for `manifest`, `rubric`, `engine_record`, and `authoring_public_key`. Now write the agent config:

```bash
cat > /tmp/huitzilopochtli-manual/honor/agent_config.json << 'EOF'
{
  "mode": "honor",
  "manifest_path": "/tmp/huitzilopochtli-manual/honor/manifest.signed.json",
  "authoring_public_key_path": "/tmp/huitzilopochtli-manual/honor/authoring_public_key.b64",
  "rubric_path": "/tmp/huitzilopochtli-manual/honor/rubric.json",
  "identity_path": null,
  "report_path": "/tmp/huitzilopochtli-manual/honor/report.html",
  "checkin_interval_s": null
}
EOF
```

Run the agent:

```bash
cd /home/hna/dev/dawgsec/huitzilopochtli
python3 -m agent /tmp/huitzilopochtli-manual/honor/agent_config.json
echo "exit code: $?"
```

Expected: exit code `0`, no output (silence = success). Now look at the report:

```bash
open /tmp/huitzilopochtli-manual/honor/report.html   # macOS
# or: xdg-open /tmp/huitzilopochtli-manual/honor/report.html   # Linux
# or just: grep -o "Total: [0-9]*" /tmp/huitzilopochtli-manual/honor/report.html
```

Expected: `Total: 10`.

**Now break it on purpose** to confirm signature verification actually fails closed:

```bash
python3 -c "
import json
p = '/tmp/huitzilopochtli-manual/honor/manifest.signed.json'
m = json.load(open(p))
m['scenario_version'] = 999  # tamper without re-signing
json.dump(m, open(p, 'w'))
"
rm /tmp/huitzilopochtli-manual/honor/report.html
python3 -m agent /tmp/huitzilopochtli-manual/honor/agent_config.json
echo "exit code: $?"
```

Expected: **non-zero exit code**, an error mentioning `FAILED signature verification`, and `report.html` is **not** recreated. This confirms the agent genuinely refuses to run on a tampered manifest rather than silently trusting it.

**Re-arm** (recompile fresh first, since the manifest above is now permanently tampered):

```bash
python3 -c "
import sys, json
sys.path.insert(0, '.')
from authoring.compile import compile_scenario
from common.crypto import signing
priv, pub = signing.keypair()
compile_scenario('/tmp/huitzilopochtli-manual/honor/scenario.yaml', '/tmp/huitzilopochtli-manual/honor', priv)
"
python3 -m agent /tmp/huitzilopochtli-manual/honor/agent_config.json
python3 packaging/rearm.py --config /tmp/huitzilopochtli-manual/honor/agent_config.json
ls /tmp/huitzilopochtli-manual/honor/report.html 2>&1   # should say "No such file"
```

Expected: `rearm.py` prints `removed cached report: ...` and the report file is gone.

## 3. Ranked mode, by hand

This mirrors `tests/integration/test_ranked_loopback.py` and `test_admin_endpoints.py`. You'll need two terminals (or background the engine).

**Terminal 1 — start the engine:**

```bash
cd /home/hna/dev/dawgsec/huitzilopochtli
mkdir -p /tmp/huitzilopochtli-manual/ranked
HUITZILOPOCHTLI_DB_PATH=/tmp/huitzilopochtli-manual/ranked/engine.db \
HUITZILOPOCHTLI_PORT=8080 \
HUITZILOPOCHTLI_ADMIN_TOKEN=devtoken \
python3 -m engine.server
```

Expected output: `huitzilopochtli engine listening on http://0.0.0.0:8080 (db=/tmp/huitzilopochtli-manual/ranked/engine.db)` plus a warning about running without TLS (expected/fine for local testing).

**Terminal 2 — everything else:**

```bash
curl -s localhost:8080/health
```
Expected: `{"ok": true}`.

Compile a ranked-mode scenario:

```bash
mkdir -p /tmp/huitzilopochtli-manual/ranked/box
echo "SECURE_BANNER" > /tmp/huitzilopochtli-manual/ranked/box/banner.txt

cat > /tmp/huitzilopochtli-manual/ranked/scenario.yaml << 'EOF'
scenario:
  name: "ManualRankedTest"
  version: 1
  mode: ranked
  engine_url: "http://127.0.0.1:8080"
  hosts: ["localhost"]

checks:
  - id: banner_ok
    type: file_regex
    category: vuln
    display: "Banner present"
    max_points: 10
    collect:
      path: /tmp/huitzilopochtli-manual/ranked/box/banner.txt
      extract: '(SECURE_BANNER)'
    expect:
      equals: "SECURE_BANNER"
      points: 10
EOF

cd /home/hna/dev/dawgsec/huitzilopochtli
python3 -c "
import sys, json
sys.path.insert(0, '.')
from authoring.compile import compile_scenario
from common.crypto import signing
priv, pub = signing.keypair()
outputs = compile_scenario(
    '/tmp/huitzilopochtli-manual/ranked/scenario.yaml',
    '/tmp/huitzilopochtli-manual/ranked/box',
    priv,
)
print(json.dumps(outputs, indent=2))
"
```

Upload the scenario to the engine and mint an enrollment token:

```bash
curl -s -X POST localhost:8080/admin/scenarios \
  -H "Content-Type: application/json" \
  -H "X-HUITZILOPOCHTLI-Admin-Token: devtoken" \
  -d @/tmp/huitzilopochtli-manual/ranked/box/engine_record.json

echo   # newline
curl -s -X POST localhost:8080/admin/tokens \
  -H "Content-Type: application/json" \
  -H "X-HUITZILOPOCHTLI-Admin-Token: devtoken" \
  -d '{"scenario_name": "ManualRankedTest", "ttl_s": 3600}'
```

Expected: `{"ok": true, "scenario_name": "ManualRankedTest"}` then a JSON blob with a `"token"` field — **copy that token value** for the next step.

Write the ranked agent config, pasting your token in:

```bash
cat > /tmp/huitzilopochtli-manual/ranked/box/agent_config.json << EOF
{
  "mode": "ranked",
  "manifest_path": "/tmp/huitzilopochtli-manual/ranked/box/manifest.signed.json",
  "authoring_public_key_path": "/tmp/huitzilopochtli-manual/ranked/box/authoring_public_key.b64",
  "rubric_path": null,
  "identity_path": "/tmp/huitzilopochtli-manual/ranked/box/identity.json",
  "report_path": "/tmp/huitzilopochtli-manual/ranked/box/report.html",
  "checkin_interval_s": 5,
  "enrollment_token": "PASTE_YOUR_TOKEN_HERE"
}
EOF
```

Run the agent (it loops forever in ranked mode — that's expected, leave it running):

```bash
cd /home/hna/dev/dawgsec/huitzilopochtli
python3 -m agent /tmp/huitzilopochtli-manual/ranked/box/agent_config.json
```

In a **third terminal**, watch the leaderboard update:

```bash
watch -n 2 'curl -s "localhost:8080/leaderboard?scenario=ManualRankedTest"'
```

Expected: within ~10-15 seconds, a row appears with `"total": 10`. This confirms enroll → sign → check-in → score all worked over real HTTP.

**Confirm restart doesn't re-enroll**: `Ctrl-C` the agent (terminal 2), then run the exact same `python3 -m agent ...` command again. It should immediately resume checking in (no enrollment error, no crash) — because `identity.json` already exists, so the agent skips straight to the check-in loop per §9.6.

When done, stop the engine (`Ctrl-C` in terminal 1) and the agent (`Ctrl-C`).

## 4. Zipapp packaging

Confirm the actual distributable artifact behaves identically to running from source:

```bash
cd /home/hna/dev/dawgsec/huitzilopochtli
python3 packaging/build_zipapp.py /tmp/huitzilopochtli-manual/agent.pyz

# rerun the honor-mode config from step 2 through the real .pyz
rm -f /tmp/huitzilopochtli-manual/honor/report.html
python3 /tmp/huitzilopochtli-manual/agent.pyz /tmp/huitzilopochtli-manual/honor/agent_config.json
grep -o "Total: [0-9]*" /tmp/huitzilopochtli-manual/honor/report.html
```

Expected: `Total: 10`, identical to step 2 — proving the zipapp genuinely bundles `agent/`+`common/` correctly and nothing outside those two packages leaked in or was missed.

## 5. Cleanup

```bash
rm -rf /tmp/huitzilopochtli-manual
```

(Nothing was written outside `/tmp` and the repo's own `dist/`/`.pytest_cache` — both already gitignored.)

## Going further

`tests/README.md` documents the `tests/proxmox/` tier — real cloned VMs on Proxmox. `test_local_honor_distribution.py` passes there against real Ubuntu/Fedora clones; `test_ranked_two_machines.py` is currently blocked on two infrastructure issues (a Proxmox template machine-id collision, and Fedora's guest-agent SELinux confinement blocking outbound network) that are documented there in detail, with options laid out for fixing them. Not necessary for the verification above — only relevant if you want to push further into real-VM/real-network testing.
