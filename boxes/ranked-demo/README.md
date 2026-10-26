# Ranked demo competition box

Minimal live-test scenario for the v1.1 competition surface. It is not a
shipped practice box; it exists to exercise scored services, a live adversary,
and the per-player run clock.

- `scenario.yaml` — hardening check + web/SSH services.
- `scenario-r2.yaml` — same plus `kill-demo-web`, which stops the demo web
  service in its 20–40s window and forces `svc_web` DOWN.

Compile with `authoring.compile.compile_scenario`; the generated
`artifacts*/` directories contain the authoring private key and are ignored by
git. Install the agent with `boxbuilder install --competition` or the manual
layout described in `RANKED_COMPETITION.md`.

The demo web service is:

```bash
mkdir -p /opt/huitz-demo-web
echo ok > /opt/huitz-demo-web/health
python3 -m http.server 8081 --directory /opt/huitz-demo-web
```
