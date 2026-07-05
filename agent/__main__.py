"""Agent entrypoint. See architecture.md §15. PHASE 2 (integration).

Wires: config -> collector -> (honor: evaluator+reporter |
                                ranked: transport+reporter+adversary executor)

Honor-mode run: load signed manifest -> verify authoring signature -> run all
checks concurrently -> assemble evidence -> load local rubric ->
common.evaluate(evidence, rubric, no-op clock) -> write HTML. No network, no
time axis, no adversary.

Ranked check-in loop: every checkin_interval_s -> collect evidence ->
assemble+sign bundle (seq++) -> POST /checkin (TLS) -> on success apply score
to cache/report and execute directives; on network failure queue bundle and
retry next cycle.
"""


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
