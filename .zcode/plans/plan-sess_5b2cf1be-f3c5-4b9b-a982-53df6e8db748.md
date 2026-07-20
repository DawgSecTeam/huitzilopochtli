## Summary

I audited the codebase (engine, agent, common/authoring) and **verified 9 real bugs** by reading the offending source. They span scoring correctness, concurrency, input validation, crash-loops, and a hang. Below are the fixes, grouped by area, plus regression tests for each.

---

## Verified Bugs & Fixes

### Scoring correctness (common/)

**BUG-E1 — VULN awards full points for ERROR/TIMEOUT evidence** *(HIGH)* — `common/evaluator.py:54,58,70-72`
The `if not evidence_ok` guard only covers PENALTY/PROHIBITED. For VULN, the matcher still runs against `ev.raw` and the `else` branch awards points whenever the matcher passes — directly contradicting the module docstring ("Missing/ERROR/TIMEOUT evidence is scored as 'not satisfied' for VULN"). A collector fault that leaves a matching value in `raw` inflates the score.
**Fix:** VULN must also treat non-OK evidence as not-satisfied. Restructure so `not evidence_ok` forces `awarded=0` and a clear reason for *all* categories, while still preserving the existing PENALTY/PROHIBITED zero-on-undetermined behavior. Missing-evidence (`ev is None`) still flows the matcher against `raw={}` and scores 0 (no behavior change — keeps `test_missing_evidence_calls_matcher_with_empty_raw_dict` green).

**BUG-E2 — matchers crash on `None`/wrong-type raw values** *(MEDIUM)* — `common/matchers.py:217,230,244,248`
`user_absent`/`user_present` do `username not in users` with no None guard; `{"users": null}` → `TypeError`. `group_members_subset_of` does `group_members.get(group)`; a list value → `AttributeError`, `None` members → `TypeError`. Since `evaluate_matcher` has no try/except, one malformed field aborts the entire scoring pass.
**Fix:** Add explicit type guards (return `False, "..."` like the sibling `contains` predicate does). Non-dict `group_members` and non-iterable `users`/`members` become clean not-matched results instead of exceptions.

**BUG-A4 — ReDoS in regex matcher** *(MEDIUM)* — `common/matchers.py:183` and `agent/checks/file_regex.py:38`
`re.search` with no timeout/cap. A naive author regex against large/attacker-influenced input hangs the scoring/check thread.
**Fix:** Use `re.compile(pattern).search(str(actual))` wrapped with `re.search`/`re.compile` timeout (Python 3.11+ supports `timeout=`; we're on 3.14). Cap input length defensively. On timeout, return `(False, "regex timed out")`.

### Engine concurrency & validation (engine/)

**BUG-E3 — Store readers skip the lock; SLA read-modify-write is non-atomic** *(HIGH)* — `engine/store.py:137,239,311,357,382,418,437` + `engine/sla.py:33-80`
Under `ThreadingHTTPServer`, readers (`get_box`, `get_sla_state`, `get_token`, `get_issued_event_ids`, `get_scores`, `get_scenario`, `get_meta`) call `self._conn.execute` without holding `self._lock`, while writers hold it — on a single shared `check_same_thread=False` connection. This both raises `OperationalError: database is locked` and enables the SLA lost-update: `update_sla` does `get_sla_state` → mutate → `save_sla_state` across three unlocked calls, so two concurrent check-ins (different seqs both pass the seq guard) both read the same counters and the second write clobbers the first — corrupting SLA accrual and the persisted `final_total`.
**Fix (minimal, robust):** (a) make every Store reader acquire `self._lock` around its execute/fetch, restoring single-writer/multi-reader serial safety on the shared connection; (b) add `Store.update_sla_atomic(...)` that performs the SLA read→mutate→write inside one lock hold (single SQL transaction with an atomic accrual expression, or read+compute+write under the lock) and have `sla.update_sla` call it. This closes the RMW race without changing `sla.update_sla`'s public signature.

**BUG-E4 — Leaderboard ties are non-deterministic** *(MEDIUM)* — `engine/store.py:386`
`ORDER BY total DESC` with no tiebreak. Equal totals (common when boxes pass identical rubrics) return in unspecified order across runs.
**Fix:** Add a deterministic secondary sort: `ORDER BY total DESC, updated_at ASC, box_id ASC` (earliest score wins ties, then stable by id).

**BUG-E5 — `/admin/scenarios` stores a rubric without validation; `/checkin` then 500s** *(MEDIUM)* — `engine/server.py:265-283,226`
The upload handler stores `body["rubric"]` verbatim and never calls `validate_rubric`. Then `_rubric_from_dict` at `server.py:226` (outside the `try/except CheckinError`) raises `KeyError`/`ValueError`/`TypeError` on a malformed stored rubric → unhandled 500 with traceback, and every enrolled box is permanently stuck.
**Fix:** (a) Call `validate_rubric(rubric)` in `_handle_admin_upload_scenario` and reject with 400 + the error list if invalid; (b) defensively move the `_rubric_from_dict` call inside the existing `try/except` and map unexpected errors to a clean 400/500 so a bad stored rubric can't take down `/checkin` with a raw 500.

### Agent robustness (agent/)

**BUG-A1 — Permanent rejection of the *current* bundle crashes the ranked loop into a crash-loop** *(HIGH)* — `agent/transport.py:219-225`
The queued-bundle flush path catches `Exception` (drops poison bundles, keeps going). But the *new*-bundle send path only catches `_NetworkFailure`; a 409 replay / 403 raises a bare `Exception`, escapes `client.checkin`, and kills `_run_ranked`'s `while True` (no try/except in `__main__.py:242`). Because `last_seq` was already persisted before send, the same seq is regenerated on restart → 409 again → permanent crash-loop.
**Fix:** Catch `Exception` on the new-bundle send path with the same "log + drop" policy as queued bundles: print a WARNING, drop the rejected bundle (it can never succeed), and return `None` so the loop advances its cadence and the agent keeps running. (Crucially, do *not* re-queue it — that would crash-loop.)

**BUG-A2 — Collector timeout doesn't actually stop a hung check; `shutdown(wait=True)` hangs `run_all`** *(MEDIUM)* — `agent/collector.py:39-88`
`future.result(timeout=...)` records TIMEOUT correctly, but `ThreadPoolExecutor.__exit__` calls `shutdown(wait=True)`, which blocks until the runaway worker thread finishes — converting the documented "a hung check yields TIMEOUT and never stalls the run" guarantee into a hard hang (triggered by BUG-A4's ReDoS, a stuck socket, etc.).
**Fix:** Don't use the `with` block's blocking shutdown. Submit work, collect results with timeouts, then call `executor.shutdown(wait=False, cancel_futures=True)` (cancels not-yet-started futures; can't kill a running thread but stops *new* ones from blocking exit). This restores the timeout guarantee for the common case and avoids the `__exit__` hang.

**BUG-A3 — `flush_firewall` nft fallback defeated by iptables exception** *(LOW)* — `agent/adversary/actions.py:59-74`
If `shutil.which("iptables")` is truthy but `subprocess.run(["iptables","-F"])` raises (PermissionError / binary removed in a TOCTOU), the bare `except Exception` swallows it and returns without trying `nft`, defeating the documented fallback. (`check=False` doesn't prevent `OSError`/`PermissionError` from `run` itself.)
**Fix:** Move the try/except inside each tool's block (or try iptables, then unconditionally try nft if iptables didn't succeed) so an iptables failure falls through to the nft attempt rather than short-circuiting.

---

## Testing plan
After each fix, run `pytest` and add a focused regression test:
- **E1**: `test_vuln_awards_zero_on_error_evidence` / `_on_timeout_evidence` (status=ERROR but raw matches → 0 points, passed=False, reason notes unavailable evidence).
- **E2**: `test_user_absent_present_users_none` / `test_group_members_*_non_dict` / `_members_none` (return not-matched, no raise).
- **A4**: `test_regex_redos_times_out` (catastrophic pattern + adversarial input returns within a few seconds, not 120s).
- **E3**: `test_concurrent_checkins_dont_corrupt_sla` (two threads, distinct seqs, overlapping check-ins → accrued total reflects both) + `test_store_readers_hold_lock` style concurrency smoke.
- **E4**: `test_get_scores_tiebreak_is_deterministic` (equal totals ordered by updated_at then box_id).
- **E5**: `test_admin_upload_rejects_invalid_rubric` (400 + errors) + `test_checkin_bad_stored_rubric_does_not_500`.
- **A1**: `test_permanent_rejection_of_new_bundle_returns_none` (monkeypatch `_send_canonical` to raise a 409 Exception → `checkin` returns None, no raise).
- **A2**: `test_run_all_does_not_hang_on_runaway_check` (a check that sleeps beyond timeout → run_all returns promptly with TIMEOUT evidence).
- **A3**: `test_flush_firewall_falls_back_to_nft_on_iptables_error` (iptables present but raises → nft invoked).

I'll run the full suite after each cluster of fixes and keep iterating until green. The 3 pre-existing ranked_loopback agent-loop hangs (documented in commit `d0a086a` as unrelated to pure-Python Ed25519 speed) will be left as-is unless a fix here resolves them.

## Scope & notes
- No changes to frozen signatures (`Store` methods, `evaluate`, `evaluate_matcher`, `run_all`, `checkin`). The new `Store.update_sla_atomic` is an internal helper; `sla.update_sla`'s public signature is unchanged.
- All changes are pure stdlib (the zipapp constraint in `agent/` + `common/`).