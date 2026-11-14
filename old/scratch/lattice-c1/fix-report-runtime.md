# Fix report — lattice/runtime.py (st0g, hna1, zmks)

File written: `lattice/runtime.py` (only file touched; ~+106/−47 lines, line-granular,
re-indented lines counted). Not committed.

## Functions changed

1. **`_send_outbound_message`** (success/audit reconciliation region) — `record_success`
   return value now drives the audit. On a valid 202 receipt: if the terminal write landed
   (`mark_terminal` matched), audit `OUTBOUND_DELIVERED`; if it matched nothing (the 60 s
   expiry sweep already flipped the row to `expired`), the terminal writer wins and the audit
   is `OUTBOUND_FAILED` with reason `"row already terminal (expired) before delivered write"`
   via the existing `_audit_outbound_failed` helper. `mark_terminal`'s guard untouched.
   `_circuit_record_success` still fires in both branches (peer returned a valid custody
   receipt — node health is independent of the lease state).
2. **`_circuit_record_success` / `_circuit_record_failure`** — write bodies wrapped in
   `with self._cache_repo.conn:` so each commits (or rolls back) within its own boundary;
   docstrings note best-effort durability (disposable cache DB). No bare `conn.commit()`.
3. **`stop`** — executor drains bounded by the `timeout` argument: shared
   `time.monotonic()` deadline; each drain runs `shutdown(wait=True, cancel_futures=False)`
   on a helper thread joined with the remaining budget; budget exhaustion cancels queued
   futures (leased rows recover at-least-once via lease expiry). Drain-before-persist
   ordering preserved; `_persist_rate_limits`, transport/webhook close still follow.

Exemplar mirrored: `with self._conn:` transaction idiom in
`lattice/storage/repositories.py:mark_terminal`/`release_lease` (via `BaseRepository.conn`);
audit helpers `_audit_outbound_delivered`/`_audit_outbound_failed` in `runtime.py`.

## Verification — EXECUTED

Probe script (temp, deleted): real SQLite durable+cache DBs (`migrate`,
`initialize_cache_db`), real self-signed-CA TLS HTTPS server on 127.0.0.1 (private-mode
NetworkPolicy, `private_cidrs=["127.0.0.0/8"]`), real `OutboundTransport`,
three real `RuntimeCoordinator` instances. No mocks/fakes.

- **(a) hna1** — `_circuit_record_failure("node-a")` then a hostile unrelated cache block
  that raises inside `with conn:` and rolls back. Fixed: `in_transaction=False`, row
  visible to a second connection, **survived the unrelated rollback**, success reset visible.
  Negative control (pre-fix code restored temporarily): `in_transaction=True`, row invisible
  to 2nd connection, discarded by the rollback.
- **(b) st0g** — two real outbound rows claimed; hostile input: row `msg-expired` flipped to
  `status='expired', lease_owner=NULL` (post-sweep state) before delivery; both then delivered
  through the real TLS transport (202 receipts). Fixed: expired row → status `'expired'` +
  audit `['OUTBOUND_FAILED']` (agree); live row → `'delivered'` + `['OUTBOUND_DELIVERED']`.
  Negative control: expired row got `['OUTBOUND_DELIVERED']` while status stayed `'expired'`
  — durable/audit disagreed.
- **(c) zmks** — started runtime, 30 s task submitted to `_delivery_executor`, a seeded rate
  bucket pending persist; `stop(timeout=2.0)`. Fixed: returned in **2.01 s**, rate bucket
  persisted (rows=1). Negative control: took **29.50 s** (unbounded drain).

Gates (all after final code restored): `py_compile` ok; `.venv/bin/ruff check lattice/` —
All checks passed; `.venv/bin/mypy --strict lattice/` — no issues (30 files);
`.venv/bin/python -m pytest` — **163 passed, 1 skipped**, exit 0.

## Found, not touched

- `lattice/runtime.py` is untracked in git (`??`); many sibling deletions/modifications in
  the tree are other agents' work — left alone.
- The abandoned-still-running drain task keeps a non-daemon executor thread alive after
  `stop()` returns; interpreter exit can linger until it finishes (atexit join). Rate-limit
  persist and transport close still happen inside the bound, which is what zmks's WHY
  requires; noting for the orchestrator in case a daemon-thread change is wanted elsewhere.
