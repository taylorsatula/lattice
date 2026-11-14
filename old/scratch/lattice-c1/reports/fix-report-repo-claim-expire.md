# Fix report — lattice/storage/repositories.py (rows CLAIM ym88, EXPIRE st0g repo half)

## Changed
File: `lattice/storage/repositories.py` (only file written)

- `OutboundMessageRepository.claim_pending` (+3/−6 net): UPDATE now ends `RETURNING *`; the rows
  returned are exactly the rows this UPDATE claimed (fetched from the RETURNING cursor). Removed the
  re-query `WHERE lease_owner = ? AND lease_expires_at = ?` that returned any prior same-owner
  same-second claim's rows with no LIMIT.
- `InboundMessageRepository.claim_for_webhook` (+2/−7 net): identical repair, `RETURNING *` on the
  UPDATE; removed the `webhook_lease_owner`/`webhook_lease_expires_at` re-query.
- `OutboundMessageRepository.expire_messages` (+2/−2 net): WHERE now adds
  `AND (lease_owner IS NULL OR lease_expires_at <= ?)` (ts bound twice). A row with a live lease is
  no longer terminal-expired underneath the delivering worker; `leased` rows with dead leases and
  unleased past-TTL pending rows still expire. `mark_terminal`'s `status='leased' AND lease_owner`
  guard untouched (as required).

Same-hazard extension: none needed — both claim functions in scope had the identical re-query
defect and both are the enumerated set.

## Exemplar mirrored
- `OutboundMessageRepository.expire_messages` in the same file — the pre-existing
  `RETURNING message_id` + `cursor.fetchall()` inside `with self._conn:` idiom (the file already
  depends on SQLite RETURNING; venv SQLite is 3.50.4, pyproject pins no sqlite floor but requires
  Python >=3.11 whose bundled sqlite3 is >=3.35, so RETURNING is safe).

## Verification — EXECUTED (repo venv `.venv/bin/python`, real SQLite via repo's own `migrate`)
Probe script `/tmp/lattice_c1_probe.py` (deleted after run; temp db dirs rmtree'd). Hostile input:
frozen same-second timestamps, same owner, overlapping claims, past-TTL rows with live leases.

(a) CLAIM: 4 pending rows; `claim_pending("worker-1", NOW, limit=2)` twice in the same second:
    first=['m-0','m-1'], second=['m-2','m-3'] — disjoint, each exactly 2; a third claim returned [].
    Same for `claim_for_webhook`: w1=['i-0','i-1'], w2=['i-2','i-3'], w3=[]. Subselect priority
    still governs selection: limit=1 over {low, urgent} claims only the urgent row.
(b) EXPIRE: row claimed at T (TTL T+5s, lease to T+5min); `expire_messages(T+10s)` returns []
    and the row stays status='leased', owner='deliverer'; the worker's `mark_terminal(...,
    'delivered')` then succeeds (rowcount 1, final status 'delivered'). An unleased past-TTL
    pending row and a dead-lease leased row both expire: ['leased-dead','pend-pastttl'].

Gates: `.venv/bin/ruff check lattice/` — All checks passed; `.venv/bin/mypy --strict lattice/` —
no issues in 30 files; `.venv/bin/python -m pytest -q` — 164 passed, 1 skipped, 0 failed.
`py_compile` on the touched file: OK.

## Found but not touched
- Pre-existing dirty working tree (many unrelated deletions/modifications, e.g. `lattice/client.py`
  deleted, `docs/*` modified) — left as found; not mine to clean.
- runtime.py EXPIRE/audit half is owed to the sibling per the coordination note; repo half now
  satisfies the target contract's durable-status side.
