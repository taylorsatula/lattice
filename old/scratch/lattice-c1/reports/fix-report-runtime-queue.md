# fix-report-runtime-queue — executor report, row `w7m6` (QUEUE, H)

## Files and functions changed

`lattice/runtime.py` only (out-of-scope list respected; no other file touched):

- `queue_domain_resolution` — added FIFO size cap (`_UNRESOLVED_DOMAINS_MAX = 512`,
  oldest entry evicted when full) and a no-TTL-refresh guard: a repeat POST of an
  already-queued domain keeps its original enqueue time, so an attacker cannot keep
  one domain alive by re-enqueueing it. Malformed-domain rejection unchanged.
- `_resolve_pending_senders` — per tick: (1) expire entries past
  `_UNRESOLVED_DOMAINS_TTL_SECONDS = 900.0`; (2) attempt only a bounded batch of the
  oldest `_UNRESOLVED_DOMAINS_BATCH = 5` entries; (3) discard each attempted domain in
  a `finally` — on success AND failure — so a permanently-failing domain leaves after
  one attempt and is never re-resolved every 30 s forever. Existing per-item exception
  isolation (ResolutionError → DEBUG, unexpected → WARNING, `continue` semantics)
  preserved.
- `_unresolved_domains` + initialization (~256) — `set[str]` → `dict[str, datetime]`
  (domain → enqueue time; dict insertion order is FIFO, which both the eviction and the
  oldest-first batch selection rely on).
- Three module-level constants added immediately above `class RuntimeCoordinator`
  (~lines 153–158) — they parameterize exactly the named queue and its initialization.

Insertions/deletions: ~75 inserted, ~30 deleted across the four hunks (no other lines
touched; no debug prints; ruff and mypy --strict clean).

## Extensions beyond the enumerated set

None outside `runtime.py`. The module constants are the only additions outside the
three named symbols; they are the parameterization of the named set's initialization.

## Sibling pattern mirrored

`lattice/runtime.py:_run_outbound_delivery` — claims a bounded batch
(`claim_for_delivery(owner, limit=5)`), never an unbounded scan. The resolution queue
now does the same: bounded oldest-first batch of 5 per 30 s tick.

## What I did NOT do (owned by the sibling executor on `api.py`)

Per HOW: no signature verification before enqueue (cold senders are unverifiable by
design) and no IP-keyed/global rate check ahead of queueing — that is the sibling's
change in `api.py`. The queue is now bounded and self-draining, so it is safe without
that change and strictly better with it.

## Verification — EXECUTED

Probe: a throwaway script (written to `/tmp`, deleted after the run; no residue in the
tree) constructed a **real** `RuntimeCoordinator` — real generated root/op keys,
root-signed well-known document, real sqlite durable (migrated) + cache DBs, real
`Config`, real `OutboundTransport`/`WellKnownResolver`, real DNS over urllib3. The only
injection was the repo's own designed `Clock` seam (constructor parameter), used to age
entries past the 900 s TTL without sleeping; the TTL code path executed is production
code. No mocks, no test files, no offline DBs.

Hostile input: 600 distinct attacker-chosen `.invalid` domains (RFC 2606 — guaranteed
NXDOMAIN, i.e. genuine end-to-end resolution failure through `getaddrinfo` →
`TransportError` → `ResolutionError`), then a 5000-domain sustained flood, plus
malformed inputs (`evil.example:8080`, `https://evil.example`, whitespace).

Command: `timeout 180 .venv/bin/python /tmp/lattice_probe_queue.py` (script removed after).

Observed (all assertions passed, exit 0):

- `[1]` 600 hostile domains queued → queue size **512** (cap enforced; 88 oldest evicted)
- `[2]` malformed domains rejected; queue unchanged at 512
- `[3]` repeat POST does not refresh TTL (enqueue timestamp unchanged)
- `[4.1–4.3]` each cycle: 512→507→502→497 — exactly **5 domains of work per cycle**
- `[5]` first 15 permanently-failing domains discarded after **one** attempt each
  (old code retained them forever, re-resolving every 30 s)
- `[6]` TTL expiry: 497 aged-out domains purged to size **0** in one cycle
- `[7]` post-purge queueing still works (fresh domains queued, resolved, discarded)
- `[8]` 5000-domain sustained flood: queue held at **512**

Also: `.venv/bin/ruff check lattice/` → All checks passed; `.venv/bin/mypy --strict
lattice/` → no issues in 30 source files; `.venv/bin/python -m py_compile
lattice/runtime.py` → OK. No servers started; nothing to kill. Tree was already dirty
with the untracked rewrite; I added no files and committed nothing.

## Found but not touched

None new. The pre-existing dirty tree (untracked rewrite, deletions, `uv.lock`) is
orchestrator territory.
