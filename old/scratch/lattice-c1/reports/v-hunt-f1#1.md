# v-hunt-f1#1 — PRIMED VERIFIER of hunt-f1#1 (gossip rate-limit keying)

Claim under test: `scratch/lattice-c1/reports/hunt-f1.md` finding 1, reported tier **M**.

Verdict: **ADJUSTED (CONFIRMED mechanism, severity raised M → H)**.

Reachability kind: **PRODUCTION** (public fixed route `POST /lattice/v1/gossip`, invariant 3;
default bind `127.0.0.1:1113` behind the shipped Nginx config).

## Frame re-derived from source (not from the claim)

- `api.py:264` — `peer_id = sender_node_id or _peer_ip(request)`; `sender_node_id =
  runtime.verify_gossip_sender_card(cards[0])` (api.py:260-263). This is the only call site of
  `allow_gossip` (rg, below).
- `runtime.py:536-571` `verify_gossip_sender_card` derives the root key from the card itself
  (`model.root_public_key`), requires `derive_node_id(root_key) == model.node_id`, builds
  `RootIdentity(node_id=model.node_id, public_key=root_key)` and calls `cert.verify(root_identity)`.
  No `get_pin`, no `_root_identity_for_node`, no pinned/known-root lookup is consulted anywhere on
  this path (rg section B). Verification is self-consistent, exactly as the docstring states.
- `rate_limit.py:91-108` `_bucket(peer_id, kind)`: on miss creates a new `TokenBucket` and inserts
  it into `self._buckets`; nothing ever removes an entry (`rg` section A shows no delete/prune).
  `capacity = gossip_per_minute/60 * 60 * 1.0 = gossip_per_minute`. Default
  `DEFAULT_GOSSIP_PER_MINUTE = 30` (config.py:22), so capacity 30, confirmed.
- `runtime.py:497-513` `_persist_rate_limits` writes every bucket to the `rate_buckets` table on
  `stop()`; `runtime.py:402-409` restores on `start()`. `cache_schema.sql:65` `rate_buckets` has no
  TTL column and no prune statement exists (rg section A).
- `deploy/lattice.nginx.conf` has **no** `limit_req`/`limit_conn` (rg section C) — only
  `limit_except` method restrictions. So within the shipped tree the application limiter is the
  only request-rate enforcement on gossip, as the claim states.

## Sub-claims, each resolved

1. **Self-attested card accepted; unlimited fresh identities.** CONFIRMED. Minting is trivial:
   `PeerCard` (models.py:146) places no constraint the attacker cannot self-satisfy; the cert chain
   is checked only against the card's own root. Trigger: any network peer POSTs with a freshly
   minted card. Frequency: per hostile request.
2. **Each distinct identity gets a brand-new bucket.** CONFIRMED (`_bucket` miss path).
3. **Capacity 30 default.** CONFIRMED (arithmetic above).
4. **IP fallback never reached.** CONFIRMED when a valid card is present.
5. **Unbounded `_buckets` growth, persisted across restarts, never evicted.** CONFIRMED. This is
   the basis of the severity correction (below).
6. **Victim-bucket drain by a third party.** CONFIRMED mechanism, with one refuted directional
   detail: a replayed genuine peer card keys the bucket on the victim's node_id, so the attacker
   consumes the victim's tokens; the victim's next genuine round receives 429, and it is the
   *victim* (running `_send_gossip_batch`, runtime.py:1115-1116) that calls
   `_circuit_record_failure(node_id)` **against the receiver (us)**, not "against the victim".
   The net cross-peer effect the claim derives — the victim's circuit toward us opens after
   `_CB_THRESHOLD`, its gossip to us stops, our `record_observation` (runtime.py:1119 →
   topology.py:352) of the victim stalls, retarding its maturity — is real and traced.

## Severity correction — M → H, with trace

The claim bundles three outcomes and prices the bundle at M. Outcome (b) is a standalone
**unbounded resource exhaustion reachable by a network peer**, which the pinned scale prices at H:

- `rate_limit.py:88` `self._buckets: dict[...] = {}` is populated on every novel key and never
  evicted; `_persist_rate_limits` (runtime.py:497) mirrors that population into
  `rate_buckets` on every graceful stop, and `load_rate_buckets` (repositories.py:624) reloads it.
  No eviction, no TTL, no row cap, no prune statement exists anywhere in the tree (rg section A).
- Key material is free to the attacker: a fresh Ed25519 identity costs one keygen and one signed
  POST (mechanism 1), so both memory and the persisted `rate_buckets` table grow without bound.
- The endpoint is network-reachable; the shipped edge config imposes no rate or connection cap.

Outcomes (a) quota bypass and (c) cross-peer drain are the M-tier components the claim priced; the
H basis is (b). Corrected tier: **H**.

Note the scale caveat: if a reviewer judges bucket growth a slow leak rather than a fast DoS, the
residual would be M for the quota/cross-peer components — but the pinned H clause ("unbounded
resource exhaustion reachable by a network peer") is met literally, and the leak is the reason to
stop and fix.

## Frequency correction — DEMONSTRATED, unchanged, re-grounded

Kept DEMONSTRATED. Grounding: the trigger population is the hostile-peer population of one public
route; cadence is one HTTP request per novel key (per fresh card, or see added mechanism per
spoofed XFF), on a federation endpoint that is continuously visible to the internet. Victim-drain
sub-trigger is per targeted peer while its cert window is valid. Not latent.

## Added mechanisms / earlier failure site (same trace)

**A. `_peer_ip` trusts a client-controlled `X-Forwarded-For` prefix (earlier failure site,
api.py:110-116).** `_peer_ip` returns `forwarded.split(",")[0]`. The shipped Nginx config sets
`X-Forwarded-For $proxy_add_x_forwarded_for`, i.e. `"<client-supplied XFF>, $remote_addr"`, so the
**first** element is attacker-controlled. Consequence: the "transport-level fallback" is not a
fallback at all. A request with an **invalid** card (no keygen at all) gets a caller-chosen
`peer_id` string, so (i) the rate limit is bypassed without any cryptography, and (ii) the
unbounded bucket population can be grown with arbitrary keys. This is an earlier site on the same
trace and a distinct fix target (`_peer_ip`).

## Fix-direction constraints

- Re-keying on IP is insufficient: any repair must take the client address from a
  proxy-controlled header (`X-Real-IP`, or the last XFF hop) rather than a client-writable prefix.
- Identity-keyed quotas are inherently unbounded when identities are free. A repair must add
  bucket eviction/expiry and a **global** aggregate ceiling (in-memory and a prune/retention rule
  for `rate_buckets`), not just a bigger per-identity bucket.
- The victim-drain must be answered structurally: a third party must not be able to spend another
  node's quota. Separate the quota key (transport) from card identity, or make self-asserted
  identity usable only for accounting, never for quota deduction.
- Escaping structure-breaking (validating the card) is not the fix: the injection is that identity
  is self-asserted and unbounded, so any card-validating repair that keeps per-identity quotas
  reproduces the defect.
- A protocol-level decision is involved (`docs/PROTOCOL.md` §5.2 prescribes node-ID keying), so the
  repair crosses the spec/implementation boundary; the code is a faithful implementation of a
  trust assumption that does not hold.

## Checked and clean

- `verify_gossip_sender_card` correctly rejects malformed cards, node-id/root mismatches, bad cert
  signatures, expired certs, and bad card signatures (runtime.py:551-571) — the gap is the trust of
  a *valid, freely-mintable* identity, not a validation bug.
- Message-route rate limiting is **not** affected: `allow_message(from_node_id)` (api.py:335) keys
  on a signature-verified resolved node id; cold senders return 503 before the limiter. The defect
  is specific to the gossip route's self-attested card.
- Body-size guard `require_content_length(MAX_GOSSIP_BODY_BYTES)` and batch cap 32 are enforced
  before the limiter; not a substitute for request-rate enforcement.
- `TokenBucket.consume` arithmetic and lazy refill are correct; `snapshot`/`restore` refill
  arithmetic is consistent.

## Enumeration

```
rg -n "allow_gossip|allow_message|_bucket\(|self._buckets|save_rate_bucket|load_rate_buckets|DELETE FROM rate_buckets|rate_buckets" lattice/ --glob '!__pycache__'
rg -n "verify_gossip_sender_card|root_public_key|RootIdentity|derive_node_id|get_pin|known_root" lattice/runtime.py lattice/api.py
rg -n "limit_req|limit_conn|limit_except" deploy/lattice.nginx.conf
```

Instance table (bucket lifecycle — the class is closed; no eviction instance exists):

| Instance | Disposition |
|---|---|
| `_buckets` insert (rate_limit.py:99) | finding: no matching eviction anywhere |
| `_buckets` snapshot (rate_limit.py:124) | feeds persistence, no prune |
| `_buckets` restore (rate_limit.py:157,160) | reloads attacker rows on start |
| `save_rate_bucket` (repositories.py:605) | upsert only; no delete/TTL |
| `load_rate_buckets` (repositories.py:624) | SELECT all; unbounded |
| `allow_gossip` (api.py:265) | only gossip-rate caller of the limiter |
| `allow_message` (api.py:335) | keyed on verified id; examined-clean |
| `_peer_ip` (api.py:110) | added mechanism A |
| nginx `limit_req`/`limit_conn` | absent (rg section C) |

## Bound

- No live infrastructure: I did not run the daemon or send requests; the XFF spoof in added
  mechanism A rests on documented Nginx `$proxy_add_x_forwarded_for` semantics, not on an observed
  request. If a deployment inserts Nginx `limit_req`/`limit_conn` not present in the shipped
  config, the request-rate ceiling changes (invariant 7) but the unbounded `rate_buckets` growth
  and the per-identity quota bypass remain.
- Memory cost per `TokenBucket` was not measured; the claim of unboundedness rests on the absence
  of any eviction/prune (rg section A), which is decisive, not on a byte figure.
- `docs/PROTOCOL.md` §5.2 and `deploy/lattice.nginx.conf` read in full; runtime/api/rate_limit/
  repositories read along the traced path, not end to end.
