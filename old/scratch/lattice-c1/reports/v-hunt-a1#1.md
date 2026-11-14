# v-hunt-a1#1 — PRIMED VERIFIER

Claim under test: **hunt-a1 #1 [M] — Gossip rate-limit key trusts first X-Forwarded-For element**
(`scratch/lattice-c1/reports/hunt-a1.md`, finding 1, reported tier M).

Method: frame re-derived from source before reading the claim's conclusion. `lattice/api.py` read
end-to-end (414 lines); `lattice/rate_limit.py` end-to-end; `deploy/lattice.nginx.conf`
end-to-end; `lattice/runtime.py` (rate-limiter construction, `verify_gossip_sender_card`,
`_persist_rate_limits`, `stop`); `lattice/storage/repositories.py` (`save_rate_bucket`,
`load_rate_buckets`); `lattice/migrations/cache_schema.sql`; `lattice/config.py` (bind host,
rate-limit defaults); `lattice/cli.py:cmd_serve`. No live daemon or proxy was exercised.

## Verdict: CONFIRMED (M)

All three components — mechanism, trigger, frequency — re-derive to the claim. Severity stays M.

### Frame re-derived from source

- `_peer_ip` (api.py:110-117) returns `forwarded.split(",")[0].strip()` for any present
  `x-forwarded-for`; else `request.client.host`; else `"unknown"`.
- `receive_gossip` (api.py:242) computes `sender_node_id` from `verify_gossip_sender_card(cards[0])`
  and sets `peer_id = sender_node_id or _peer_ip(request)` (api.py:264), then
  `allow_gossip(peer_id)` (api.py:265). `_peer_ip` is used **nowhere else** in the tree
  (`rg -n "_peer_ip" lattice/` → api.py:110, api.py:264 only).
- `verify_gossip_sender_card` (runtime.py:536-569) returns `None` for an empty `cards` list, a
  non-dict `cards[0]`, or any card that fails the self-consistent root/cert/signature chain. A
  `None` therefore routes every such request to the IP fallback.
- `deploy/lattice.nginx.conf` sets, on the gossip location (lines 50-51) and every other location,
  both `proxy_set_header X-Real-IP $remote_addr;` and
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.
  `$proxy_add_x_forwarded_for` = the client's incoming `X-Forwarded-For` value, appending
  `$remote_addr` after a comma (or just `$remote_addr` when the client sent none). It does **not**
  strip a client-supplied value. Therefore the first comma-separated element the daemon sees is
  attacker-controlled whenever the attacker sends one, and `X-Real-IP` is the unspoofable field the
  app ignores.
- `cmd_serve` binds `uvicorn.run(host=config.bind_host, ...)`; `DEFAULT_BIND_HOST = "127.0.0.1"`
  (config.py:18,190). The daemon is loopback-only; the documented production ingress is nginx, so
  the header is exactly what a remote peer controls.

### Mechanism

Confirmed. `peer_id` falls back to a client-supplied header field. Rotating `X-Forwarded-For`
across requests selects a fresh `(peer_id, "gossip")` key, so `RateLimiter._bucket` constructs a
new `TokenBucket` at full capacity each time (rate_limit.py:91-100). The limiter never sees the
attacker's real bucket. Decisive artifact: api.py:112-114 feeding api.py:264-265.

### Trigger

Confirmed, production-reachable. Any network peer POSTs to the public fixed route
`POST /lattice/v1/gossip` (invariant 3) with `Content-Length` set, a body whose `cards[0]` is
absent or fails `verify_gossip_sender_card` (e.g. `{"cards": []}`, or 32 random-byte card dicts),
and a distinct `X-Forwarded-For` per request. No valid signature, no pinned peer, no operator
action is required. `require_content_length` + `require_ready` pass; only `_peer_ip` is consulted.

### Frequency

Confirmed, DEMONSTRATED and grounded. The population is every request to the public gossip route
that does not present a verifying first card; the cadence is per request. No coincidence is
required — an empty/`invalid` first card plus a rotated header is sufficient on each request. This
is the ambient traffic of an internet-exposed federation route.

### Outcome

Confirmed for the primary effect: the gossip token bucket — the endpoint's only quota enforcement —
does not constrain a hostile sender ("wrong rate/quota decision", the M criterion). The claim's
secondary clause is also literally true but is a distinct mechanism, separated below.

### Severity

Left at M. The finding's specific defect is a quota-decision fault, which the pinned scale places
at M ("a wrong rate/quota decision"). I considered promoting to H on the accompanying
unbounded-`_buckets` clause and declined: that growth is not specific to the XFF fault (any
distinct key — a self-minted node id, a genuine rotated client IP — grows the same map), so
charging H to the XFF parse would fold a second defect into the first. The H-class resource
mechanism is recorded separately under Added mechanisms. No correction issued; trace above.

### Sub-claims refuted

None. Every sub-claim (first element attacker-controlled under `$proxy_add_x_forwarded_for`;
fallback reached on a non-verifying first card; fresh bucket per rotated key; `X-Real-IP` set but
ignored; nginx append semantics) re-derived true. The claim's self-limitation ("only the XFF
parsing fault; identity-keyed limits are also bypassable by key rotation") is accurate and is the
hook for the additional mechanism below.

## Added mechanisms / earlier failure sites / new reachability (same trace)

1. **Verification precedes the limiter (ordering).** api.py:259-263 performs full first-card
   Ed25519 verification *before* api.py:265 consumes a token. The limiter therefore cannot protect
   the verification CPU: an abusive sender pays the cost of verifying `cards[0]` on every request
   even when the request is (in a fixed design) over quota. A correct limiter alone does not bound
   verification work; the check must move ahead of verification. Reachable in PRODUCTION.
2. **Unbounded `_buckets`, no eviction, persisted** (H-class resource mechanism, distinct root
   cause). `RateLimiter._buckets` (rate_limit.py:88) has no cap or prune path;
   `runtime._persist_rate_limits` (runtime.py:497-509) iterates `snapshot()` and writes one
   `rate_buckets` row per key, and `rate_buckets` (cache_schema.sql:65-70) has no prune either.
   Any actor able to present distinct keys — a spoofed XFF, a self-minted node id, or ordinary IP
   churn — grows both in-process memory and a durable table without bound. Reachable in PRODUCTION
   by an unauthenticated peer.
3. **Self-attested identity is a second, header-independent bypass.** `verify_gossip_sender_card`
   builds `RootIdentity` from the card's own `root_public_key` (runtime.py:553-566), so an attacker
   mints a fresh keypair per request, passes `cards[0]`, and gets a fresh node-id bucket with no
   XFF spoof at all. This is reported independently as hunt-f1 #1; recorded here because it sits on
   the same `peer_id` construction and shows the XFF fix alone does not close the bypass class.
   Reachable in PRODUCTION. (Not re-reported as new.)

## Fix-direction constraints

- Replacing the first-element XFF parse with `X-Real-IP` fixes only the spoof. Because the daemon
  can be bound directly (`bind_host` is configurable), any proxy-header trust must be gated on a
  configured trusted-proxy set; unconditionally trusting `X-Real-IP` moves the spoof, not closes
  it. No trusted-proxy configuration exists today.
- A complete repair must also (a) move the rate-limit check ahead of card verification, (b) add an
  eviction/expiry bound to `_buckets` and a prune path for `rate_buckets`, and (c) decide the
  identity-minting question (cost of minting a self-attested key), which is a protocol decision,
  not an api.py edit.
- Escaping the header spoof is not the same as bounding the resource: the unbounded-per-key map is
  reachable through legitimate keys too, so a header fix without eviction leaves the H-class
  mechanism intact.

## Checked and clean

- `_peer_ip` is not used on the message route: `receive_message` keys only on the
  signature-verified `from_node_id` (api.py:335). The XFF fault is gossip-only.
- `x-forwarded-for` lookup is case-insensitive (Starlette headers); no alternate casing bypass or
  double-parse; `split(",")[0]` on a comma-free value is the value itself.
- `verify_gossip_sender_card` is self-consistent and returns `None` (not raises) on malformed
  input; the `isinstance(cards[0], dict)` guard prevents an exception on a non-dict first card, so
  the fallback is reached cleanly rather than by crashing.
- `RateLimiter` locking: `_bucket` and `consume` are lock-protected; no lost-update on the bucket
  map under concurrent requests.
- `require_content_length`, `require_ready`, and `require_admin` re-checked (unchanged from
  hunt-a1's clean list); the gossip route's only pre-limiter gates are content-length and readiness.

## Enumeration

`_peer_ip` class closure and its call sites:
`rg -n "_peer_ip" lattice/` →
`lattice/api.py:110:def _peer_ip(request: Request) -> str:` and
`lattice/api.py:264: peer_id = sender_node_id or _peer_ip(request)` — exactly one caller, the gossip
route; disposition: finding.

Proxy-header trust sites: `rg -n "forwarded|X-Real-IP|X-Forwarded" lattice/ deploy/` →
app reads only `x-forwarded-for` (api.py:112); nginx sets both `X-Real-IP` and `X-Forwarded-For`
per location (deploy/lattice.nginx.conf:36-37,50-51,64-65,81-82,95-96); `X-Real-IP` is never read
in Python. Disposition: finding (gossip), examined-clean (other locations proxy the admin/health
loopback-only routes which are not IP-keyed).

Rate-limit persistence/prune closure:
`rg -n "rate_buckets|_persist_rate_limits|load_rate_buckets|save_rate_bucket" lattice/` →
`CacheRepository.save_rate_bucket` (repositories.py:605, upsert), `load_rate_buckets`
(repositories.py:624, SELECT *), `_persist_rate_limits` (runtime.py:497), `_restore_rate_limits`
(runtime.py:402), schema `rate_buckets` (cache_schema.sql:65). No DELETE/prune of `rate_buckets`
anywhere. Disposition: added mechanism 2.

## Design risks (max 2)

1. The gossip rate limiter's identity key is *self-attested* (`verify_gossip_sender_card` verifies a
   card against the root key the card itself carries). This matches docs/PROTOCOL.md §5.2, whose
   trust assumption (minting an identity is expensive) does not hold for an anonymous Ed25519
   keygen. Closing it is a protocol cost-function decision, not a code fix. (Shared with hunt-f1.)
2. `receive_gossip` verifies before it limits; any future auth/rate design on this route inherits
   the same ordering unless the check is deliberately moved ahead of verification.

## Bound

- No daemon, nginx, or HTTP client was run. The `$proxy_add_x_forwarded_for` append semantics are
  established from nginx documented behavior, not observed on this host; if a deployment inserted a
  header-stripping proxy ahead of nginx, the first element would become the trusted proxy's, not the
  attacker's. That is a deployment property outside the tree.
- Whether a given human deployment actually routes through the shipped nginx config (vs. a
  different proxy that overwrites XFF) is a config choice; the default bind is loopback and the
  shipped config is the documented ingress, which is the basis for the production-reachability call.
- Uvicorn's own proxy-header handling was not exercised and is irrelevant: the code reads the raw
  header directly, independent of `forwarded_allow_ips`.
