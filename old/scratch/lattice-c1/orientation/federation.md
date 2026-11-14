# Orientation: federation, topology, and the outbound trust boundary

## 1. Concept
This subsystem is the node's entire relationship with other nodes: it resolves and connects to external hosts under an SSRF policy (`transport.OutboundTransport`, `network_policy.NetworkPolicy`), accepts gossiped peer cards as *untrusted* candidates (`gossip.GossipService.receive_batch` → `topology.TopologyService.accept_candidate`), independently re-verifies them against the domain's well-known document before promoting them (`topology._verify_against_well_known`), matures and slots verified peers into guards/discovery (`topology._fill_guards/_fill_discovery`), stores durable state and local blocks (`peers.PeerStore`, `peers.BlockStore`), rate-limits peers (`rate_limit.RateLimiter`), and pins domains (`resolution.WellKnownResolver`). Peers are **untrusted** at gossip intake and transport level; **partially trusted** once a self-advertised signature chain verifies (rate-key only, `runtime.verify_gossip_sender_card`); **verified** only after the receiver fetches `/.well-known/lattice`. The operator/host is assumed honest (THREAT_MODEL §2).

## 2. Invariants
- **Immutable identity** (THREAT_MODEL §4.1): `identity.derive_node_id`, enforced in `resolution._verify_against_well_known` and `topology._verify_against_well_known`.
- **No silent domain takeover** (§4.2): `WellKnownResolver.pin`/`reset_domain`; transfer path outside this subsystem. **Not enforced on re-resolution here** (see §7).
- **Self-authenticating objects** (§4.3): `protocol.signing.verify_peer_card` / `verify_with_root`.
- **Direct delivery / no relay** (§4.4): `gossip` sends card batches only (`runtime._run_gossip_round`); messages route separately (`api.receive_message`).
- **Durable custody** (§4.5), **content minimization** (§4.6), **bounded concurrency** (§4.7): not enforced here.
- **Sybil controls** (§5): candidate caps `topology.can_accept_candidate`; independent verification `_verify_against_well_known`; maturity `_maybe_promote`; diversity `prefix_from_ip`/`_fill_discovery`; **no propagated trust** — `introduced_by` used only for caps/audit (`gossip.ReceivedCard`).
- **PROTOCOL §5.2** identity-keyed gossip rate limit: `runtime.verify_gossip_sender_card` + `api._peer_ip` fallback.
- **PROTOCOL §6** card validation: op signature/cert enforced; expired and sequence-monotonic rules **not enforced at verification** (§7).

## 3. Mechanism inventory
SSRF-safe resolve+validate: `transport.OutboundTransport._resolve_and_validate`/`request`. IP policy: `NetworkPolicy.validate_ip`/`_is_internal`/`hostname_allowed`. Peer-card verification: `topology._verify_against_well_known` (full), `runtime.verify_gossip_sender_card` (rate key). Candidate intake: `gossip.receive_batch` → `topology.accept_candidate`. State transitions: `peers.PeerStore.transition`, `PeerState`, `topology._maybe_promote`. Prefix grouping: `topology.prefix_from_endpoints`/`prefix_from_ip`, `_fill_discovery`. Quotas: `can_accept_candidate`, `_fill_guards`. Token bucket: `rate_limit.RateLimiter._bucket`/`TokenBucket.consume`. Pins: `resolution.WellKnownResolver.resolve_with_ip`/`pin`, `resolve_address`. Addresses: `addressing.parse_address`.

## 4. Sanctioned idioms + exemplars
- **Resolve + connect to external host**: always `OutboundTransport.request`; never `socket`/`requests` directly. Mirror `transport.py:OutboundTransport._resolve_and_validate`.
- **Verify a peer card**: full chain pinned to the root derived from `node_id`. Mirror `topology.py:TopologyService._verify_against_well_known`. `runtime.verify_gossip_sender_card` is a deliberately weaker, self-consistent variant (§6).
- **Admit a candidate**: route through `gossip.py:GossipService.receive_batch` → `topology.py:TopologyService.accept_candidate` with an `observed_prefix`; do not insert candidate rows directly.
- **Key a rate-limit bucket**: stable identity — node ID when the card verifies, client IP fallback. Mirror `api.py:_peer_ip` + `runtime.py:RuntimeCoordinator.verify_gossip_sender_card`.
- **Parse an address**: `addressing.py:parse_address`; consumers use `parsed.domain`/`parsed.node_id`.
- Neutral divergences: duplicate `Clock`/`_SystemClock` in `gossip.py` and `topology.py`; `peers.PeerStore.get_peer_by_domain` uses raw SQL while the rest uses repositories.

## 5. Consequence map (ranked)
1. `transport._resolve_and_validate` / `network_policy.validate_ip` — failure lets an attacker point well-known fetches at internal addresses (SSRF); affects the node's network position; **silent**.
2. `topology._verify_against_well_known` — bypass admits an unverified/unforgeable-identity peer as verified; corrupts mesh trust for everyone downstream; silent.
3. `resolution.pin`/`resolve_address` — wrong pin sends mail to the wrong node; silent misdelivery.
4. `rate_limit.RateLimiter._bucket` + `runtime.verify_gossip_sender_card` — mis-keyed buckets allow flood or lock out honest peers; availability; silent.
5. `topology.accept_candidate` caps — disabled caps let a candidate flood consume all slots, slowly degrading discovery; silent.
6. `peers.transition`/`_maybe_promote` — corrupt topology/maturity; silent.
7. `addressing.parse_address` — malformed routing; localized, visible.

## 6. Intentional design decisions
- **Bootstrap introduces, never relays** (THREAT_MODEL §4.4): gossip carries cards only; `GossipService` never forwards message bodies.
- **Candidate intake groups by hostname, not IP** (LOOSE_ENDS Phase 6): `prefix_from_endpoints` runs before any fetch so rejected cards cost no traffic; real `/24`–`/48` prefix (`prefix_from_ip`) supersedes it after verification.
- **First-card trust is rate-key only** (`verify_gossip_sender_card`); it never authorizes topology admission.
- **`introduced_by` is recorded, never trusted** (`GossipService.receive_batch`) — used only for per-introducer caps.
- **Candidate intake does not verify signatures**: cheap Pydantic gate; real verification deferred to `verify_candidate`. Bounded by caps.
- **Blocks are local-only** (`topology.block`); no network propagation.
- **Caps are best-effort bounds, not elimination** (THREAT_MODEL §5); operators block explicitly.
- **IP fallback via `X-Forwarded-For` first hop** (`api._peer_ip`) is deliberately best-effort; only used when the card does not verify.

## 7. Doc ↔ code drift
- PROTOCOL §6 peer-card table omits `root_public_key`, but `protocol.models.PeerCard.root_public_key` is required and `gossip.build_own_card` emits it.
- PROTOCOL §6 "reject if `expires_at` is past" and "sequence not greater than last accepted card": no such enforcement in `topology.verify_candidate`/`_verify_against_well_known` (only max-lifetime via `PeerCard._check_expiry`). `peers` stores only `current_certificate_sequence`.
- ADDRESSING "If a pinned domain returns a different node ID on re-resolution, Lattice fails closed": `resolution.resolve_address` never re-resolves an existing pin, and `pin` upserts without comparing the prior `node_id`. No enforcing symbol.
- PROTOCOL §5.1 "well-known cache lifetime max 1 hour": outbound resolver has no cache; only the response `Cache-Control` header in `api.well_known`.
- THREAT_MODEL §4.5/§4.6/§4.7 name no symbols in this subsystem (out of scope).

## 8. Verification surface
`tests/test_transport.py` only asserts rejection of `http://`, `localhost`, and a direct private IP — no successful connection, `resolved_ip` check, or DNS-rebind test. `test_network_policy.py` covers `validate_ip`. `test_resolution.py` uses `MagicMock(spec=OutboundTransport)` with pre-baked responses, so `_resolve_and_validate`, content-type handling, and TLS never run. `test_topology.py` mocks `resolver.resolve_with_ip`; covers caps, maturity, guards, `prefix_from_ip`, blocks — but not `_verify_against_well_known` over a real transport, expired cards, or sequence monotonicity. `test_gossip.py` covers intake/caps. **There is no `test_rate_limit.py`**; `RateLimiter` has no direct test. `conftest._FakeTransport` backs `two_nodes`, bypassing the urllib3/TLS/SSRF path, masking IP validation, SNI/Host handling, `resolved_ip` propagation, and private-CA loading. A live probe needs real HTTPS with controlled DNS to exercise `_resolve_and_validate` and prefix diversity. Unexercised: transport TOCTOU, rate limiting, card expiry, sequence monotonicity, pin-conflict fail-closed.

## 9. Surprises
`transport.request` builds `https://{ip}:{port}`; bare IPv6 `str(ip)` would be malformed (no brackets). `NetworkPolicy.validate_ip` suffix matching is `endswith`, so `evilinternal.example.com` matches `internal.example.com`. `_fill_guards` re-queries `list_guards()` inside its loop. `_run_verify_candidates` swallows all exceptions. `resolve_address` does synchronous network I/O inside `api.admin_submit`.
