# Orientation: normative docs, deploy, and test surface

## 1. Concept

Docs are layered. `docs/AGENTS.md` is the routing index and declares every doc "normative for its
area" (docs/AGENTS.md §Cross-cutting rules); the root `AGENTS.md` gives invariants + a file map;
`docs/ARCHITECTURE.md` is the design overview; `docs/PROTOCOL.md` is the wire/schema/route contract;
`docs/THREAT_MODEL.md` fixes security assumptions, invariants, and non-goals;
`docs/ADDRESSING.md`, `docs/KEY_MANAGEMENT.md`, `docs/MIGRATIONS.md`, `docs/LATTICE_SYSTEMD.md`
own addressing, key lifecycle, storage, and deployment respectively. `docs/adr/` is **empty**.
A code fix is adjudicated primarily against `PROTOCOL.md` (behavior/schemas), `THREAT_MODEL.md`
(invariants/non-goals), and the root `AGENTS.md` invariants; deploy files are the operational
projection of those contracts.

## 2. Normative statements that constrain fixes

- **Eight root invariants** (AGENTS.md §Invariants): immutable root; no root key in daemon; fixed
  public routes; synchronous core; durable-custody receipts; no message relay; Nginx/systemd
  boundary; no legacy compat.
- **202+rejected receipts** (PROTOCOL.md §8): "A `202 Accepted` with a rejected receipt is final.
  The receipt bytes MUST be persisted and returned identically for duplicate `message_id`."
- **Message duplicate idempotency** (PROTOCOL.md §5.3): "If the same `message_id` is received again
  and the message is already in durable custody, the receiver MUST return the identical signed
  receipt bytes."
- **Signature preimage** (PROTOCOL.md §4.3): `"lattice-signature-v1\0"||kind||"\0"||media_type||"\0"||canonical_bytes`,
  canonicalizing the object **excluding** `signature`.
- **Strict JSON** (PROTOCOL.md §4.1): reject duplicate keys, non-I-JSON numbers, NaN/Infinity,
  invalid UTF-8; key order not significant.
- **Node ID** (PROTOCOL.md §3.2): `lat_` + lowercase unpadded base32(SHA-256("lattice-node-id-v1\0"||raw_root_pub)).
- **Cert monotonicity** (PROTOCOL.md §3.3): reject past `valid_until`, non-increasing `sequence`,
  bad root signature.
- **Gossip body/batch** (PROTOCOL.md §5.2): first card SHOULD be sender's own; receiver MUST verify
  and only then identity-key rate limiting, else fall back to client IP; 32 cards; 256 KiB.
- **Gossip validation** (PROTOCOL.md §6): reject past `expires_at`, non-increasing `sequence`;
  independently fetch well-known before verified.
- **Message fields/limits** (PROTOCOL.md §7,§10): content 64 KiB, extension 16 KiB, priority
  enum, TTL default 86400/max 604800, reject wrong-node addresses.
- **Error format** (PROTOCOL.md §9): RFC 9457 `application/problem+json` with stable `code`.
- **Version policy** (PROTOCOL.md §11): media-type major version; reject unsupported/missing version.
- **Threat invariants** (THREAT_MODEL.md §4): immutable identity; no silent domain takeover;
  self-authenticating objects; direct delivery; durable custody boundary; content minimization
  (audit metadata 30 days); bounded concurrency.
- **Migration discipline** (MIGRATIONS.md): cumulative, `user_version` tracked; integrity+FK checks;
  pre-migration backup; refuse DB newer than binary; cache recreated on mismatch; fixture per
  released version.
- **Address trust reset** (ADDRESSING.md §Domain binding warnings): fail closed on bind change;
  `trust reset-domain`; transfer via dual root signatures.
- **Op/transfer statements** (KEY_MANAGEMENT.md): rotation = root+old op+new op over same object;
  transfer = old root + new root; `accept-transfer` fails closed unless old pin root matches and
  live well-known derives new node ID.
- **Deployment security** (THREAT_MODEL.md §8, LATTICE_SYSTEMD.md §Security notes): only three
  public routes; `LoadCredentialEncrypted=`; root key never loaded by daemon.

## 3. Deploy ↔ code map

- `deploy/lattice.service` `ExecStart=lattice serve --config ...` → `cli.py:cmd_serve` →
  `uvicorn.run(host=config.bind_host, port=config.bind_port, workers=1)` (cli.py:720-724).
- Credentials `operational_key`, `webhook_bearer`, `admin_bearer` via
  `/run/credentials/lattice.service` → `credentials.py:DEFAULT_CREDENTIAL_DIR` and loaders.
- `StateDirectory/CacheDirectory=lattice` → `/var/lib/lattice`, `/var/cache/lattice` (MIGRATIONS.md).
- Nginx `127.0.0.1:1113` → `config.DEFAULT_BIND_PORT=1113`, default `bind_host=127.0.0.1`.
- Nginx exact routes `/.well-known/lattice`, `/lattice/v1/gossip`, `/lattice/v1/messages` →
  `constants.ROUTE_*`, api.py:226/235/280. Loopback-only `/lattice/v1/admin/` and
  `/lattice/v1/health/` → api.py:212/216/360/384 (health paths **not** in constants).
- Nginx body caps 256k/128k and method allowlists → `MAX_GOSSIP_BODY_BYTES=256*1024`,
  `MAX_MESSAGE_BODY_BYTES=128*1024`, enforced in code (not only edge).

## 4. Test harness map

- `test_canonical` — strict parse + JCS; no mocks.
- `test_vectors` — golden `tests/vectors/{canonical,signatures}.json`; no mocks.
- `test_addressing` — parser; no mocks.
- `test_config` — TOML load/render; no mocks.
- `test_network_policy` / `test_transport` — real policy/IP checks; transport does real DNS for
  localhost/private (test_transport.py).
- `test_storage`/`test_schema_upgrades` — real SQLite, fixture `tests/fixtures/durable_schema/v1.sql`.
- `test_peers` — real repos, no net.
- `test_topology`/`test_gossip` — `FakeClock`, `MagicMock(spec=WellKnownResolver)` — **well-known
  fetch is faked**.
- `test_resolution` — `MagicMock(spec=OutboundTransport)` + MagicMock responses — **HTTP is faked**.
- `test_messages` — `FakeClock`; real repos, no net.
- `test_runtime` — `MagicMock` transport `request` and `webhook_service.deliver` patched
  (test_runtime.py:286-314) — **outbound HTTP and webhook are faked**.
- `test_webhook` — `urllib3` pool `urlopen` patched (test_webhook.py:83-133) — **all HTTP faked**.
- `test_api` — `TestClient`, real runtime/DB; no network.
- `test_integration` — `_FakeTransport` routes between in-memory apps (conftest.py:32-120) —
  **no real TLS/Nginx/DNS/systemd** (LOOSE_ENDS.md §Phase 11 says so).
- `test_cli`/`test_resilience` — `getpass` patched, `lattice.cli.OutboundTransport` patched with
  `_WKTransport`.
- `test_deployment` — parses real unit/nginx text; `nginx -t` **skipped if nginx absent**.
- `test_wheel` — builds wheel, installs in fresh venv (real subprocess).
- Not exercised: real systemd start, nginx runtime, TLS, live DNS/federation, `_LockedConnection`
  concurrency bottleneck.

## 5. Doc ↔ code drift inventory

- `docs/AGENTS.md` registers `OPERATIONS.md`, `INTEGRATION.md`, `adr/` — **none exist**; it omits
  `ARCHITECTURE.md` and `LATTICE_SYSTEMD.md`, which do exist.
- Root `AGENTS.md` file map cites `lattice/app.py`, `api_public.py`, `api_local.py`, `queue.py`,
  `client.py`, `docs/OPERATIONS.md`, `docs/INTEGRATION.md`, `docs/adr/`, `tests/e2e/`,
  `tests/fixtures/schema_versions/`, `lattice/rate_limit.py` mapping — code has `api.py` (single),
  `messages.py`, `rate_limit.py`; adr/e2e/schema_versions missing. Root AGENTS.md §TODO admits this.
- `docs/ARCHITECTURE.md` and README list 6 docs; neither lists `MIGRATIONS.md`/`ARCHITECTURE.md` in
  README. README docs list omits `MIGRATIONS.md`, `ARCHITECTURE.md`, `LOOSE_ENDS.md` present.
- Stale `tests/__pycache__/*.pyc` reference deleted modules (`test_send_message`, `test_client`,
  `test_domain_registration`, `test_request_body_limit`, `test_signature_verification`) — no source.
- LATTICE_SYSTEMD.md §Health checks shows `:1113/lattice/v1/health/{live,ready}` — paths exist in
  api.py but not in `constants.py` (minor).
- KEY_MANAGEMENT.md §Development and testing mentions explicit-path creds — matches
  `credentials.load_credential(path=...)`.

## 6. Doc ↔ doc contradictions

- README §Status/§Documentation implies docs list; `docs/AGENTS.md` claims a larger doc set
  (`OPERATIONS.md`, `INTEGRATION.md`, `adr/`) than exists.
- Root AGENTS.md says Nginx owns "generic edge limits" and daemon also enforces (THREAT_MODEL.md §8
  and LATTICE_SYSTEMD.md agree both) — consistent, but root map claims separate `api_public/api_local`
  files while ARCHITECTURE.md §Wire protocol names routes only.
- LOOSE_ENDS.md §Phase 9 says Nginx has no rate-limit zones, relying on Lattice quotas; root
  AGENTS.md invariant 7 says Nginx owns "generic edge limits" — scope-only tension, not conflict.

## 7. Census caveats

- THREAT_MODEL.md §7 non-goals: no E2E encryption, human receipts, one-human-per-node, global
  consensus, relay, content filtering, multi-process runtime, first-class containers, pre-release
  compat.
- LOOSE_ENDS.md explicit known gaps: real TLS/Nginx/systemd e2e not run; nginx/systemd verify not
  executed on target distros; no packaging; webhook no mTLS; `_LockedConnection` bottleneck.
- PROTOCOL.md §Status "Draft"; media-type/well-known registration pending.
- README §Status: no compat with pre-release implementation.
- `docs/adr/` empty → no frozen ADRs to bound scope.

## 8. Surprises

- Test suite is broad but **every external boundary is faked**; "integration" is in-memory.
- Root AGENTS.md is partly aspirational and self-flags it in §TODO.
- Doc set referenced by `docs/AGENTS.md` is larger than the tree; `README`/root AGENTS disagree.
- `test_deployment` never validates live nginx (skips without binary).
- `docs/adr/` exists but is empty — architectural rationale lives only in ARCHITECTURE.md prose.
