# q-contract — documented-vs-implemented contract drift (tree-wide)

Blind hunter pass, contract-drift question. Assigned docs read end to end:
`docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`, `docs/ADDRESSING.md`,
`docs/KEY_MANAGEMENT.md`, `docs/MIGRATIONS.md`, `deploy/lattice.nginx.conf`,
`deploy/lattice.service`. Code read end to end: `lattice/api.py`,
`lattice/protocol/constants.py`, `lattice/protocol/models.py`,
`lattice/protocol/signing.py`, `lattice/canonical.py`, `lattice/addressing.py`,
`lattice/identity.py`, `lattice/gossip.py`, `lattice/topology.py`,
`lattice/peers.py`, `lattice/messages.py`, `lattice/resolution.py`,
`lattice/runtime.py` (full), `lattice/config.py`, `lattice/cli.py` (full),
`lattice/transport.py`, `lattice/webhook.py`, `lattice/storage/connection.py`,
`lattice/storage/cache.py`, `lattice/storage/migrations.py`,
`lattice/storage/repositories.py` (all repository classes), migration SQL.
`docs/LOOSE_ENDS.md` read as context for intent. `docs/LATTICE_SYSTEMD.md` NOT
assigned (bound, see end).

Empirical verification: a live FastAPI/TestClient run against a real
`RuntimeCoordinator` (temp-dir databases, unmodified repo code) confirmed the
media-type and error-path behaviors quoted below. urllib3 2.7.0 kwargs fault of
hunt-b1b #1 independently re-verified by inspecting
`HTTPConnectionPool._make_request` parameters in the repo venv.

## Findings

1. [H] — Bootstrap restart silently rewrites a pinned domain's node binding
   (reachability: **GATED** behind the transport TypeError, hunt-b1b #1)
- Location: lattice/runtime.py:_pin_bootstrap_peers; lattice/storage/repositories.py:DomainPinRepository.upsert
- Evidence: runtime.py: `if self._peer_store.get_peer_by_domain(domain) is not None: continue` — the
  guard consults the **peer table**, never the pin table; then `self._pin_repo.upsert(domain=domain,
  node_id=node_id, root_public_key=root_pub_key, ...)` runs unconditionally. repositories.py upsert:
  `ON CONFLICT(domain) DO UPDATE SET node_id = excluded.node_id, root_public_key =
  excluded.root_public_key, ..., transfer_node_id = NULL, trust_reset_at = NULL`.
- Trigger: daemon restart with a `gossip.bootstrap` URL whose domain has a **pin but no peer row**
  (pins-without-peer rows are created by every `resolve_address` on a human address —
  `admin_submit` → `runtime.resolve_destination` → `resolver.pin(domain)`, no peer row written),
  while the domain's live well-known now advertises a different node ID (re-host, DNS hijack, or
  takeover — the exact event pins exist to defend against). Path: `cmd_serve` →
  `RuntimeCoordinator.start()` → `_pin_bootstrap_peers` → `resolver.resolve(domain)` (fresh
  DNS+TLS fetch) → `_pin_repo.upsert` overwrite.
- Frequency: DEMONSTRATED mechanism, environment-armed trigger — restarts are routine (deploys);
  the binding-change precondition is the takeover scenario the pin exists to reject. Today the
  path is GATED: `resolver.resolve()` raises TypeError (hunt-b1b #1, re-verified:
  `_make_request` accepts no `fields`/`assert_hostname` kwargs in urllib3 2.7.0), which escapes
  `except ResolutionError` and exits the daemon before the upsert. A repair of hunt-b1b #1 that
  does not also add a pin-mismatch check ships this defect live.
- Outcome: THREAT_MODEL invariant 2 ("A domain pin can change only through an old-root/new-root
  transfer statement or explicit local trust reset") and ADDRESSING.md ("If a pinned domain returns
  a different node ID on re-resolution, Lattice fails closed") are violated: the local node
  silently accepts a new root key for the domain and delivers subsequent messages for
  `user@domain` to the new node with valid 202 custody. No transfer statement, no trust reset,
  only an INFO log line.
- Confidence: traced — mechanism fully traced (guard is peer-table, not pin-table; upsert
  overwrites unconditionally); trigger gated as stated; frequency of the binding-change
  precondition is environment-dependent (stated, not asserted as common).

2. [M] — Documented recovery procedure `lattice init --force` destroys the root key it is
   supposed to preserve
- Location: lattice/cli.py:cmd_init; docs/KEY_MANAGEMENT.md §Backup and recovery
- Evidence: KEY_MANAGEMENT.md: "1. Copy the encrypted root key to `/etc/lattice/root_key.pem`.
  2. Run `lattice init --force` to generate a new operational key and config." Code:
  cmd_init unconditionally does `root_key = generate_private_key()` … `save_root_key(root_key,
  root_key_path, password)` — there is no branch that reuses an existing root_key.pem.
- Trigger: an operator executes the documented recovery steps on a replacement host. PRODUCTION,
  operator action, documented procedure. No gating (pure CLI, no transport).
- Frequency: DEMONSTRATED population — every operator performing the documented host-replacement
  recovery; rare cadence but the doc itself instructs the exact command.
- Outcome: the just-copied root key is overwritten with a fresh one; the "recovered" node comes
  up with a new node ID (init prints it, nothing fails), the new well-known/cert all
  self-consistently describe the *new* identity, every peer pin for the old identity is dead,
  and the recovery the doc promises (identity preserved) did not happen. Doc and code disagree —
  either the doc's recovery section or cmd_init must change; today the documented procedure is
  a trap.
- Confidence: traced — mechanism, trigger, frequency all verified; nothing unproven.

3. [L] — PROTOCOL §9 example error-code table: six of seven documented machine codes do not
   exist anywhere in the code
- Location: docs/PROTOCOL.md §9 vs lattice/protocol/constants.py; emitting sites in lattice/api.py:_problem
- Evidence: doc table promises `LATTICE_INVALID_SIGNATURE` (401), `LATTICE_UNKNOWN_NODE` (404),
  `LATTICE_EXPIRED_CERTIFICATE` (401), `LATTICE_MESSAGE_TOO_LARGE` (413), `LATTICE_INVALID_ADDRESS`
  (400), `LATTICE_DOMAIN_BINDING_MISMATCH` (403), `LATTICE_RATE_LIMITED` (429), and states "The
  `code` field is stable and machine-readable. Clients SHOULD use `code`". Code emits
  `LATTICE_BAD_REQUEST`, `LATTICE_UNAUTHORIZED`, `LATTICE_FORBIDDEN`, `LATTICE_NOT_FOUND`,
  `LATTICE_LENGTH_REQUIRED`, `LATTICE_TOO_LARGE`, `LATTICE_RATE_LIMITED`,
  `LATTICE_SERVICE_UNAVAILABLE`, `LATTICE_INTERNAL_ERROR`. Only `LATTICE_RATE_LIMITED` overlaps
  (see Enumeration, ENUM 2). Empirically confirmed: a signature-failing POST to
  `/lattice/v1/messages` returns `"code": "LATTICE_UNAUTHORIZED"` where the doc specifies
  `LATTICE_INVALID_SIGNATURE`.
- Trigger: PRODUCTION — every error response on the public routes demonstrates the divergence;
  any client that branches on the documented codes never matches.
- Frequency: DEMONSTRATED — the operation population is every 4xx/5xx problem-detail response
  the daemon ever emits; cadence is continuous in normal operation.
- Outcome: the documented machine contract is unusable as written; a spec-conforming client's
  error handling silently never fires. Direction: doc wrong (or code wrong — either side must
  move; today they disagree).
- Confidence: traced — mechanism (two-sided literal sets compared), trigger, frequency all
  demonstrated. Note: hunt-e1 flagged one nonexistent code (`LATTICE_EXPIRED_CERTIFICATE`) inside
  its cert-expiry finding; the full-table divergence is reported here.

4. [L] — THREAT_MODEL invariant 6 "Audit metadata is retained only 30 days" has no
   implementation
- Location: docs/THREAT_MODEL.md §4 invariant 6; lattice/migrations/durable/001_initial.sql:193
  ("Audit log: minimal structured event records retained 30 days"); lattice/runtime.py:_run_expiry_cleanup
- Evidence: `_run_expiry_cleanup` calls only `self._outbound.expire()` and
  `self._topology.prune(...)`. `AuditLogRepository` has `insert` only — no delete/prune method
  exists; `rg "DELETE FROM audit_log|retention|prune" lattice/` returns no audit hits (see
  Enumeration note).
- Trigger: PRODUCTION — normal continuous operation; every accepted inbound message
  (`_audit_inbound_accepted`), delivered/failed outbound, and webhook outcome appends a row that
  no code ever deletes.
- Frequency: DEMONSTRATED — unbounded accumulation on the durable database at the rate of all
  message traffic, from process start, permanently.
- Outcome: the stated content-minimization/retention invariant is not enforced; durable DB grows
  without bound and metadata (node IDs, message IDs, failure reasons) is retained indefinitely —
  the opposite of the documented 30-day bound. Direction: code wrong (doc states a bound; nothing
  implements it).
- Confidence: traced — mechanism (no pruning code path exists), trigger, frequency all verified.

5. [L] — PROTOCOL §5.3 documents only a 202-with-signed-receipt response; the implemented
   cold-sender 503 is absent from the normative spec
- Location: docs/PROTOCOL.md §5.3 vs lattice/api.py:receive_message (cold-sender branch)
- Evidence: doc: "Response is a signed `receipt` object (§8) with HTTP status `202 Accepted`."
  Code: `if cold_sender: runtime.queue_domain_resolution(from_node_id); return JSONResponse(
  status_code=503, ..., headers={"Retry-After": "60"})`. The behavior is documented only in
  docs/LOOSE_ENDS.md Phase 8, not in the normative protocol.
- Trigger: PRODUCTION — every message POST whose `from_address` domain is not pinned (the
  cold-sender branch; common with any new peer).
- Frequency: DEMONSTRATED — one 503 per cold-sender message; seam-s1 documented this population.
- Outcome: the normative response contract for `POST /lattice/v1/messages` is incomplete: an
  interop client written to §5.3 treats 503 as an unspecified server error rather than the
  retry-with-Retry-After flow the implementation (and the sender-side `_send_outbound_message`,
  which retries on `>= 500`) depends on. Direction: doc wrong (behavior is deliberate —
  LOOSE_ENDS — but the spec was never updated).
- Confidence: traced — mechanism, trigger, frequency verified.

## Checked and clean

- **Public routes (§5, invariant 3)**: `ROUTE_WELL_KNOWN`/`ROUTE_GOSSIP`/`ROUTE_MESSAGES`
  literals in constants.py match the doc and the three exact-match nginx locations; nginx
  `limit_except` matches verbs (GET / POST); admin + health routes are loopback-only in nginx and
  behind bearer auth (admin) in api.py — intended per invariant 3.
- **Limits table (§10)**: all values in `protocol/constants.py` match the doc exactly — content
  64 KiB, extension 16 KiB, TTL default 86400 / max 604800, gossip batch 32, gossip body 256 KiB,
  message body 128 KiB, card lifetime 7 d, cert lifetime 90 d (enforced in
  `create_operational_certificate`), well-known cache 1 h (served via
  `Cache-Control: max-age=3600`). Nginx `client_max_body_size 256k/128k` match.
- **Signature preimage (§4.3)**: `canonical.signature_preimage` builds
  `lattice-signature-v1\0kind\0application/vnd.lattice+json; version=1\0canonical_bytes` exactly
  as documented; sign/verify strip only `signature` (plus the multi-sig fields for transfer/
  rotation, matching vector semantics); JCS via the `rfc8785` library as §4.2 recommends.
- **Node-ID derivation (§3.2)**: `derive_node_id` = `lat_` + lowercase unpadded base32 of
  SHA-256(`lattice-node-id-v1\0` ‖ raw 32-byte key) — matches.
- **Object schemas**: `WellKnownDocument` (§5.1), `OperationalCertificateModel` (§3.3), `Message`
  (§7), `Receipt` (§8), `Block`, `Transfer` all match the doc field tables (with
  `extra="forbid"`). Duplicate `message_id` returns the persisted identical signed receipt
  (`InboundMessageService.accept` → `get_existing_receipt`) per §5.3.
- **Gossip contract (§5.2)**: request `{cards, introduced_by}`; 200 `{accepted, rejected,
  errors}`; batch cap checked before verification work; identity-keyed rate limiting on the
  first card with IP fallback — all match, including the doc's rate-limit attribution wording.
- **CLI surface**: every command named in KEY_MANAGEMENT/ADDRESSING/MIGRATIONS exists in the
  parser with the documented flags (`init`, `init --force`, `upgrade --config`, `keys
  rotate-operational`, `keys create-transfer/co-sign-transfer`, `trust reset-domain`,
  `trust accept-transfer`, `contacts export/import/list`) — Enumeration ENUM 5. File modes
  claimed by KEY_MANAGEMENT (600/644/640) match `cmd_init` chmods; credential names
  (`operational_key`, `webhook_bearer`, `admin_bearer`) match `_credential_path`,
  `LoadCredentialEncrypted=` lines in `deploy/lattice.service`, and the doc's systemd-creds
  commands.
- **MIGRATIONS.md vs migrations.py**: integrity_check, foreign_key_check, pre-migration backup,
  cumulative in-order application, user_version verification, refusal of newer-than-target DB —
  all present; `serve`/`upgrade`/CLI trust commands call `migrate()` before opening the durable
  DB, so "refuses to open" holds in effect.
- **Cache DB**: hash-based schema check, unlink + WAL/SHM removal, recreate — matches
  MIGRATIONS.md "removed and recreated".
- **ADDRESSING.md**: `parse_address` examples (`username`/`domain`/`node_id`, `is_canonical`)
  match `addressing.py`; short-fingerprint slice `node_id[4:20]` matches the doc snippet;
  `trust reset-domain` / dual-signed transfer flows match `cmd_trust_*` (accept-transfer fails
  closed on pin/old-root/live-well-known mismatch as documented).
- **deploy/lattice.service**: ExecStart config path, `StateDirectory`/`CacheDirectory` matching
  the documented DB paths, credential names — all consistent with the docs and `cmd_serve`.

## Enumeration

ENUM 1 — signed-object kinds (doc §4.4 vs code literals):
```
doc:  awk '/^### 4.4/,/^## 5/' docs/PROTOCOL.md | grep -o '`[a-z_]*`' | ... | sort -u
code: rg -o '"(well_known|operational_certificate|peer_card|message|receipt|block|contact_card|transfer|rotation|webhook_envelope)"' lattice/ --no-filename | tr -d '"' | sort -u
comm -3 <(doc) <(code)
```
Result: doc set = 9 kinds, code set = 10; the only comm difference is `webhook_envelope`
(code-only; hunt-e2 side discovery 3 already recorded the §4.4 omission — cross-referenced, not
re-reported). All 9 documented kinds are implemented and signed/verified under the documented
kind string. Internal doc inconsistency: §1's signed-object list omits `contact_card` while §4.4
includes it (side discovery below).

ENUM 2 — error codes (doc §9 table vs constants.py):
```
doc:  sed -n '/^| `LATTICE/,/^$/p' docs/PROTOCOL.md | grep -o 'LATTICE_[A-Z_]*' | sort -u
code: rg -o 'LATTICE_[A-Z_]+' lattice/protocol/constants.py | sort -u
comm -3 <(doc) <(code)
```
doc-only: `LATTICE_DOMAIN_BINDING_MISMATCH LATTICE_EXPIRED_CERTIFICATE LATTICE_INVALID_ADDRESS
LATTICE_INVALID_SIGNATURE LATTICE_MESSAGE_TOO_LARGE LATTICE_UNKNOWN_NODE`.
code-only: `LATTICE_BAD_REQUEST LATTICE_FORBIDDEN LATTICE_INTERNAL_ERROR LATTICE_LENGTH_REQUIRED
LATTICE_NOT_FOUND LATTICE_SERVICE_UNAVAILABLE LATTICE_TOO_LARGE LATTICE_UNAUTHORIZED` (plus the
placeholder `LATTICE_SNAKE_CASE`/`LATTICE_CODE` from the doc's example shape). Overlap:
`LATTICE_RATE_LIMITED` only → finding 3.

ENUM 3 — routes (doc §5 vs api.py + nginx):
```
rg -o '"/.well-known/lattice"|"/lattice/v1/[a-z/]*"' lattice/api.py deploy/lattice.nginx.conf | sort -u
```
api.py declares admin/status, admin/messages/submit, health/live, health/ready beyond the three
public routes (constants `ROUTE_*`); nginx exposes exactly the three public routes exactly-matched
plus loopback-only admin/health blocks and a catch-all 404. Disposition: examined-clean, intended
per invariant 3.

ENUM 4 — limits (doc §10 table vs constants.py): `rg -n 'MAX_|DEFAULT_TTL'
lattice/protocol/constants.py` — all eight rows match; see Checked and clean.

ENUM 5 — CLI commands in docs vs parser: `rg -o 'lattice [a-z-]+( [a-z-]+)*' docs/KEY_MANAGEMENT.md
docs/ADDRESSING.md docs/MIGRATIONS.md | sort -u` — every extracted command/flag combination exists
in `_build_parser`; only `init --force` has semantic drift (finding 2).

## Design risks (1)

1. The normative tables in PROTOCOL.md (§9 codes, §6 card schema, §5.3 response set) have no
   conformance test binding them to code literals — every drift found in this pass is of a kind
   that recurs silently on each edit (a literal-set snapshot test or generated constants from the
   doc tables would close the class).

## Side discoveries (single-pass candidates, not confirmed work)

1. `PeerCard` requires a `root_public_key` field that is absent from the documented §6 schema
   (and the model uses `extra="forbid"`): a third-party implementation building cards per §6
   would be rejected with "invalid card". No in-tree trigger exists (all cards in tree are minted
   by `gossip.build_own_card`, which includes the field) — doc-side omission only.
2. §1's signed-object list omits `contact_card` while §4.4's allowed-kinds table includes it —
   internal PROTOCOL.md inconsistency (kind itself is implemented, per LOOSE_ENDS).
3. `resolution.resolve_with_ip` accepts any Content-Type containing the substring
   `application/vnd.lattice+json` (no version check) — already recorded as hunt-e2 side
   discovery 4; consistent with the §11 gap family but on the fetch side.

## Disputes / overlaps with prior passes

- **hunt-e2's clean claim "Problem-details constants match doc §9" is incorrect** as to the
  example-code table: only `LATTICE_RATE_LIMITED` overlaps (finding 3, ENUM 2). hunt-e2 verified
  the *format* (type-URI shape, code field, media type), which does match.
- Overlapping mechanisms found by prior passes, verified still present, **not re-reported** here:
  cert-expiry non-enforcement (hunt-e1 #1 / hunt-f2 #1 — also covers peer-card `expires_at`
  non-enforcement), certificate-sequence monotonicity absent (hunt-e1 #3), §11 media-type version
  enforcement absent (hunt-e2 #2; I independently re-confirmed empirically), malformed-address
  500 on the public route (seam-s1 #4; I independently re-confirmed empirically), 401
  `LATTICE_UNAUTHORIZED` for structural validation failures (hunt-a1 #6), transport TypeError /
  redirect SSRF / unbounded unresolved-domain set (hunt-b1b, seam-s2).
- Finding 1 is **gated** behind hunt-b1b #1 (re-verified in this pass's venv): the daemon cannot
  currently reach the pin-overwrite upsert because `resolver.resolve()` raises TypeError first
  and `start()` propagates. The finding keeps its severity; a repair of the transport fault that
  ignores this ships the pin overwrite underneath.

## Bound

- `docs/LATTICE_SYSTEMD.md` and `docs/ARCHITECTURE.md` were not in the assigned set and were
  not compared (LATTICE_SYSTEMD.md is the deployment companion to `deploy/` — a future pass could
  diff its credential/unit claims against `lattice.service`).
- No live Nginx/systemd execution (macOS host) — deploy files were compared textually only.
- `tests/` were read only where needed to confirm fixtures; no test-suite-wide drift audit.
- The `pyproject.toml`/build packaging surface was not in scope.
