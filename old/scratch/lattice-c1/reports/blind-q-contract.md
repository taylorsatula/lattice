# blind-q-contract — normative documents vs code

Pass type: blind third pass (target withheld). Scope read end-to-end:
`docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`, `docs/ADDRESSING.md`, `docs/KEY_MANAGEMENT.md`,
`docs/MIGRATIONS.md`, `docs/LATTICE_SYSTEMD.md`, `docs/ARCHITECTURE.md`, `docs/LOOSE_ENDS.md`,
`docs/AGENTS.md`, `AGENTS.md`, `deploy/lattice.nginx.conf`, `deploy/lattice.service`, and the
code under `lattice/` (`api.py`, `runtime.py`, `resolution.py`, `identity.py`,
`protocol/{constants,models,signing}.py`, `topology.py`, `gossip.py`, `messages.py`, `peers.py`,
`canonical.py`, `encoding.py`, `addressing.py`, `config.py`, `cli.py`, `storage/{migrations,connection,cache}.py`,
`storage/repositories.py`, `migrations/durable/001_initial.sql`).

Neutral question: where do the normative documents and the code disagree. Every finding below is a
literal document-vs-code divergence with both sides quoted and a stated direction (code wrong /
document wrong). Each finding states its reachability kind. Executable probes were run only where
reasoning could not settle the question (strict-JSON parsing of FastAPI bodies, RFC 8785
behaviour); nothing was modified except this report.

---

## Findings

### 1. [M] A `rejected` durable-custody receipt is treated as an *invalid* receipt and retried — the sender never honors the documented "final" rejection

- Location: `lattice/runtime.py:_send_outbound_message` (lines 976–1000); producer of the rejected
  receipt is `lattice/api.py:receive_message` lines 292–301 via
  `lattice/messages.py:InboundMessageService.build_receipt`.
- Document (PROTOCOL.md §8, quoted verbatim):
  > "A `rejected` receipt indicates the destination node will not take custody (e.g., recipient
  > blocked, message malformed after signature check). A `202 Accepted` with a rejected receipt is
  > final."
  THREAT_MODEL.md invariant 5:
  > "A signed HTTP 202 receipt transfers retry ownership to the destination node. The sender stops
  > retrying."
- Code (runtime.py:983–1000):
  ```python
  if (data.get("message_id") != message_id
      or data.get("node_id") != to_node_id
      or data.get("status") != "accepted"):
      ...
      self._outbound.record_failure(message_id, owner, retryable=True)
  ```
  Only `status == "accepted"` is accepted; a protocol-valid `status == "rejected"` receipt falls
  into the invalid branch and is rescheduled (`retryable=True`). The same file's own comment
  (`runtime.py:63–64`) says the rejection "is final and the sender stops retrying", contradicting
  its delivery code.
- Trigger: destination has the sender blocked (`BlockedSenderError`, api.py:294–300) or custody
  insert fails (`CustodyError`, api.py:335–343). Destination returns `202` + signed `rejected`
  receipt; the sender's next `_run_outbound_delivery` retries instead of marking terminal.
- Frequency: DEMONSTRATED. Population = outbound deliveries; cadence = every retry cycle for a
  message whose destination rejects custody (blocked sender is a normal operator action; custody
  insert failure is a normal error path). Each such message is retried up to `RetryPolicy.max_attempts`
  (messages.py:44, default 10) before it is finally marked failed, burning the documented finality.
- Outcome: wrong custody semantics — the sender retains and re-sends content for a message the
  destination has terminally refused, contrary to §8 and invariant 5. Content‑minimization is
  delayed as well.
- Reachability kind: PRODUCTION.
- Confidence: traced (mechanism + trigger). Frequency population traced; exact collision
  count unmeasured.

### 2. [M] Operational-certificate expiry and certificate-sequence monotonicity (PROTOCOL.md §3.3 MUST) are not enforced on the pin, candidate-verification, or inbound-message paths

- Location: `lattice/resolution.py:WellKnownResolver.resolve_with_ip` lines 103–110;
  `lattice/topology.py:TopologyService._verify_against_well_known` lines 320–331;
  `lattice/runtime.py:RuntimeCoordinator.verify_inbound_message` lines 650–659 (via
  `lattice/protocol/signing.py:verify_message`). Sequence storage: `lattice/peers.py:PeerStore.transition`
  → `repositories.py:transition_peer` (line 274, plain `= ?`) and `record_operational_key`
  (lines 297–318, `ON CONFLICT ... DO UPDATE`, no ordering check).
- Document (PROTOCOL.md §3.3):
  > "A daemon MUST reject a certificate whose `valid_until` is in the past, whose `sequence` is
  > not greater than the previously accepted certificate for that node, or whose signature does
  > not verify with the root public key matching `node_id`."
  PROTOCOL.md §6:
  > "Reject if `sequence` is not greater than the last accepted card from this node."
- Code: only `verify_gossip_sender_card` calls `cert.is_valid_at` (`runtime.py:564`). The pinning
  path (`resolution.py:107`), candidate verification (`topology.py:322`), and inbound-message
  verification (`runtime.py:658` → `signing.verify_message` → `cert.verify`) call only
  `OperationalCertificate.verify()` (signature) and never `is_valid_at()`. No code path anywhere
  compares a certificate/card `sequence` to the previously stored one; `grep -rn
  current_certificate_sequence` shows the value is only written, never compared.
- Trigger: a well-known document (or inbound message) carrying an operational certificate whose
  `valid_until` is in the past is accepted and pinned; a replayed older `operational_certificate`
  with a lower `sequence` overwrites the peer's `current_certificate_sequence`.
- Frequency: DEMONSTRATED mechanism. Population = every well-known resolution/pin and every
  inbound message from a pinned node; the expired-ceremony window is reached whenever a node's
  certificate lapses before it rotates (KEY_MANAGEMENT.md tells operators to rotate periodically,
  so a lapsed cert is a normal operational state).
- Outcome: a root-signed but expired operational certificate still authorizes traffic; operational
  rotation/expiry is not a hard boundary. This is the documented "bounded lifetime" control
  (THREAT_MODEL.md §1 "Operational private key … bounded lifetime") with no enforcement on the
  main paths.
- Reachability kind: PRODUCTION.
- Confidence: traced (mechanism, call sites, absence of `is_valid_at`). The sequence half is traced
  by absence of any comparison; the expired half is traced by call sites.

### 3. [M] Outbound delivery transfers custody on an unverified receipt — the sender never checks the receipt's operational signature (PROTOCOL.md §8 / THREAT_MODEL invariant 5 "signed")

- Location: `lattice/runtime.py:_send_outbound_message` lines 976–1005; no `verify_receipt`
  exists in `lattice/protocol/signing.py` (only `sign_receipt`, signing.py:62).
- Document (PROTOCOL.md §8): receipt field `signature` — "Operational signature"; THREAT_MODEL.md
  invariant 5 — "A **signed** HTTP 202 receipt transfers retry ownership…".
- Code comment claims verification that does not happen:
  ```python
  if response.status == 202:
      # Validate the signed custody receipt before transferring ownership.
      data = json.loads(response.data.decode("utf-8"))
      if (data.get("message_id") != message_id
          or data.get("node_id") != to_node_id
          or data.get("status") != "accepted"):
  ```
  It parses the JSON and compares three fields; it never verifies `signature` against the
  destination's operational certificate. `docs/LOOSE_ENDS.md` similarly asserts the body is a
  "signed JSON receipt".
- Trigger: any 202 delivery response. A response whose body has matching `message_id`/`node_id`/
  `status` but no valid signature causes `record_success` → durable custody is considered
  transferred and content erased.
- Frequency: DEMONSTRATED. Population = every outbound delivery attempt; the check is exercised on
  every successful delivery, so the missing verification is not an edge case.
- Outcome: custody ownership is transferred (and content erased) on an unauthenticated
  acknowledgment. Bounded by the transport requirement that the endpoint be the pinned HTTPS
  address (`resolution.py`/`runtime.peer_endpoint_for_node`), so the practical attacker is an actor
  who can answer TLS for the pinned endpoint or a buggy/forging peer; the protocol's own
  defense-in-depth (the signed receipt) is absent.
- Reachability kind: PRODUCTION.
- Confidence: traced (call site; absence of any receipt-verify call). The exploitability of the
  gap depends on TLS trust and is SUSPECTED (upstream TLS unverifiable here).

### 4. [L] §9 error-code table is not implemented; the codes the daemon actually emits are undocumented

- Location: `lattice/protocol/constants.py` lines 34–64 (`_PROBLEM_BASE`, `PROBLEM_CODE_*`);
  emitted via `lattice/api.py:_STATUS_PROBLEM_MAP` (lines 76–86) and `_problem`.
- Document (PROTOCOL.md §9) — "The `code` field is stable and machine-readable. Clients SHOULD use
  `code`…": `LATTICE_INVALID_SIGNATURE`, `LATTICE_UNKNOWN_NODE`, `LATTICE_EXPIRED_CERTIFICATE`,
  `LATTICE_RATE_LIMITED`, `LATTICE_MESSAGE_TOO_LARGE`, `LATTICE_INVALID_ADDRESS`,
  `LATTICE_DOMAIN_BINDING_MISMATCH`.
- Code emits: `LATTICE_BAD_REQUEST`, `LATTICE_UNAUTHORIZED`, `LATTICE_FORBIDDEN`,
  `LATTICE_NOT_FOUND`, `LATTICE_LENGTH_REQUIRED`, `LATTICE_TOO_LARGE`, `LATTICE_RATE_LIMITED`,
  `LATTICE_SERVICE_UNAVAILABLE`, `LATTICE_INTERNAL_ERROR`. Set intersection is exactly
  `{LATTICE_RATE_LIMITED}`. Concretely, a signature failure returns `401` →
  `{"code":"LATTICE_UNAUTHORIZED"}` (api.py:302), where §9 names `LATTICE_INVALID_SIGNATURE`; a
  413 returns `LATTICE_TOO_LARGE`, not `LATTICE_MESSAGE_TOO_LARGE`; a 403 ownership rejection
  (api.py:326–334) returns `LATTICE_FORBIDDEN`, not `LATTICE_DOMAIN_BINDING_MISMATCH`.
- Trigger: any error response on a public route.
- Frequency: DEMONSTRATED. Population = every rejected request; e.g. every rate-limited peer, every
  oversized body, every bad message.
- Outcome: a client written to §9 cannot recognize any error except rate limiting. Direction: code
  does not emit the documented codes and the document lists codes nothing emits — both sides are
  wrong. Bounded by the doc's own hedge "Example codes"; the normative sentence is the "stable
  machine-readable `code`" claim.
- Reachability kind: PRODUCTION.
- Confidence: traced (set comparison, command in Enumeration).

### 5. [L] §4.1 strict-JSON rules are not applied to public-route request bodies (FastAPI's default parser accepts duplicate keys, `NaN`, and out-of-I-JSON-range integers)

- Location: `lattice/api.py:receive_gossip` (line 242) and `receive_message` (line 280) — the body
  is bound as `dict[str, Any]`, parsed by Starlette's `Request.json()`; `strict_json_loads`
  (`lattice/canonical.py:44`) is imported only by `lattice/resolution.py`.
- Document (PROTOCOL.md §4.1):
  > "Before canonicalization or validation, a JSON payload MUST be parsed with these restrictions:
  > Duplicate object keys MUST be rejected. Numbers MUST be within the I-JSON safe integer range…"
- Probe (`.venv/bin/python`, real FastAPI/Starlette):
  - `{"a": 1, "a": 2}` → `200`, parsed as `{"a": "2"}` (duplicate silently collapsed, last wins).
  - `{"a": NaN}` → `200`, `nan` accepted.
  - `{"a": 99999999999999999999}` → `200`, integer far outside the I-JSON safe range accepted.
  `strict_json_loads` rejects all three (tests/test_canonical.py:11–27) but is never on this path.
- Trigger: any public POST body containing one of the constructs.
- Frequency: DEMANDED but narrow: population = every gossip/message request; the malformed-body
  fraction is attacker-chosen. Mechanism DEMONSTRATED; the rate at which conformant peers produce
  such bodies is low (L).
- Outcome: parser-differential surface (an implementation that rejects duplicates computes/accepts
  a different object than one that last-wins); a body that §4.1 says MUST be rejected is processed.
  Direct signature bypass was checked and not found: `rfc8785` raises `ValueError` on NaN/out-of-range
  (`FloatDomainError`/`IntegerDomainError` subclass `ValueError`), and `verify_inbound_message`
  catches `ValueError`, so the malformed value degrades to `401` on the signature path.
- Reachability kind: PRODUCTION.
- Confidence: traced (probe).

### 6. [L] §11 media-type/version rejection is not implemented (requests and well-known responses)

- Location: `lattice/api.py` (no `Content-Type`/`Accept` inspection anywhere; only
  `content-length`, `authorization`, `x-forwarded-for` are read — grep in Enumeration);
  `lattice/resolution.py:57–59` checks only the substring.
- Document (PROTOCOL.md §11):
  > "Implementations MUST reject requests with an unsupported or missing `version` parameter in the
  > `Content-Type` or `Accept` header, as applicable."
  §1: "The protocol uses `application/vnd.lattice+json; version=1`".
- Code: `resolve_with_ip` accepts any content type containing `application/vnd.lattice+json`
  (so `application/vnd.lattice+json` with no `; version=1` passes); the public routes never inspect
  the request `Content-Type`/`Accept` at all — a body with `Content-Type: application/json` (no
  version) is parsed and processed.
- Trigger: any request to a public route with a missing/wrong version parameter.
- Frequency: DEMONSTRATED mechanism; population = every public request, though conformant peers
  send the version (L).
- Outcome: forward-compatibility boundary is unenforced; a v2 client's request is processed as v1.
  Direction: code wrong (MUST unimplemented).
- Reachability kind: PRODUCTION.
- Confidence: traced (grep; probe showed `application/json` accepted).

### 7. [L] The §6 peer-card schema omits `root_public_key`, which the code requires and validates with `extra="forbid"`

- Location: `lattice/protocol/models.py:PeerCard` (lines 138–165, fields include
  `root_public_key`; `model_config = ConfigDict(extra="forbid")`);
  `lattice/gossip.py:build_own_card` line 207 emits `"root_public_key": public_key_b64url(...)`.
- Document (PROTOCOL.md §6) peer-card table fields: `kind`, `node_id`, `domain`,
  `operational_certificate`, `endpoints`, `sequence`, `issued_at`, `expires_at`, `signature` —
  no `root_public_key`. §6 validation says:
  > "Verify the operational certificate against the root public key derived from `node_id`."
- Code: `runtime.py:verify_gossip_sender_card` reads `model.root_public_key` and calls
  `derive_node_id(root_key) == model.node_id`; a card that follows §6 literally (no
  `root_public_key`) fails `PeerCard.model_validate` and is rejected as "invalid card"
  (`gossip.py:105–116`).
- Trigger: any peer card produced to the §6 field list.
- Frequency: DEMONSTRATED as a schema mismatch; in a single-implementation deployment no peer
  produces it, so the actual failure population is other implementations (currently zero) —
  L.
- Outcome: direction — **the document is wrong**. §6's field table is incomplete, and its
  validation sentence is unimplementable (a node ID is a one-way hash of the root key and cannot
  yield it). A conformant third party cannot gossip with this daemon.
- Reachability kind: PRODUCTION (protocol boundary), but no current producer.
- Confidence: traced.

### 8. [L] THREAT_MODEL §4.6 "Audit metadata is retained only 30 days" has no retention path

- Location: `lattice/storage/repositories.py:AuditLogRepository` (lines 1128–1152) has only
  `insert`; no delete/prune. `runtime.py` writes audit rows (`_audit_inbound_accepted`,
  `_audit_outbound_*`, `_audit_webhook_*`, lines 831–892) and the only maintenance sweep
  (`_run_expiry_cleanup`, runtime.py:1131–1133) touches outbound/topology, not `audit_log`. Schema
  `audit_log` has no TTL trigger (001_initial.sql).
- Document (THREAT_MODEL.md §4.6):
  > "Terminal message content and extensions are erased. Audit metadata is retained only 30 days."
- Trigger: continuous — every accepted/failed message and webhook outcome writes a durable audit
  row that is never removed.
- Frequency: DEMONSTRATED. Population = every audited event; cadence = every delivery/accept.
- Outcome: audit metadata accumulates past the documented 30-day boundary (privacy-retention and
  unbounded-growth mismatch). Direction: code wrong.
- Reachability kind: PRODUCTION.
- Confidence: traced (absence of any delete on `audit_log`; command in Enumeration).

### 9. [S-] §5.1 "MUST regenerate [the well-known] when the operational certificate or endpoints change" has no code path for the endpoint case

- Location: `lattice/cli.py:cmd_serve` lines 654–668 serve the on-disk `well-known.json` verbatim;
  `cmd_init` (lines 187–211) and `cmd_keys_rotate_operational` (lines 800–824) regenerate it for a
  new certificate; nothing regenerates it when `server.public_base_url` changes.
- Document (PROTOCOL.md §5.1):
  > "The daemon MAY cache a pre-signed well-known document. It MUST regenerate it when the
  > operational certificate or endpoints change."
- Code: the daemon holds no root key (invariant 2 / KEY_MANAGEMENT.md), so it cannot regenerate;
  the only endpoint source at runtime is `config.gossip_endpoint`/`messages_endpoint` used by
  `gossip.build_own_card`, which can advertise different endpoints than the served `well-known.json`.
- Trigger: operator edits `server.public_base_url` in `/etc/lattice/config.toml` and restarts
  (no `lattice init`/`rotate-operational` rerun). The served well-known keeps the old endpoints
  while peer cards advertise the new ones.
- Frequency: LATENT — the population is "operators who change the public base URL post-init"; no
  cadence can be grounded from the tree, so capped at L. Direction: document/architecture conflict
  (the MUST cannot be met under invariant 2).
- Outcome: peers that resolve the domain learn stale endpoints; inbound delivery is directed at the
  old URLs.
- Reachability kind: GATED behind an operator configuration change; not reachable through any
  current test or normal request.
- Confidence: traced (no regeneration call site); frequency latent.

---

## Checked and clean

- **Public routes, three-way.** Doc (`PROTOCOL.md` §1, §5), `lattice/protocol/constants.py`
  (`ROUTE_WELL_KNOWN/GOSSIP/MESSAGES`), `lattice/api.py` decorators, and
  `deploy/lattice.nginx.conf` `location =` blocks all agree exactly. Admin/health routes are
  loopback-proxied in nginx and gated by `require_admin`; both intended.
- **Body-size limits.** `MAX_GOSSIP_BODY_BYTES=256*1024`, `MAX_MESSAGE_BODY_BYTES=128*1024`,
  nginx `client_max_body_size 256k`/`128k`, and PROTOCOL §10 all agree (k = 1024).
- **Signature preimage.** `canonical.py:signature_preimage` matches PROTOCOL §4.3 byte-for-byte
  including the normalized media type constant.
- **Node-ID derivation.** `identity.derive_node_id` = `"lat_" + b32lower(SHA-256(b"lattice-node-id-v1\0" || raw))`
  matches §3.2; `NODE_ID_RE = ^lat_[a-z2-7]+$` matches the alphabet; the §3.2 example string is a
  valid base32 body.
- **Signed-object field schemas that do match.** `WellKnownDocument` (§5.1), `Message` (§7, incl.
  default TTL 86400, max 604800, content 64 KiB, extension 16 KiB), `Receipt` (§8),
  `OperationalCertificateModel` (§3.3, plus the expected `signature` column the table elides),
  `Transfer`, `Rotation`.
- **`contact_card`.** PROTOCOL §4.4 and ADDRESSING.md contact cards are implemented in
  `cli.cmd_contacts_export/import/list` with `contact_card` signing and a durable `contacts` table —
  no divergence.
- **Receipt bytes idempotency.** §8's "return the identical signed receipt bytes" is honored:
  `InboundMessageRepository.get_existing_receipt` returns the stored receipt and
  `InboundMessageService.accept` short-circuits on a duplicate `message_id`.
- **Migration runner ordering/refusal.** `MIGRATIONS.md` steps 1, 2, 4, 5 are implemented
  (`integrity_check`/`foreign_key_check`, pre-migration backup, `user_version == number` check,
  `current > target` refusal). Step 3 ("single transaction") is the weak one — see Design risks.
- **Cache recreation.** `initialize_cache_db` hashes the schema and deletes/recreates on mismatch,
  matching MIGRATIONS.md.
- **Deploy credentials.** `deploy/lattice.service` `LoadCredentialEncrypted=` names
  (`operational_key`, `webhook_bearer`, `admin_bearer`) match KEY_MANAGEMENT.md and
  `credentials.py`; the daemon loads only the operational key (`cmd_serve`), and no serving path
  touches the root private key.
- **Problem-Details envelope shape.** `type` = `https://lattice.dev/errors/<code>`, media type
  `application/problem+json`, `code` field present — matches §9's shape (values diverge, Finding 4).

## Enumeration

```bash
# routes: doc vs constants vs api vs nginx
grep -oE '`(GET|POST) [^`]+`' docs/PROTOCOL.md | tr -d '`' | sort -u
grep -E 'ROUTE_' lattice/protocol/constants.py
grep -nE '@app\.(get|post)' lattice/api.py
grep -E 'location' deploy/lattice.nginx.conf
```
Dispositions: all three sets identical → examined-clean (no divergence).

```bash
# error codes: doc table vs constants vs actual emissions
grep -oE 'LATTICE_[A-Z_]+' docs/PROTOCOL.md | sort -u
grep -oE 'LATTICE_[A-Z_]+' lattice/protocol/constants.py | sort -u
```
Dispositions: intersection `{LATTICE_RATE_LIMITED}` only → Finding 4. Doc-only:
`INVALID_SIGNATURE`, `UNKNOWN_NODE`, `EXPIRED_CERTIFICATE`, `MESSAGE_TOO_LARGE`,
`INVALID_ADDRESS`, `DOMAIN_BINDING_MISMATCH`. Code-only: `BAD_REQUEST`, `UNAUTHORIZED`,
`FORBIDDEN`, `NOT_FOUND`, `LENGTH_REQUIRED`, `TOO_LARGE`, `SERVICE_UNAVAILABLE`,
`INTERNAL_ERROR`.

```bash
# signed kinds: doc §4.4 vs literals passed to sign/verify helpers
sed -n '/### 4.4 Allowed kinds/,/## 5/p' docs/PROTOCOL.md | grep -oE '^\| `[a-z_]+`' | tr -d '|` '
grep -rhoE '(sign_object|sign_with_root|verify_object|verify_with_root)\([^,)]+,\s*"[a-z_]+"' lattice/ --include=*.py \
  | grep -oE '"[a-z_]+"$' | tr -d '"' | sort -u
```
Dispositions: `webhook_envelope` is signed/verified in code but absent from §4.4 → side discovery
(webhook-only object, deliberately outside the wire document; not reported as a defect). All other
kinds match.

```bash
# certificate validity / sequence enforcement sites
grep -rn "is_valid_at" lattice/            # only runtime.py:564
grep -rn "current_certificate_sequence" lattice/ | grep -v "def \|import"
```
Dispositions: only the gossip-sender path checks validity; sequence is only ever written →
Finding 2.

```bash
# audit retention
grep -rn "audit_log\|recorded_at" lattice/ | grep -i "delete\|prune\|expire"
```
Dispositions: no delete/prune on `audit_log` → Finding 8.

```bash
# Content-Type / Accept on public routes
grep -n "headers\.get\|content_type" lattice/api.py lattice/resolution.py
```
Dispositions: api.py reads only `content-length`, `authorization`, `x-forwarded-for`; resolution
checks a substring → Finding 6.

```bash
# HTTP 411 emitted but absent from §9
grep -n "411" lattice/api.py lattice/protocol/constants.py docs/PROTOCOL.md
```
Dispositions: `require_content_length` raises 411 with `LATTICE_LENGTH_REQUIRED`; §9's table does
not list a 411 code → side discovery 4.

## Design risks (max 2)

1. **Durable migrations are not applied in a single transaction.** `MIGRATIONS.md` step 3 says
   "Applies each missing migration in a single transaction", but
   `storage/connection.py:execute_script` is `with conn: conn.executescript(script)`, and
   `durable/001_initial.sql` (and the runner) contain no `BEGIN`/`COMMIT`. Python's `executescript`
   performs no implicit transaction control beyond committing a pending one, so a mid-script failure
   leaves partially created schema while `user_version` stays at the old value. Today's script is
   idempotent (`IF NOT EXISTS`), so re-running recovers; a future non-idempotent migration
   (`ALTER TABLE`) would leave an unrecoverable half-state reported as "not applied".
2. **`ARCHITECTURE.md` claims Nginx "owns … IP rate limits".** `deploy/lattice.nginx.conf` has no
   `limit_req_zone`/`limit_req`. `docs/LOOSE_ENDS.md` Phase 9 already records this, so it is a known
   open item rather than a new finding; the code-side per-peer token buckets are the only quota.

## Side discoveries (labeled separately; not folded into a verdict)

- **SD1 [L] Protocol responses carry the wrong media type.** `api.receive_gossip` (line 265) and
  the 202 receipt response (line 354) return `JSONResponse(...)` with no `media_type`, so
  `Content-Type: application/json`, while `well_known` uses `MEDIA_TYPE`. PROTOCOL §1 says the
  protocol uses `application/vnd.lattice+json; version=1`. Direction: code wrong (or doc silent).
  Frequency: every gossip/message response. Fix-direction constraint: set `media_type=MEDIA_TYPE`
  on protocol responses without changing the Problem-Details responses (which must stay
  `application/problem+json`).
- **SD2 [S-] `webhook_envelope` is a signed object kind absent from PROTOCOL §4.4's "Allowed
  kinds".** `runtime.py:1044–1056` signs and `signing.verify_webhook_envelope` verifies it. It is a
  loopback-integration object, not a wire object, so the omission is plausibly deliberate; flagged
  only because §4.4 reads as exhaustive.
- **SD3 [L] HTTP 411 (`LATTICE_LENGTH_REQUIRED`) is emitted but absent from §9's code table.**
  `api.require_content_length` raises 411 when `Content-Length` is missing; §9 has no 411 row.
  Direction: doc incomplete.
- **SD4 [S-] `config.webhook.bearer_credential_name` is parsed but ignored.** `cmd_serve` hardcodes
  `_credential_path("webhook_bearer", ...)` (cli.py:671), so a configured alternate credential name
  has no effect. No document states the key is configurable, so this is a code-only inconsistency;
  needs one more pass.

## Bound

- **Live infrastructure unverifiable.** No TLS, Nginx, systemd, or real peer was exercised; the
  receipt/TLS mitigation bounds in Findings 1–3 and SD1 are reasoned from the transport contract,
  not observed. Marked SUSPECTED where impact depends on it.
- **Upstream strictness unverifiable.** Wording like §9 "Example codes" and the doc's §6 field
  table leave the intended direction (code wrong vs doc wrong) genuinely ambiguous in Findings 4
  and 7; I state both sides rather than assume.
- **Third-party implementations.** Findings 5, 6, 7 describe protocol-boundary behavior whose real
  impact appears only against a conformant non-Lattice implementation; none exists in the tree, so
  those populations are latent.
- **Frequency within retry/quota windows.** Counts (e.g. how often custody insert fails, how often a
  certificate lapses before rotation) were not measured; only the populations and triggers are
  traced.

## Falsification attempt (self-refutation)

- Finding 1 was checked against `tests/test_integration.py` (the "message stays pending" assertion
  is for the 503 cold-sender path, not for a 202 rejected receipt) and against
  `tests/test_runtime.py:283` (which mocks only a `status:"accepted"` receipt). No test asserts the
  rejected-receipt-as-final behavior, so it is not a deliberate design.
- Finding 3 was checked for a `verify_receipt` helper in every module; none exists (`grep -rn
  verify_receipt` empty). The only receipt signature check in the tree is in
  `tests/test_vectors.py`, which verifies a receipt the test signs, not a received one.
- Finding 2 was checked for an indirect `is_valid_at` in the model validators (`OperationalCertificateModel`
  only checks `tzinfo`) and in `PeerRepository.ensure_root_history`/`record_operational_key` (no
  time comparison). Absent.
- Findings 4, 6, 7 were checked for a middleware or response-model layer that might perform the
  missing enforcement (`create_app` adds no middleware; no custom response class). None.
