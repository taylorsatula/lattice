# hunt-e2 — canonicalization, encoding & protocol models

Pass: blind hunter (generative discovery). Assigned files read end to end:
`lattice/canonical.py`, `lattice/encoding.py`, `lattice/protocol/signing.py`,
`lattice/protocol/models.py`, `lattice/protocol/constants.py`,
`lattice/protocol/__init__.py`. Supporting files read for tracing only:
`identity.py`, `api.py`, `gossip.py`, `topology.py` (100–340), `runtime.py`
(partial), `messages.py`, `resolution.py` (30–110), `cli.py` (excerpts),
`crypto.py` (excerpt), `docs/PROTOCOL.md`, `tests/vectors/`.

Neutral question answered: **the JCS layer itself is sound, but two
implementations CAN disagree on the bytes that are signed**, in three ways:
the strict parse rules of §4.1 are not applied to inbound route bodies, the
media-type version rule of §11 is not enforced, and signature verification on
the certificate/peer-card paths is computed over re-serialized normalized
objects rather than the received bytes.

## Findings

### 1. [L] Public routes bypass PROTOCOL.md §4.1 strict JSON parsing rules

- Location: `lattice/api.py:create_app.receive_gossip` / `receive_message`
  (FastAPI default body parsing); contrast `lattice/canonical.py:strict_json_loads`
- Evidence: `async def receive_gossip(body: dict[str, Any], request: Request)`
  — the route bodies are parsed by Starlette's `json.loads`, while
  `strict_json_loads` ("Duplicate object keys are rejected. NaN, Infinity…
  UTF-8 is enforced") is called from exactly one place in the tree:
  `resolution.py:62` (the outbound well-known fetch).
- Trigger: PRODUCTION — any remote HTTP peer POSTs to `/lattice/v1/gossip` or
  `/lattice/v1/messages`. Verified live against a FastAPI app mirroring the
  route signatures (repo venv):
  - body `{"cards": [], "cards": [{"a":1}]}` → **200, last key wins**
    (`strict_json_loads` on the same text raises `duplicate key: 'a'`);
  - body containing a bare `NaN` literal → accepted by the parser (in
    Lattice it then reaches `canonicalize`, which raises
    `rfc8785.CanonicalizationError`, misreported as
    401 "message signature invalid" — a parse error reported as a signature
    failure);
  - body bytes encoded UTF-16 with the lattice media type → **200**
    (`json.loads(bytes)` auto-detects UTF-16; doc: "UTF-8 MUST be enforced").
  - I-JSON safe-integer range (§4.1 MUST): not checked at parse;
    `strict_json_loads`' docstring claims "validated during model
    construction", but no model bounds integers above
    (`sequence: int = Field(ge=1)`, `Extension.data: Any`); an integer ≥ 2^53
    raises mid-verification inside `rfc8785` instead.
- Frequency: DEMONSTRATED — population is every remote request to the two
  public routes; the specific triggers (duplicate keys, NaN, UTF-16) are
  produced only by non-conforming or hostile senders, which the threat model
  explicitly includes (federated peers are outsiders). Normal conforming
  clients never emit them.
- Outcome: wire-contract MUST violations are accepted rather than rejected.
  No signature/validation split exists (the same last-wins parsed dict is both
  model-validated and signature-verified), so the harm is bounded to
  non-conforming-input acceptance, misreported error codes, and
  cross-implementation divergence on what the protocol says must be rejected.
- Confidence: traced — mechanism, trigger, and frequency all demonstrated
  live; nothing unproven.

### 2. [L] No media-type/version enforcement on public routes (§11 MUST)

- Location: `lattice/api.py:receive_gossip` / `receive_message`
  (no Content-Type inspection anywhere in `create_app`)
- Evidence: doc §11: "Implementations MUST reject requests with an
  unsupported or missing `version` parameter in the `Content-Type` … header".
  The routes only check `Content-Length` (`require_content_length`).
- Trigger: PRODUCTION — a remote peer POSTs
  `Content-Type: application/vnd.lattice+json; version=2` (or plain
  `application/json`) to `/lattice/v1/messages`. Verified live: version=2 body
  is processed normally (200), not rejected. A missing Content-Type yields a
  generic FastAPI 422→400, not the protocol's version-mismatch rejection.
- Frequency: DEMONSTRATED — any remote request with a non-conforming media
  type; in-tree senders always send version=1, so the population is
  misconfigured or future/foreign clients.
- Outcome: the public routes accept what their contract forbids — a
  version-parameter mismatch (e.g. a future v2 client) is silently processed
  by v1 schema rules instead of being rejected. No wrong custody decision
  follows today (models still validate the body), hence L.
- Confidence: traced — mechanism and trigger demonstrated; frequency grounded
  (no in-tree producer of a wrong version today).

### 3. [L] Signature preimages computed over re-serialized objects, not the received bytes — two in-tree verification paths disagree

- Location: `lattice/identity.py:OperationalCertificate.verify` (reconstructs
  via `to_dict()` → `_format_ts` / `public_key_b64url` re-encoding);
  `lattice/topology.py:_verify_against_well_known`
  (`verify_peer_card(card.model_dump(mode="json"), …)`); contrast
  `lattice/runtime.py:verify_gossip_sender_card` (`verify_object(…, card, …)`
  over the **raw** dict)
- Evidence: `signed = self.to_dict(); del signed["signature"]; canonical =
  canonicalize(signed)` — the preimage is built from parsed-then-reformatted
  fields (`_format_ts` uses `strftime("%Y-%m-%dT%H:%M:%SZ")`, silently
  dropping microseconds; the operational public key is re-encoded from the
  parsed key). The topology path likewise verifies the pydantic round-trip
  (`model_dump`) while the runtime rate-limit path verifies the raw dict.
- Trigger: PRODUCTION — a remote peer's certificate or peer card.
  Demonstrated live with the repo's own code:
  1. **Certificate wire text is not signature-bound**: a cert signed by the
     root over `valid_until "2026-01-31T12:30:00Z"` verifies unchanged when
     the transmitted text is rewritten to `"2026-01-31T17:30:00+05:00"` or
     `valid_from` to `"2026-01-01T00:00:00.5Z"` (`cert.verify` passes; a
     raw-byte verification of the mutated dict fails with SignatureError).
  2. **Two paths disagree**: a peer card genuinely signed over
     `issued_at "2026-01-15T10:30:00+00:00"` (RFC 3339-legal; doc §2 asks for
     Z) passes `verify_gossip_sender_card` (raw dict → OK) but **fails**
     candidate verification in `_verify_against_well_known`
     (`model_dump` re-emits `"…T10:30:00Z"` → SignatureError) — the peer can
     never become verified.
- Frequency: DEMONSTRATED for mechanism; trigger population: any hostile peer
  (self-generated root keypair suffices) for the malleability direction, and
  any non-conforming emitter of offset/fractional timestamps for the
  divergence direction. The repo's own signers always emit `Z` second
  precision, so direction 2 needs a foreign/non-conforming implementation.
- Outcome: the transmitted certificate/card bytes are not bound by any
  signature — encodings a spec-conforming raw-byte verifier rejects are
  accepted here and re-propagated by gossip (`receive_batch` stores and
  re-sends the raw wire card). No value-level bypass exists (all mutations
  that survive normalization parse to the same instant, except sub-second
  timestamp wiggle from the `_format_ts` truncation), so the harm is
  cross-implementation divergence and the permanent-verification-failure
  case above — hence L, not M.
- Confidence: traced — mechanism demonstrated end-to-end with the repo's own
  sign/verify functions; frequency for the divergence direction depends on a
  non-conforming sender (stated above).

## Checked and clean

- `signature_preimage` byte layout matches doc §4.3/§12.2 exactly:
  `"lattice-signature-v1\0" || kind || "\0" || media_type || "\0" || bytes`,
  media type identical to `MEDIA_TYPE` in constants.py.
- Signature-field exclusion: `sign_object`/`verify_object`/`sign_with_root`/
  `verify_with_root` strip `signature`; `verify_transfer` strips
  `signature`+`new_signature`; `verify_rotation` strips all three signature
  fields — matches the vectors generator and doc §4.3.
- `rfc8785.dumps` (pinned venv) enforces UTF-16 key ordering, the I-JSON
  safe-integer domain, string keys, and rejects lone surrogates; every
  canonicalization site I traced catches the resulting `ValueError` or its
  propagation is bounded (message path → 401; gossip sender path → None;
  topology well-known verify → TopologyError with candidate removal).
- `strict_json_loads` itself correctly rejects duplicate keys, NaN,
  Infinity, -Infinity, and non-UTF-8 (verified live); duplicate-key rejection
  via `object_pairs_hook` is correct.
- `derive_node_id`: `"lat_" + b32lower_encode(sha256("lattice-node-id-v1\0" || raw))`
  matches doc §3.2, lowercase unpadded, prefix constant matches.
- `b32lower_encode` matches RFC 4648 lowercase unpadded.
- Pydantic models: all signed-object models use `extra="forbid"` and
  `Literal` kinds, so unknown fields cannot enter a signed object and kind
  values are pinned; timestamp validators require timezone-aware values;
  `NODE_ID_RE` accepts non-canonical lengths, but every verification boundary
  cross-checks `node_id` against `derive_node_id` output (cert.verify,
  verify_gossip_sender_card, _verify_against_well_known, resolution) —
  examined, fail-closed.
- Well-known fetch path (`resolution.py`) is the strongest path in the tree:
  strict parse → model validation → raw-dict signature verification.
- Receipts: `build_receipt` signs `model_dump(mode="json")` after placing a
  placeholder signature which `sign_object` strips; self-consistent;
  duplicate `message_id` returns the stored receipt dict unchanged.
- Webhook envelope signing (runtime `_run_webhook_delivery`): kind
  `webhook_envelope`, message dict passed through unmodified, metadata
  locally generated — self-consistent with `verify_webhook_envelope`.
- JCS/signature cross-implementation vectors exist (`tests/vectors/canonical.json`,
  `signatures.json`) and `test_vectors.py` asserts wrong-kind signature
  failure — the kind-binding property is tested.
- Problem-details constants match doc §9 (type URIs, codes, media type).

## Enumeration

Command (composed, closes the kind class):

```
grep -n 'Literal\["' lattice/protocol/models.py
grep -rn '"(well_known|operational_certificate|peer_card|message|receipt|block|contact_card|transfer|rotation|webhook_envelope)"' lattice/ tests/vectors/generate_vectors.py
grep -n '^| `[a-z_]*`' docs/PROTOCOL.md
```

Kind set — code vs `docs/PROTOCOL.md` §4.4 (9 doc kinds):

| kind | doc | model | sign/verify sites | disposition |
|---|---|---|---|---|
| `well_known` | ✓ | ✓ | signing.py:24/29, cli:164/175/810, topology:312, resolution:99 | examined-clean (raw-dict verify) |
| `operational_certificate` | ✓ | ✓ | identity.py:98/135/272, embedded in well_known/peer_card | **finding 3** (verify over reconstructed object) |
| `peer_card` | ✓ | ✓ | signing.py:34/44, gossip.py:206, runtime:566 (raw), topology:328 (model_dump) | **finding 3** (two paths disagree) |
| `message` | ✓ | ✓ | signing.py:49/59, runtime:606, messages | examined-clean (raw-dict verify) |
| `receipt` | ✓ | ✓ | signing.py:64, messages:309 | examined-clean |
| `block` | ✓ | ✓ | signing.py:67 `sign_block` | examined — sign helper exists, no daemon caller, no verify helper; kind consistent with vectors; no defect |
| `contact_card` | ✓ | **no model** | cli.py:310 sign, cli.py:367 verify (raw dict) | gap — see side discovery 2 |
| `transfer` | ✓ | ✓ | identity.py:200-203, cli:474 | examined-clean (multi-signature exclusion matches vectors) |
| `rotation` | ✓ | ✓ | identity.py:220-227, cli:776/785 | examined-clean (three-signature exclusion matches vectors) |
| `webhook_envelope` | **not in doc §4.4** | ✓ | signing.py:84, runtime:1047/1051 | doc/code drift — see side discovery 3 |

Kind strings at every sign/verify site agree with the model literals and the
doc; no mismatched kind at any call site.

Parsers/normalizers dispositioned: `strict_json_loads` (correct; unwired to
routes — finding 1), `canonicalize` (clean), `signature_preimage` (clean),
`b64url_encode`/`b32lower_encode` (clean), `b64url_decode` (lenient —
`validate=False` admits standard-alphabet chars, whitespace, and padded
forms; contributes to finding 3's encoding non-binding; no standalone defect
beyond that), `_parse_ts`/`_format_ts` (part of finding 3), pydantic model
validators (12 models — examined, clean except as noted).

## Design risks

1. Canonical timestamp bytes depend on pydantic's `model_dump(mode="json")`
   serializer output (finding-3 path) rather than a pinned format function in
   the protocol layer; a pydantic upgrade that changes datetime serialization
   would silently change signature preimages and break interop with
   previously signed objects.
2. `_format_ts` truncates microseconds while the certificate dataclass retains
   them, so the signed text and the in-memory validity window differ by a
   sub-second amount; self-consistent today but a standing trap for any code
   that later echoes the stored datetime instead of the signed text.

## Side discoveries

1. **Stuck-candidate retry loop via non-IdentityError escape** (out of
   assigned files; traced): `topology.py:_verify_against_well_known`
   (~line 313) and `resolution.py` (~line 106) wrap
   `OperationalCertificate.from_dict(...)`/`cert.verify(...)` in
   `except IdentityError` only. `from_dict` → `load_public_key_b64url` →
   `Ed25519PublicKey.from_public_bytes` raises plain `ValueError` for a
   wrong-length key, and the model validators pass it first because
   `encoding.b64url_decode` (validate=False) decodes e.g. `"abc"` to 2 bytes
   without error. The escaping ValueError is not a `TopologyError`, so
   `verify_candidate` never calls `remove_candidate`; `_run_verify_candidates`
   logs it and the candidate is retried every verify interval — each retry
   performing a full HTTPS fetch of the peer's domain plus an exception
   traceback — until the card's `expires_at` (≤ 7 days). Trigger requires only
   a self-generated root keypair, a gossiped card, and a served well-known
   document whose embedded certificate has a short `operational_public_key`;
   no valid signature needed on the certificate.
2. `contact_card` is a doc §4.4 kind signed and verified by `cli.py`, but has
   no protocol model: `cmd_contacts_import` checks only `kind` and
   `address`; `username`, `display_name`, `avatar_url` from the
   operator-supplied (outsider-authored) card file are not schema-validated or
   size-capped before storage in the contact book.
3. `webhook_envelope` is a signed kind in code (model, verify helper, runtime
   signer) absent from doc §4.4's allowed-kinds table — doc/code drift.
4. `resolution.py` (~line 59) accepts any Content-Type containing the
   substring `application/vnd.lattice+json` (e.g.
   `text/html; x="application/vnd.lattice+json"`), unlike the exact match the
   media-type contract implies.

## Bound

- Assigned files all read end to end; nothing skipped.
- Read for tracing only (not assignment-covered, so not exhaustively
  audited): identity.py, api.py, gossip.py, topology.py, runtime.py,
  messages.py, resolution.py, cli.py, crypto.py, storage/repositories.py
  (grep-level).
- Not opened: transport.py, webhook.py, network_policy.py, addressing.py,
  peers.py, credentials.py, migrations/ — out of assignment; tracing did not
  require them.
- No live daemon or network was run; HTTP-parse behavior verified against a
  minimal FastAPI app in the repo's pinned venv (fastapi/starlette versions
  from uv.lock), which mirrors `create_app`'s body-parsing setup (no custom
  body middleware exists in api.py).
- Enumeration pattern limitation: kind discovery used fixed string literals;
  a kind constructed dynamically (string concatenation) would not match — no
  such construction appears in the read files.
