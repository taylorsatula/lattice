# Orientation — identity / crypto / protocol / canonicalization trust core

## 1. Concept
This subsystem is the key-anchored trust root of Lattice. `lattice/canonical.py` defines strict JSON parsing, RFC 8785 JCS canonicalization, and the Ed25519 signature preimage; `lattice/crypto.py` wraps Ed25519 key I/O and verify; `lattice/identity.py` derives `lat_…` node IDs and implements certificate, transfer, and rotation verification; `lattice/protocol/{constants,models,signing}.py` hold the domain constants, Pydantic schemas, and per-kind sign/verify helpers. The trust boundary sits at the point untrusted bytes become a verified signed object: `resolution.py` (well-known), `runtime.py` (messages, gossip sender card, webhook), `topology.py` (peer-card verification). Everything inside this subsystem assumes the caller already holds a root public key that is pinned/derived; it authenticates, it does not establish trust in the root itself.

## 2. Invariants
- Immutable root identity: `RootIdentity` (identity.py) holds only a public key; `OperationalIdentity` holds the operational private key. No root private key in daemon types. Enforced by dataclass shape.
- Node ID derived from root key: `derive_node_id` (identity.py); callers re-derive and compare (`resolution.py`, `topology.py:_verify_against_well_known`, `runtime.py:verify_gossip_sender_card`).
- Signature covers canonical bytes minus `signature` only: `signature_preimage` (canonical.py); multi-sig statements strip all sig fields (`verify_transfer`, `verify_rotation`).
- Kind is domain-separated in the preimage: `signature_preimage(kind,…)`; kind is a caller argument, not read from the object.
- Strict parsing (dup keys, non-finite, UTF-8): `strict_json_loads` (canonical.py).
- I-JSON safe integer range: docs PROTOCOL.md §4.1 require it; **not enforced here** — docstring defers to model construction, no model enforces it.
- Certificate signed by root for the node ID: `OperationalCertificate.verify` (identity.py).
- Certificate validity window and sequence monotonicity: window via `OperationalCertificate.is_valid_at`; sequence monotonicity **not enforced anywhere** in the trust core (`current_certificate_sequence` is stored by `PeerRepository` but no comparison site was found).
- Certificate lifetime ≤ 90 days: enforced only at creation in `create_operational_certificate`, not at parse/verify.
- No root key in daemon: `RootIdentity` has no private field.

## 3. Mechanism inventory
- Signature preimage construction: `canonical.signature_preimage`.
- Canonicalization: `canonical.canonicalize` (delegates to `rfc8785.dumps`).
- Strict parsing: `canonical.strict_json_loads`, `_reject_duplicate_keys`, `_reject_non_finite`.
- Binary encoding: `encoding.b64url_encode/decode`, `b32lower_encode`.
- Node-ID derivation: `identity.derive_node_id`, `node_id_from_public_key_b64url`.
- Sign/verify primitives: `crypto.sign/verify`, `load_public_key_b64url`.
- Object signing/verifying: `identity.sign_with_root`, `verify_with_root`, `verify_object`, `OperationalIdentity.sign_object/verify_object`.
- Certificate create/parse/verify: `create_operational_certificate`, `OperationalCertificate.from_dict/to_dict/verify/is_valid_at`.
- Multi-sig statements: `identity.verify_transfer`, `identity.verify_rotation`.
- Kind dispatch/schema: `protocol/models.py` (one Pydantic class per kind), `protocol/signing.py` (per-kind wrappers).
- Constants: `protocol/constants.py` (`SIGNATURE_DOMAIN_PREFIX`, `NODE_ID_DOMAIN_PREFIX`, `MEDIA_TYPE`, limits).

## 4. Sanctioned idioms + exemplars
- **Signature preimage:** call `signature_preimage(kind, canonicalize(obj_without_signature))` — exemplar `identity.py:OperationalIdentity.sign_object` / `identity.py:verify_object`. Multi-sig exemplars: `identity.py:verify_transfer`, `identity.py:verify_rotation`. Divergence: `cli.py:cmd_keys_rotate_operational` builds `canonicalize(rotation)` before adding sig fields and reuses one preimage for all three — equivalent to the bare-object preimage only because no sig fields exist yet.
- **Certificate validation:** `certificate.verify(root_identity)` then `certificate.is_valid_at(now)` — exemplar `runtime.py:verify_gossip_sender_card`. Divergence: `resolution.py:WellKnownResolver.resolve_with_ip` and `topology.py:_verify_against_well_known` call only `cert.verify`, never `is_valid_at`; `protocol/signing.py:verify_peer_card`/`verify_message` likewise omit expiry.
- **Untrusted JSON:** `strict_json_loads` then Pydantic `model_validate` — exemplar `resolution.py:resolve_with_ip`. Divergence: API gossip/message ingress (`api.py:receive_gossip`, `receive_message`) takes `dict[str,Any]` via FastAPI default parsing; `topology.py:verify_candidate` uses `json.loads` on stored card JSON.
- **Binary encoding:** `encoding.b64url_encode`/`b64url_decode`; root/op keys via `crypto.load_public_key_b64url`. Divergence: callers that need raw bytes for `Ed25519PublicKey.from_public_bytes` do `b64url_decode` directly (`resolution.py`, `runtime.py:_load_public_key`, `topology.py`).

## 5. Consequence map (ranked by blast radius)
1. `canonicalize` / `signature_preimage` — every signed object and every peer; wrong ⇒ whole federation rejects or accepts differently; failure usually loud (`SignatureError`) but cross-implementation divergence can be silent.
2. `derive_node_id` — the identity anchor; wrong ⇒ whole federation, silent if both sides agree on the wrong derivation.
3. `strict_json_loads` + ingress parsing — authentication boundary; duplicate-key/NaN ambiguity can make signer and verifier canonicalize different values ⇒ silent auth bypass. Only well-known uses it.
4. `OperationalCertificate.verify` — one peer's operational key; wrong ⇒ that node impersonated or wrongly rejected.
5. `verify_object` / `verify_with_root` — per-object; wrong ⇒ one message/card accepted or dropped.
6. Certificate validity window / sequence monotonicity — per-peer; window check mostly absent ⇒ stale/rotated key accepted silently.
7. `b64url_decode` — per-field; lax alphabet handling can silently accept malformed encodings.

## 6. Intentional design decisions
- Root key never in daemon: `RootIdentity` (identity.py) intentionally carries no private key; docs/KEY_MANAGEMENT.md "Key custody model". Violating this (adding a root private field) is not intended.
- Multi-signature preimage strips *all* signature fields: `verify_transfer`/`verify_rotation` docstrings and `tests/vectors/generate_vectors.py` are the rationale. A single-signature verifier that strips only `signature` is intended; one that strips a multi-sig object's extra sigs incorrectly is not.
- `verify_object` takes `kind` as a separate argument, not from `obj["kind"]`: intentional domain separation, asserted by `tests/test_vectors.py:test_signature_fails_on_wrong_kind`.
- `strict_json_loads` defers I-JSON range to models: explicitly stated in its docstring; that no model implements the range is a gap, not a design goal.
- `verify` normalizes all crypto exceptions to `SignatureError`: `crypto.py:verify`.
- `load_public_key` accepts raw/PEM/DER: `crypto.py:load_public_key` for CLI/key files; network objects use the raw-only `load_public_key_b64url`.
- Bootstrap peers skip independent verification: `runtime.py:_pin_bootstrap_peers` comment "trusted by configuration".
- FastAPI default JSON at federation ingress: docs/LOOSE_ENDS.md Phase 10 calls it intentional; it nevertheless conflicts with PROTOCOL.md §4.1 (see §7).
- `webhook_envelope`, `contact_card` kinds implemented outside `models.py`/`signing.py` (cli.py, runtime.py): intentional, generic `verify_object` covers them.

## 7. Doc ↔ code drift
- PROTOCOL.md §4.4 allowed-kinds table omits `webhook_envelope`, which `protocol/signing.py:verify_webhook_envelope` and `runtime.py` (line ~1051) sign/verify.
- PROTOCOL.md §4.4 lists `contact_card`, but there is no `ContactCard` model in `protocol/models.py` and no helper in `protocol/signing.py`; only `cli.py` builds it.
- PROTOCOL.md §4.1 mandates I-JSON safe-range rejection; `canonical.py:strict_json_loads` explicitly does not do it and no model does.
- PROTOCOL.md §4.1 mandates duplicate-key/NaN rejection "before canonicalization or validation"; `api.py:receive_gossip`/`receive_message` parse with FastAPI defaults, so public gossip/message paths bypass it. LOOSE_ENDS.md Phase 10 asserts default parsing is intended.
- PROTOCOL.md §3.3/§6 require rejecting expired certificates and non-increasing sequences; `is_valid_at` is invoked only in `runtime.py:verify_gossip_sender_card`; no sequence comparison exists.
- PROTOCOL.md §10 caps operational certificate lifetime at 90 days; only `identity.py:create_operational_certificate` enforces it; `OperationalCertificateModel`/`verify` do not.
- PROTOCOL.md §2/§7 require RFC 3339 `Z` timestamps; `identity.py:_parse_ts` and Pydantic accept arbitrary ISO offsets.
- `protocol/signing.py` has `sign_receipt`/`sign_block` but no `verify_receipt`/`verify_block`; verification is via generic `verify_object`.

## 8. Verification surface
`tests/test_canonical.py` covers duplicate keys, non-finite, UTF-8, JCS ordering/negative-zero/unicode. `tests/test_vectors.py` replays `tests/vectors/canonical.json` and `signatures.json` (generated by `tests/vectors/generate_vectors.py`): node-ID derivation, cert, well-known, peer card, message, receipt, block; tamper/wrong-kind/wrong-key negatives; rotation-preserves-node-id. Nothing mocks crypto. Not exercised: `verify_transfer`, `verify_rotation` (only vector generation builds them), `webhook_envelope`, `contact_card`, certificate expiry/lifetime/sequence at verify time, strict parsing at HTTP ingress, I-JSON range, `is_valid_at` boundaries. A live probe would need a two-node in-memory `_FakeTransport` (tests/conftest.py) plus real `Ed25519PrivateKey` fixtures; the two-node integration test uses the fake transport, not TLS.

## 9. Surprises
- `b64url_decode` pads but does not validate the alphabet; `urlsafe_b64decode` ignores many invalid characters, so decodability validators in `models.py` are weaker than they read.
- `PeerCard.sequence` is documented as monotonic but is independent of `operational_certificate.sequence`; `gossip.py:build_own_card` sets card `sequence` equal to the certificate sequence.
- `verify_candidate` (`topology.py`) records `record_operational_key` from the *well-known* certificate while the peer row's sequence comes from the same doc; the candidate card's own cert signature is only verified inside `verify_peer_card`.
- `signing.py:verify_well_known` is unused; resolution/topology call `identity.verify_with_root` directly.
- `runtime.py:verify_inbound_message` verifies the raw transmitted dict, while `WebhookEnvelope` wraps a `dict[str,Any]` message — signature coverage of the nested message depends on the original bytes.
- `NODE_ID_RE` is duplicated in `addressing.py` and `protocol/models.py`.
