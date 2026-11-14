# seam-s4 — protocol ↔ verification contract (preimage agreement)

Pass type: blind hunter (generative discovery). Files read end to end:
`lattice/protocol/signing.py`, `lattice/canonical.py`, `lattice/identity.py`; every
call site of `sign_*`/`verify_*`/`sign_object`/`verify_object`/`signature_preimage`
traced in: `lattice/runtime.py` (sign/verify sites: `verify_gossip_sender_card`,
`sign_local_message`, `verify_inbound_message`, `_send_outbound_message`,
`_run_webhook_delivery`), `lattice/gossip.py`, `lattice/topology.py`,
`lattice/resolution.py`, `lattice/messages.py`, `lattice/api.py`, `lattice/cli.py`
(init/rotation/transfer/contact-card paths), plus supporting reads of
`lattice/protocol/models.py`, `lattice/protocol/constants.py`, `lattice/crypto.py`,
`lattice/encoding.py`, `tests/test_vectors.py`, `tests/vectors/generate_vectors.py`,
`docs/PROTOCOL.md` §3–9, `docs/LOOSE_ENDS.md`. Empirical probes (read-only, repo env):
pydantic 2.11.9 datetime/domain round-trip behavior on `PeerCard`; urllib3 kwargs
behavior reproducing the transport gate (see Findings 1–2 reachability note).

## Findings

Both findings below are the receipt leg of the signer/verifier table: the `receipt`
kind is the one signed kind whose verifier does not exist in the production tree.
Each was independently traced in this pass; the wave's hunt-b1b documents the same
mechanisms (its #2 and #5), so the dedupe ledger should merge, not double-count.
Both are **GATED** behind the wave's transport fault (hunt-b1b #1: `OutboundTransport.
request` raises `TypeError` on every call under the pinned urllib3 2.x because
`fields`/`assert_hostname` are passed as per-request kwargs — I reproduced this
myself against a local listener with the identical call shape: `TypeError:
HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'`).
No live outbound HTTP completes today, so the 202-response branch is reachable in
TESTS ONLY (mocked transports, `tests/test_runtime.py` delivery tasks) until that
repair lands. A repair that ignores this gate ships the hidden defects underneath.

1. [M] — A final `rejected` receipt is retried as a retryable "invalid custody receipt"
- Location: lattice/runtime.py:_send_outbound_message (202-handling branch); receipt signer at lattice/messages.py:InboundMessageService.build_receipt → lattice/protocol/signing.py:sign_receipt
- Evidence: `if (data.get("message_id") != message_id or data.get("node_id") != to_node_id or data.get("status") != "accepted"):` … `self._outbound.record_failure(message_id, owner, retryable=True)` — a receipt with `status: "rejected"` matches `message_id` and `node_id` but not `"accepted"`, so it falls into the retryable branch. There is no inspection of `status == "rejected"` anywhere in the sender (rg over runtime.py: only the two literal `"accepted"` comparisons).
- Trigger: our node holds an outbound message to a destination that returns 202 + signed `rejected`. Two in-tree destination paths produce exactly that today: `api.py:receive_message` → `BlockedSenderError` handler (signature-verified message from a blocked sender) and the `CustodyError` handler on the destination's accept path. GATED for live peers behind the transport `TypeError` fault (see above); the handler branch itself is exercised today by the mocked-transport delivery tests.
- Frequency: DEMONSTRATED population: every outbound message to a destination that has blocked our node (operator action via the `blocks` table), or any destination-side `CustodyError` on accept. Normal-operation cadence: blocks between federated peers are a routine operational event; each such message then re-sends up to `max_attempts=10` with 60 s→24 h backoff (~17 h of churn per message).
- Outcome: violates PROTOCOL.md §8 ("A `202 Accepted` with a rejected receipt is final") and the `BlockedSenderError` docstring ("a rejected receipt is final and the sender stops retrying"); each retry is mislabeled in the audit log as `reason="invalid custody receipt"`, and each retry's `_circuit_record_failure` counts against the destination, opening the circuit breaker that also suppresses gossip to that peer. Wrong acknowledgment semantics + wrong audit attribution.
- Confidence: traced — mechanism certain (code + protocol text + the destination's own two rejected-receipt paths); trigger concrete but GATED (tests-only until the transport kwargs fault is repaired); frequency grounded in the blocked-peer population. Corroborates hunt-b1b #2.

2. [L] — The custody receipt's signature is never verified by any sender-side code
- Location: lattice/runtime.py:_send_outbound_message (202 branch) — no `verify_receipt` exists; lattice/protocol/signing.py defines `sign_receipt` but no receipt verifier; `verify_webhook_envelope` is the only other kind-specific wrapper with a verifier.
- Evidence: comment `# Validate the signed custody receipt before transferring ownership.` precedes only the three-field plaintext comparison (`message_id`, `node_id`, `status`); `api.py` states `# Return the signed receipt so sender can validate custody transfer.` — the sender never validates it. rg over the tree: zero production call sites verifying kind `"receipt"` (only `tests/test_vectors.py:97,131` exercise the preimage).
- Trigger: GATED behind the transport fault (no live 202 is ever received today). Once live: any 202 response body from the pinned endpoint whose three plaintext fields match transfers ownership — `record_success` runs, content is erased (`erase_content=True`), the message is recorded `delivered`. Under invariant 7 (nginx owns TLS, endpoints pinned) the practical forger set narrows to a mispointed/still-pinned endpoint or an appliance answering 202 at the declared URL; the destination node itself can forge its own receipt either way, so the security delta is narrow — this is a spec-contract gap (the entire reason receipts are signed per §8) plus a misreported check, not a remote bypass.
- Frequency: latent by definition beyond "requires a misdirected or misbehaving endpoint at the pinned URL"; per the calibration rule it stays at L.
- Outcome: sender-side custody-transfer validation the protocol specifies is unimplemented; the `receipt` signature is dead weight in production; the code comment misreports a field comparison as signature validation. Corroborates hunt-b1b #5 (which additionally cites `tests/test_runtime.py:283` feeding an unsigned three-field body that is marked delivered).

## Checked and clean

- **Single preimage implementation.** Every signer and every verifier in the tree
  builds the preimage through `canonical.signature_preimage` (header
  `"lattice-signature-v1\0" + kind + "\0" + MEDIA_TYPE + "\0" + canonical_bytes`).
  No site hand-rolls the header; `MEDIA_TYPE` and `SIGNATURE_DOMAIN_PREFIX` are
  single constants. `cli.py` imports the same helper for transfer/rotation
  (`cli.py:19, 452, 785`). Cross-implementation disagreement about header bytes is
  structurally impossible in-tree.
- **Canonicalization.** All sign/verify paths canonicalize via `rfc8785.dumps`
  (`canonical.canonicalize`); dict-comprehension field stripping preserves
  insertion order but JCS sorts keys, so order variance cannot split signer from
  verifier. Nested `"signature"` keys (the certificate inside a peer card) are
  correctly NOT stripped — only top-level fields are excluded, identically on both
  sides (`{k: v for k, v in obj.items() if k != "signature"}`).
- **well_known**: signer `cli.py` init/rotation via `sign_with_root(root_key, doc,
  "well_known")` (strips `signature`); verifiers `resolution.py:99` and
  `topology.py:312` via `verify_with_root(root_key, data, "well_known")` over the
  raw wire dict from `strict_json_loads`. Same kind string, same strip set, same
  canonicalization — agree. (The unused `sign_well_known`/`verify_well_known`
  wrappers in signing.py delegate to the same functions — dead but consistent.)
- **peer_card**: signer `gossip.build_card`/`sign_card` → `sign_peer_card` →
  `OperationalIdentity.sign_object(card, "peer_card")`; the card is built with
  lowercase domain, `"%Y-%m-%dT%H:%M:%SZ"` timestamps, and `certificate.to_dict()`.
  Verifier A `runtime.verify_gossip_sender_card` → `verify_object(cert.
  operational_public_key, card, "peer_card")` over the RAW wire dict. Verifier B
  `topology._verify_against_well_known` → `verify_peer_card(card.model_dump
  (mode="json"), ...)` over the pydantic re-serialization. Empirically probed with
  pydantic 2.11.9: a card built by the in-tree signer round-trips through
  `model_validate`/`model_dump(mode="json")` byte-identically (Z-suffix timestamps,
  lowercase domain, cert dict verbatim). All three sides agree for the in-tree
  signer population. (Residual format-variance divergence for foreign
  implementations → Design risk 1.)
- **message**: signer `runtime.sign_local_message` → `sign_message` (hand-built
  dict); verifier `runtime.verify_inbound_message` → `verify_message(message, cert,
  root_identity)` over the raw request-body dict (FastMedia/`dict` body). Same kind,
  same object, same preimage — agree. The cold-sender 503 path returns before
  verification by design (sender retains the message); no preimage involvement.
- **operational_certificate**: signer `identity.create_operational_certificate`
  signs `cert.to_dict()` minus `signature`; verifier `OperationalCertificate.verify`
  reconstructs the same `to_dict()` minus `signature`. Both go through
  `_format_ts`/`_parse_ts` normalization, so wire-format variance in timestamps
  cannot split signer from verifier — verify always compares against the normalized
  form the signer used. Agree. (The unenforced validity window on the message path
  is hunt-g1 #2, not a preimage disagreement — noted for dedupe, not re-reported.)
- **transfer**: signer `cli._transfer_signature_preimage` strips exactly
  `("signature", "new_signature")`, kind `"transfer"`; co-sign path signs the same
  bare object before adding `new_signature`; verifier `identity.verify_transfer`
  strips the identical two-key set, same kind. Agree.
- **rotation**: signer (cli rotate command) computes one preimage over the bare
  object (all three signature fields absent) and signs it with root, old-op, and
  new-op keys; verifier `identity.verify_rotation` strips the identical
  `("signature", "old_signature", "new_signature")` set, same kind. Agree.
  (`verify_rotation` has no production caller — the statement is consumed
  out-of-band; consistent-by-construction regardless.)
- **contact_card**: signer `cli.cmd_contacts_export` → `identity.sign_object(card,
  "contact_card")`; verifier `cli.cmd_contacts_import` → `verify_object(cert.
  operational_public_key, card, "contact_card")` over the raw parsed file dict,
  against the pinned cert chain (root pin → `cert.verify` → op key). Same kind, same
  object — agree.
- **webhook_envelope**: signer `runtime._run_webhook_delivery` → `sign_object
  (envelope, "webhook_envelope")` where `metadata` comes from
  `DeliveryMetadata(...).model_dump(mode="json")`; the delivered payload is
  `WebhookEnvelope.model_validate(signed_env).model_dump(mode="json")`, and the
  `message` field is `dict[str, Any]` (pass-through, no transformation), so the
  delivered bytes equal the signed bytes. The provided verifier
  `verify_webhook_envelope` delegates to `verify_object(..., "webhook_envelope")` —
  same kind, same strip set; no in-tree caller by design (external consumer per
  docs/LOOSE_ENDS.md Phase 7). Agree by construction.
- **Cross-kind signature confusion is impossible**: the kind string is inside the
  preimage, and every kind's required field set is disjoint from every other's
  (Receipt vs Message vs Block vs PeerCard vs contact_card), so no object can be
  simultaneously well-formed under two kinds. `tests/test_vectors.py:120,131` pin
  exactly this (a `message` signature does not verify as a `receipt`). Clean.
- **Crypto/encoding primitives**: `crypto.sign`/`verify` are direct Ed25519
  wrappers, `verify` raises `SignatureError` on any failure; `b64url_decode` pads
  tolerantly (accepts padded input) — harmless for signature comparison since both
  signer and verifier encode/decode the same way; no length confusion possible
  (Ed25519 signatures are fixed 64 bytes, `from_public_bytes` requires 32).
- **Root-key boundary (invariant 2)**: no signer reachable from the daemon loads a
  root key; the only root signers are CLI offline commands (init/rotate/transfer)
  and `gossip.build_own_card` takes only the root PUBLIC key. Respected.

## Enumeration

Composed command closing the class of sign/verify call sites:

`rg -n "sign_with_root|verify_with_root|verify_object|sign_object|verify_webhook_envelope|sign_peer_card|verify_peer_card|sign_message|verify_message|sign_receipt|sign_block|sign_well_known|verify_well_known|verify_transfer|verify_rotation|create_operational_certificate|signature_preimage" --type py -g '!lattice/protocol/signing.py' -g '!lattice/identity.py' -g '!lattice/canonical.py'`

Instance table (assignment's enumeration: each signed kind → signer → verifier → preimage each builds):

| kind | signer (site) | verifier (site) | preimage agreement | disposition |
|---|---|---|---|---|
| `well_known` | `cli.py:175` init, `cli.py:821` rotate → `sign_with_root` (strip `signature`) | `resolution.py:99`, `topology.py:312` → `verify_with_root` over raw wire dict | identical kind/canonical/strip | examined-clean |
| `operational_certificate` | `identity.create_operational_certificate` (root, `to_dict` minus `signature`) | `identity.OperationalCertificate.verify` (same reconstruction) | identical; timestamp normalization stable both sides | examined-clean (validity-window gap = hunt-g1 #2, not preimage) |
| `peer_card` | `gossip.build_card`/`sign_card` → `sign_peer_card` | `runtime.verify_gossip_sender_card` (raw wire card); `topology._verify_against_well_known` (`model_dump` re-serialization) | agree for in-tree signer formats (empirically probed); raw-vs-normalized divergence possible only for foreign wire formats | examined-clean (see Design risk 1) |
| `message` | `runtime.sign_local_message` → `sign_message` | `runtime.verify_inbound_message` → `verify_message` (raw wire dict) | identical | examined-clean |
| `receipt` | `messages.build_receipt` → `sign_receipt` (over `Receipt.model_dump`) | **none in production**; sender compares 3 plaintext fields | signer exists, verifier absent | **Findings 1 & 2** (corroborate hunt-b1b #2/#5) |
| `block` | `signing.sign_block` — no production caller | none (blocks are local DB rows, `peers.BlockStore`) | no pair exists | out-of-scope: no production signer or verifier; kind reserved by spec §13 list |
| `transfer` | `cli._transfer_signature_preimage` (bare minus `signature`,`new_signature`) | `identity.verify_transfer` (identical bare set) | identical | examined-clean |
| `rotation` | cli rotate command (3 signatures over one bare preimage) | `identity.verify_rotation` (identical bare set) — no production caller | identical | examined-clean |
| `contact_card` | `cli.cmd_contacts_export` → `sign_object(…, "contact_card")` | `cli.cmd_contacts_import` → `verify_object(…, "contact_card")` over raw file dict | identical | examined-clean |
| `webhook_envelope` | `runtime._run_webhook_delivery` → `sign_object(envelope, "webhook_envelope")` | `signing.verify_webhook_envelope` — no in-tree caller (external consumer, LOOSE_ENDS Phase 7) | identical by construction (same `verify_object` path) | examined-clean / signer-only by design |

Test-only sites (`tests/conftest.py`, `test_topology`, `test_runtime`, `test_messages`,
`test_resilience`, `test_cli`, `test_integration`, `test_vectors`, `tests/vectors/
generate_vectors.py`) all use the same production helpers — no divergent test-local
preimage construction exists.

## Design risks (max 2)

1. **Two peer-card verifiers disagree about which bytes they verify.**
   `runtime.verify_gossip_sender_card` verifies the raw wire card; `topology.
   _verify_against_well_known` verifies the pydantic `model_dump(mode="json")`
   re-serialization, which silently normalizes (`"+00:00"`→`"Z"`, domain case —
   both empirically confirmed). In-tree signers emit the normalized forms, so the
   two paths agree today; a foreign implementation (or any future in-tree signer
   using `datetime.isoformat()` with an offset, as `build_receipt`'s
   `received_at` microseconds show is natural) would produce cards one verifier
   accepts and the other rejects. Same class: `OperationalCertificate._format_ts`
   truncates sub-second precision, so a foreign certificate with fractional
   timestamps fails `cert.verify` (false rejection).
2. **The receipt-signing mechanism is unexercised end-to-end.** Kind `receipt` has
   a production signer and no production verifier anywhere (Finding 2); its
   signature is never validated even once in the delivered system, so any future
   divergence between `build_receipt`'s preimage and a later-added sender-side
   verifier would surface only as interoperability failures against other nodes.

## Bound

- The GATED reachability of Findings 1–2 rests on the wave's transport fault
  (hunt-b1b #1). I reproduced the `TypeError` call-shape myself against a local
  listener (system urllib3 2.3.0; uv.lock pins 2.7.0) but did not run the daemon
  end-to-end against a live TLS peer; the gate claim is otherwise taken from
  hunt-b1b's empirical work, not re-derived.
- `lattice/runtime.py` was read in full at every sign/verify call site and its
  surrounding control flow (delivery workers, cert/root lookup helpers, webhook
  loop, circuit breaker); scheduler internals and storage repositories were
  skimmed only where the seam touches them (lease/claim semantics are seam-s3's
  and hunt-h1's domain).
- `lattice/cli.py` was read end-to-end at all signature-relevant commands
  (init, rotate, transfer create/cosign/accept, contacts export/import, serve
  bootstrap); non-signing CLI commands (config/upgrade/pins/serve plumbing) were
  skimmed.
- My enumeration pattern covers the exported helper names; a hypothetical inline
  `Ed25519PrivateKey.sign(...)` call bypassing `crypto.sign` would not match — a
  supplementary `rg -n "\.sign\(" lattice/` over raw key objects found no such site
  outside the traced ones.
