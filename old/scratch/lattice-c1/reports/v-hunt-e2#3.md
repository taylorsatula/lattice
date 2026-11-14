# v-hunt-e2#3 — PRIMED VERIFIER: finding hunt-e2#3

Claim under test: `scratch/lattice-c1/reports/hunt-e2.md`, finding 3 (tier L):
"Signature preimages computed over re-serialized objects, not the received bytes — two
in-tree verification paths disagree."

## Verdict: ADJUSTED (mechanism CONFIRMED, tier L held, frequency corrected to LATENT)

### Frame re-derived from source (not from the claim phrasing)

- `OperationalCertificate.verify` (`lattice/identity.py:125`) does
  `signed = self.to_dict(); del signed["signature"]; canonicalize(signed)`.
  `to_dict` (`identity.py:96`) rebuilds `valid_from`/`valid_until` through `_format_ts`
  (`strftime("%Y-%m-%dT%H:%M:%SZ")`, truncates microseconds) and `operational_public_key`
  through `public_key_b64url` (canonical unpadded re-encode). So verification canonicalizes a
  *reconstruction*, not the received object dict. §4.3 says "Recompute the preimage" over the
  object dict; §2 mandates Z-suffix UTC timestamps.
- `verify_gossip_sender_card` (`lattice/runtime.py:536`) calls
  `verify_object(cert.operational_public_key, card, "peer_card")` over the **raw** dict.
  `_verify_against_well_known` (`lattice/topology.py:285`) calls
  `verify_peer_card(card.model_dump(mode="json"), cert, root_identity)` — the pydantic round-trip.
  `receive_batch` (`lattice/gossip.py:73`) stores the raw card (`json.dumps(card, …)`), so the
  candidate's wire form is preserved; it is normalized only at `_verify_against_well_known`.
- `verify_inbound_message` (`runtime.py:618`) verifies the **message** over the raw received dict
  (`verify_object`), so the message path is not part of this finding.

### Sub-claim disposition (mechanism / trigger / frequency)

| Sub-claim | Disposition |
|---|---|
| Cert verify canonicalizes a reconstruction, not received bytes | CONFIRMED (mechanism) |
| Raw-byte JCS verify of a re-encoded equivalent-instant cert FAILS while `cert.verify` PASSES | CONFIRMED, reproduced |
| Two in-tree paths disagree on a peer card (raw vs `model_dump`) | CONFIRMED, reproduced |
| "any hostile peer (self-generated root keypair suffices)" is the trigger population for direction 1 | **REFUTED** — a peer re-encoding its own cert gains no trust; value-neutral |
| "the peer can never become verified" is a defect | **REFUTED as characterization** — it is the strict path rejecting a §2-non-conforming card; the accepting path is rate-limit-only, grants no trust |
| No value-level bypass exists (only sub-second timestamp wiggle) | CONFIRMED |

Reproduction (repo venv, pydantic 2.13.4), using the repo's own sign/verify functions:

```
cert.to_dict valid_until: 2026-01-31T12:30:00Z
cert.verify on offset wire "2026-01-31T17:30:00+05:00": OK   # wire text not bound
raw JCS verify of that mutated dict: FAILED -> SignatureError
signed_card issued_at: 2026-01-15T10:30:00+00:00
raw dict verify (verify_gossip_sender_card): OK
model_dump issued_at: 2026-01-15T10:30:00Z
model_dump verify (topology path): FAILED -> SignatureError
subsecond valid_until accepted; in-memory valid_until 2026-01-31T12:30:00.999000+00:00
```

### Severity correction

Held at **L**, with the trace that decides it. The scale's M requires "divergence between two
paths that must agree — under a plausible normal operation." The divergence requires a
**non-conforming** emitter: §2 mandates `Z` UTC timestamps and unpadded base64url, so every
conforming card round-trips `model_dump` identically to the signed raw dict (verified: pydantic
emits `Z` for `+00:00`; `build_own_card`/`to_dict`/`create_operational_certificate` all emit `Z`
second precision). No conforming input triggers it. The bad outcome is bounded to cross-impl
acceptance of re-encoded bytes and a non-conforming card being rejected by the strict path; the
only value-level change is a <1 s timestamp window extension. That is L, not M. No H path exists:
a hostile peer cannot use re-encoding to acquire trust it does not already hold, because it must
already own the signing key to have a verifiable card at all.

### Frequency correction

Hunter's "DEMONSTRATED — any hostile peer / any non-conforming emitter" is corrected to **LATENT**
for the divergence direction and LATENT for the malleability direction's *harmful* use.

- Direction 1 (malleability): reproduced as a mechanism, but every activation is value-neutral. The
  only actor who can act on it is a relay mutating a third party's cert — and the mutation
  normalizes back to the same signed bytes, so no state changes. No operation population produces a
  bad outcome. LATENT.
- Direction 2 (divergence): no producer in the tree emits offset/fractional timestamps or padded
  base64; §2 forbids them. The population is "non-conforming foreign implementations," which is a
  hypothesis, not a grounded cadence. LATENT.
Per the standing calibration ("a frequency you cannot ground is LATENT by definition … cap at L"),
L is the ceiling and is held.

### Reachability kind

PRODUCTION for the mechanism (any remote peer's card or cert reaches both verify sites). The
divergence sub-claim is **gated on a non-conforming sender** (offset/fractional timestamps,
padded/standard-alphabet base64); no conforming in-tree or spec-conforming peer opens it.

### Additional mechanisms / earlier failure sites on the same trace

**Side discovery (single-pass; already flagged by hunter as side discovery 1) — escaping ValueError
leaves a candidate stuck in an unbounded retry loop.**
`OperationalCertificate.from_dict` → `load_public_key_b64url` →
`Ed25519PublicKey.from_public_bytes` raises plain `ValueError` for a wrong-length key, and the
pydantic validator `_check_base64url` (`models.py`) uses lenient `b64url_decode` (accepts `"abc"`
→ 2 bytes, no length check), so the model passes and the exception surfaces only at `from_dict`.
`topology._verify_against_well_known:321` wraps `from_dict`/`cert.verify` in `except IdentityError`
only; `IdentityError` is a subclass of `ValueError`, so a plain `ValueError` is **not** caught. It
escapes `verify_candidate` (whose only guard is `except TopologyError:` → `remove_candidate`), so
`self._cache.remove_candidate(node_id)` is never reached; `_run_verify_candidates`
(`runtime.py:1124`) logs and continues, and the same candidate is retried on the next
`verify_interval_seconds` tick (default **60 s**), each retry performing a full HTTPS
`resolve_with_ip` fetch, until the card's `expires_at` (≤ 7 days) — ≈10,080 fetches per candidate,
bounded by candidate caps. The identical escape exists in `resolution.resolve_with_ip:106`
(`from_dict` is outside the `except IdentityError` block), so the plain `ValueError` also escapes
`ResolutionError`-handling callers (`runtime._certificate_for_node`, `runtime.py:666`; the
`receive_message` handler catches `BlockedSenderError`/`RuntimeError`, not `ValueError`).
- Price: **M**. Reachable in PRODUCTION by any attacker controlling a domain who gossips a card
  and serves a root-signed well-known document whose embedded cert carries a short
  `operational_public_key` (no valid cert signature needed — `from_dict` aborts before
  `cert.verify`). Frequency: one candidate per attacker card; sustained at 60 s cadence; and a
  message from such a domain can produce an unhandled 500 rather than a 401.
- Fix-direction constraint: the invariant is "a candidate is removed on *any* verification
  failure." Catching `ValueError` at the two `from_dict` sites repairs the escape; but the durable
  fix is to remove the candidate in a `finally`/broad guard in `verify_candidate` (and to
  length-check key material at the model boundary), otherwise any *next* unexpected exception
  re-opens the same stuck loop. Escaping structure-breaking (catching the exception) is not the
  same as preventing the retry.

### Fix-direction constraints for finding 3 itself

- A repair must verify the certificate over the **received object dict**, not a `to_dict()`
  reconstruction, or must pin a single canonical form used by **all** verify sites. Fixing only
  `OperationalCertificate.verify` leaves `verify_gossip_sender_card` (raw) and
  `_verify_against_well_known` (`model_dump`) disagreeing.
- The alternative "normalize at parse" fix (reject non-`Z` timestamps at `strict_json_loads` /
  model boundary) is acceptable and closes both directions, but it must be applied uniformly; and
  it must not be confused with binding the wire bytes — normalizing first then signing the
  normalized form still leaves the raw text unsigned.
- Note the sub-second window: `to_dict` truncates while `from_dict` retains microseconds, so a
  repair that stops reconstructing must decide which precision is authoritative, or signed text
  and the in-memory `is_valid_at` window will differ.

## Checked and clean

- `verify_inbound_message` / `verify_message` verify the **message** over the raw received dict —
  the message path is not affected by this finding.
- The well-known document outer signature is verified over the raw fetched dict in both
  `resolution.resolve_with_ip` (`verify_with_root(root_key_obj, data, …)`) and
  `topology._verify_against_well_known`; a mutated embedded cert inside a well-known doc breaks the
  outer root signature, so direction 1 is not reachable via the well-known path.
- For every conforming peer, `verify_gossip_sender_card` and `_verify_against_well_known` agree:
  `build_own_card`/`to_dict`/`create_operational_certificate` emit `Z` second-precision timestamps
  and canonical unpadded base64url, which `model_dump(mode="json")` round-trips byte-for-byte
  (verified for `+00:00` → `Z`).
- `signature_preimage` layout matches doc §4.3/§12.2.
- Signature-field exclusion in `sign_object`/`verify_object`/`sign_with_root`/`verify_with_root`/
  `verify_transfer`/`verify_rotation` matches the vectors.
- No value-level bypass: all cert mutations that survive normalization parse to the same instant;
  the only surviving change is < 1 s.

## Enumeration

Class = "verify sites whose preimage is built from a reconstruction rather than the received dict":

```
rg -n "\.to_dict\(\)|model_dump\(mode=\"json\"\)|verify_object\(|verify_with_root\(|verify_peer_card\(" lattice/*.py lattice/protocol/*.py
```

| verify site | preimage source | disposition |
|---|---|---|
| `identity.OperationalCertificate.verify` | `to_dict()` reconstruction | **finding 3** direction 1 |
| `topology._verify_against_well_known` (peer card) | `card.model_dump(mode="json")` | **finding 3** direction 2 |
| `topology._verify_against_well_known` (cert) | `doc.operational_certificate.model_dump(...)` → `from_dict` → `to_dict` | finding 3 direction 1 |
| `runtime.verify_gossip_sender_card` | raw `card` | correct per §4.3; upstream of direction 2 |
| `runtime.verify_inbound_message` / `signing.verify_message` | raw `message` | examined-clean |
| `resolution.resolve_with_ip` (well-known) | raw `data` | examined-clean |
| `resolution.resolve_with_ip` (cert) | `model_dump` → `from_dict` → `to_dict` | finding 3 direction 1 |
| `signing.verify_webhook_envelope` | caller-supplied dict | examined — no reconstruction at the site |

## Bound

- No live daemon or HTTP server was run; behaviour was established by executing the repo's own
  verify/sign functions in the pinned venv (pydantic 2.13.4), not over the network.
- pydantic's datetime serialization (`+00:00` → `Z`) is version-dependent; a future pydantic
  release could change it (already a design risk in the hunter report). This does not change the
  current verdict.
- I could not determine whether any real third-party implementation emits non-conforming
  timestamps/base64, so the divergence direction's frequency is LATENT by construction.
- The retry-amplification side discovery was traced through `verify_candidate` and
  `_run_verify_candidates`; I did not audit `transport.py`/`network_policy.py` for additional
  bounds on the repeated fetch.
