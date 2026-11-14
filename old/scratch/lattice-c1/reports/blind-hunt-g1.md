# blind-hunt-g1 — resolution & addressing (blind third pass)

Pass type: blind hunter, target withheld. `lattice/resolution.py` and `lattice/addressing.py` read
end to end; all callers/callees traced (`identity.py`, `crypto.py`, `canonical.py`,
`protocol/models.py`, `protocol/signing.py`, `transport.py`, `network_policy.py`,
`storage/repositories.py`, `runtime.py`, `api.py`, `topology.py`, `cli.py`).
Claims independently reproduced in-process with real Ed25519 keys, real `WellKnownResolver`, a fake
transport, and (for the queue) a stub resolver. No file modified.

Neutral question re-derived: do address parsing, well-known resolution, durable pinning, and
transfer/reset handling fail closed and reject malformed/spoofed resolution data, preserving the
pin ↔ trust relationship?

Answer: **address parsing, the schema/domain/re-derivation gates, and the pin↔domain binding are
sound.** Two fail-open defects remain on the resolution path, both already in the corpus from
`hunt-g1` (this pass independently re-derived and re-reproduced them, and adds one unpriced
side-discovery class in the caller). No new defect was found inside `addressing.py`.

## Findings

1. [H] — Malformed operational certificate escapes the resolver as `SignatureError`/`ValueError`, not `ResolutionError`
- Location: `lattice/resolution.py:WellKnownResolver.resolve_with_ip` (lines 104–109).
- Evidence:
  ```
  104  root_identity = RootIdentity(node_id=doc.node_id, public_key=root_key_obj)
  105  cert = OperationalCertificate.from_dict(doc.operational_certificate.model_dump(mode="json"))
  106  try:
  107      cert.verify(root_identity)
  108  except IdentityError as exc:
  109      raise ResolutionError(...)
  ```
  Line 105 (`from_dict` → `load_public_key_b64url` → `Ed25519PublicKey.from_public_bytes`) and the
  body of `cert.verify` (`identity.py:verify` → `crypto.verify`) raise `ValueError` and
  `SignatureError` respectively. `issubclass(SignatureError, IdentityError)` is `False` and
  `ValueError` is a sibling, so neither is caught. The function's own docstring/contract
  ("Raises `ResolutionError` on failure") is violated.
- Trigger (PRODUCTION, adversary-supplied): a peer that controls its own domain serves a
  root-signed, schema-valid `/.well-known/lattice` whose `operational_certificate` fails
  verification. `OperationalCertificateModel._check_base64url` only checks that `b64url_decode`
  succeeds and never checks length, so `"signature": ""`, a forged signature, a non-32-byte
  `operational_public_key`, or a valid key with an invalid signature all pass the model. The
  attacker root-signs the mutated document so the earlier `verify_with_root` gate passes.
  Independently reproduced (`/tmp/repro_g1_indep2.py`, real keys):
  ```
  sig_empty:      ESCAPED lattice.crypto.SignatureError: signature verification failed
  sig_forged:     ESCAPED lattice.crypto.SignatureError: signature verification failed
  opkey_32:       ESCAPED lattice.crypto.SignatureError: signature verification failed
  opkey_10bytes:  ESCAPED builtins.ValueError: An Ed25519 public key is 32 bytes long
  ```
- Frequency: DEMONSTRATED — adversarial, one hostile peer action, not a routine cadence, but the
  consequence is permanently cadenced: `RuntimeCoordinator._resolve_pending_senders`
  (`runtime.py:900–920`) catches only `ResolutionError` (line 914), so the escape aborts the whole
  `for domain in batch:` loop mid-batch; a domain is discarded only after a *successful* `pin`
  (lines 918–919). Every 30 s tick (`runtime.py:348`) re-sorts the same batch and aborts at the same
  position. Reproduced with the real method (`/tmp/repro_queue2.py`, stub resolver raising
  `SignatureError` for `aaa.evil.test` while `zzz.victim.test` sorts after it):
  ```
  round 0: ABORTED by SignatureError; queue=['aaa.evil.test', 'zzz.victim.test']
  round 1: ABORTED by SignatureError; queue=['aaa.evil.test', 'zzz.victim.test']
  round 2: ABORTED by SignatureError; queue=['aaa.evil.test', 'zzz.victim.test']
  ```
- Outcome: cross-peer resolution starvation. Any cold/unpinned domain sorting after the hostile
  one can never be pinned; its senders receive 503 forever, retry until `RetryPolicy` exhausts, and
  the sender erases the message content — cross-peer message loss driven by one hostile peer.
  Secondary surfaces from the same escape: `runtime._certificate_for_node` (`runtime.py:678`;
  `except ResolutionError: pass` lets it escape through `verify_inbound_message` → unhandled 500 on
  the public `POST /lattice/v1/messages`), `cli.py:579`, `topology.py:224/323`, and the daemon
  bootstrap `start()` path (`runtime.py:429`).
- Confidence: traced — mechanism, trigger, frequency all reproduced. Reachability kind: PRODUCTION.
- Overlap: identical to `hunt-g1#1`, verified CONFIRMED H by `v-hunt-g1#1`. Reported here because
  this pass was told nothing; independently re-derived, not copied.

2. [M] — Resolution/pin path never enforces the operational-certificate validity window
- Location: `lattice/resolution.py:resolve_with_ip` (lines 104–109); no `is_valid_at` anywhere in
  the file.
- Evidence: after `cert.verify(root_identity)` the code proceeds directly to
  `return data, resolved_ip`; `pin()` persists the model dict. The only `is_valid_at` enforcement in
  the daemon is on the gossip sender-card path (`runtime.py:564`). Independently reproduced
  (`/tmp/repro_validity.py`, real keys): a root-signed document whose cert window is
  `[now-60d, now-30d)` is accepted and pinned —
  ```
  cert valid_at(now): False
  PINNED expired cert, valid_until= 2026-08-29T17:13:44Z
  ```
- Trigger (PRODUCTION): any peer whose domain is pinned; the peer's operational certificate passes
  `valid_until` (30-day lifetime, `cli.py:115`), and pins are TOFU-forever
  (`pin()` callers = `resolution.resolve_address:172` and `runtime._resolve_pending_senders:913`
  only; no refresh task in `_build_scheduler`).
- Frequency: DEMONSTRATED cadence — certificate expiry on the ~30-day issuance cycle; nothing
  refreshes pins, so any pin older than one cert lifetime qualifies. Caveat (same as
  `v-hunt-g1#2`): if the peer rotated, the stale pin yields 401, not expired acceptance; the
  expired-acceptance path requires the peer to keep signing past expiry.
- Outcome: an expired (or not-yet-valid) operational certificate is admitted at resolve time and
  persisted; because the pin-consuming path (`_certificate_for_node` → `verify_message`,
  `protocol/signing.py:52–58`) also omits the window check, signatures from an expired key keep
  authenticating inbound messages on the pin path while the same cert is rejected on the gossip
  path — divergence between two verification paths that must agree.
- Confidence: traced — mechanism, trigger, frequency reproduced; harm delivery is via
  `verify_message`, not independently via the pin site (see `v-hunt-g1#2`).
- Overlap: same defect family as `hunt-g1#2` / `hunt-e1#1` / `hunt-f2#1`; not a new ticket. Kept
  at M, not promoted.

## Side discoveries (single-pass candidates, not primary findings; priced)

S1. [M] — `_resolve_pending_senders` never discards persistently-failing domains; the queue is
unbounded and unauthenticated (`lattice/runtime.py:900–920`).
- Mechanism: the docstring says "On failure, drops it from the queue", but the
  `except ResolutionError` branch `continue`s without `discard` (line 916–917); only success
  discards (918–919). Reproduced (`/tmp/repro_queue.py`):
  ```
  resolver calls: {'a.fail.test': 3, 'b.fail.test': 3, 'ok.test': 1}
  remaining queue: ['a.fail.test', 'b.fail.test']
  ```
- Trigger (PRODUCTION, unauthenticated): `POST /lattice/v1/messages` with a schema-valid
  `Message` whose `from_address` uses an unknown domain. `verify_inbound_message`
  (`runtime.py:638–651`) returns `(domain, True)` for a cold sender **before any signature
  verification**; `api.py:307` calls `queue_domain_resolution`, and the rate limiter is not reached
  on the 503 path. `Message.from_address` is only `min_length=1,max_length=320`, so the attacker
  chooses the domain string freely (subject to `parse_address`'s `:/@` exclusion).
- Frequency: DEMONSTRATED — per distinct attacker-supplied domain; each failed domain is retried
  every 30 s tick indefinitely, and the set has no cap (only `.add` at 897 and `.discard` at 919).
- Outcome: unbounded `_unresolved_domains` growth (memory) plus a self-sustaining DNS/HTTPS fetch
  loop against arbitrary attacker-named hosts, reachable by an unauthenticated network peer. Also
  the amplifier that makes Finding 1's starvation permanent.
- Confidence: traced (mechanism and queue growth reproduced; the 503-before-rate-limit ordering is
  read from `api.py:295–320`).
- Fix-direction constraint: catching `Exception` per domain fixes starvation but leaves the
  unbounded queue; the loop must also honor its docstring (discard or time-bound/quarantine
  failures) and the enqueue path needs a cap, otherwise the resource fault remains.

## Checked and clean

- `addressing.py:parse_address` — `rsplit("@",1)` + non-empty username/host; host `:/@` exclusion
  blocks scheme/host/userinfo injection into the fetch URL; 253-byte bound matches
  `WellKnownDocument`; node-ID regex identical to `models.NODE_ID_RE`; whole-address lowercase is
  consistent system-wide (`cli.py`, repository key normalization). `?`/`#`/space in a host can only
  redirect the fetch within the attacker's own authority and cannot cross the `doc.domain ==
  domain` equality, so no cross-domain confusion. Fail-closed.
- `resolve_with_ip` gate order — status ≠ 200 → content-type → strict JSON (duplicate-key and
  non-finite rejection in `canonical.py`) → `isinstance dict` → Pydantic `extra="forbid"` schema →
  `doc.domain == domain` (both lowercased) → root-key decode → node-ID re-derivation → root
  signature over the raw document → cert. Every gate except the cert handler fail-closes into
  `ResolutionError`.
- `pin`/`get_pin`/`reset_domain` — pin key, `doc.domain`, and fetched host are the same lowercased
  string; repository lowercases keys on both `upsert` (`repositories.py:101`) and `get`
  (`:116`); `pin()` cannot persist a cert that fails `resolve()` because `resolve` raises first
  (only the Finding-1 escapes pass through, and they abort before `upsert`).
- `cli.cmd_trust_accept_transfer` (`cli.py:528–613`) — fail-closed: existing pin required, pinned
  root key must derive `old_node_id`, live well-known `node_id` must equal `new_node_id`, and both
  transfer signatures must verify against pinned-old/new root keys. No replayed transfer can
  re-bind, because after the move the old key no longer matches the pin.
- `resolved_ip` is produced by our own transport, not remote content — not spoofable.
- No root private key loaded/derived/exported in either assigned file (invariant 2).

## Enumeration

Close the fail-closed class over the assigned files:
```
rg -n "except|raise ResolutionError" lattice/resolution.py lattice/addressing.py
```
| Site | Code | Disposition |
|---|---|---|
| resolution.py:48 | `except (TransportError, NetworkPolicyError)` → ResolutionError | examined-clean |
| resolution.py:100 | `verify_with_root` `except Exception` → ResolutionError | examined-clean |
| resolution.py:65/74/85/91 | broad `except Exception` → ResolutionError around JSON/model/b64/decode | examined-clean |
| resolution.py:108 | `except IdentityError` (too narrow — sibling `SignatureError`, `ValueError` escape) | **Finding 1** |
| addressing.py:78 | `except AddressError: return None` in `node_id_from_address` | examined-clean (dead helper, no callers) |

Certificate-consumption sites (class closure for the window check):
```
rg -n "is_valid_at" lattice/            -> identity.py:138 (def), runtime.py:564 (only caller)
rg -n "\.pin\(" lattice/                -> resolution.py:172, runtime.py:913
rg -n "except ResolutionError" lattice/ -> runtime.py:429,680,914; topology.py:224; cli.py:579
```
Disposition: `runtime.py:914` → Finding 1 amplifier + S1; `runtime.py:429/680`, `topology.py:224`,
`cli.py:579` → additional surfaces of Finding 1; `runtime.py:564` → the only window-enforcing path
(Finding 2 divergence).

## Design risks (max 2)

1. TOFU pins have no refresh mechanism. When a peer legitimately rotates its operational key, the
   stale pin keeps its old certificate and rejects the peer's new-key messages until an operator
   runs `reset_domain`; `verify_rotation` has no runtime caller. Whether automatic rotation handling
   is intended is under-documented. Not called a defect here.
2. `parse_address` accepts a single-label host equal to a node-ID-looking string (`lat_...`) as a
   domain when it fails the base32 regex — no confusion observed today, but the two namespaces
   share no separator. Speculative.

## Bound

- No live daemon, DNS, or hostile peer exercised; all three reproductions are in-process with the
  real resolver/runtime methods, real Ed25519 keys, and a fake transport/stub resolver. The 30 s
  cadence and sorted-batch ordering are read from source, not wall-clock observed.
- Whether a real deployment's `.well-known/lattice` continues serving an expired certificate is a
  deployment fact, not verifiable from the tree.
- Provider/upstream strictness of `b64url_decode` on unusual encodings was not exhaustively probed;
  the four mutation variants exercised are the ones the model demonstrably admits.
- Assigned files read in full; no unopened path.
