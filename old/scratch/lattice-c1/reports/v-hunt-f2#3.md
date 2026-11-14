# v-hunt-f2#3 — PRIMED VERIFIER verdict on hunt-f2 finding 1

Claim under test: **hunt-f2#1** [reported M] — "Candidate verification accepts expired operational
certificates and expired cards", file `scratch/lattice-c1/reports/hunt-f2.md`.

**Verdict: CONFIRMED** (tier M retained; frequency qualified, outcome bounded).

Reachability kind: **PRODUCTION** (a peer's own gossip request or a third-party gossip batch is a
real network trigger; the demoted certificate is not test-only).

---

## Re-derived frame (from source, not the claim)

The trust-verification path for a gossip-introduced candidate is:

1. `api.py:242 receive_gossip` → `body.get("cards")` → `gossip_service.receive_batch(cards,
   introduced_by=...)` (`api.py:267`).
2. `gossip.py:73 receive_batch` → `PeerCard.model_validate(card)` (model only rejects
   `expires_at > issued_at + MAX_PEER_CARD_LIFETIME_SECONDS`; it never compares to `now` — verified
   by execution, see below) → `topology.accept_candidate(...)` (`gossip.py:124`).
3. `topology.py:167 accept_candidate` → `can_accept_candidate` (self / blocked / already-known /
   caps; **no time check**) → `cache.add_candidate(..., expires_at=model.expires_at)`.
4. `runtime.py:1124 _run_verify_candidates` (60 s) → `topology.py:199 verify_candidate` →
   `resolver.resolve_with_ip(card.domain)` → `_verify_against_well_known`.
5. `topology.py:281 _verify_against_well_known`: `WellKnownDocument.model_validate` (no
   validity check on the embedded cert), `cert.verify(root_identity)` at `topology.py:322`,
   `verify_peer_card` at `topology.py:328`, then `create_peer(VERIFIED)` / `transition(VERIFIED)`
   at `topology.py:241-266` and `record_operational_key(...)`.

`OperationalCertificate.verify` (`identity.py:125`) verifies the root signature only.
`is_valid_at` (`identity.py:138`) exists and is called **once in the entire tree**:
`runtime.py:564 verify_gossip_sender_card`. It appears nowhere in `topology.py`, `resolution.py`,
or the message path. `rg -n "is_valid_at" lattice/` → `identity.py:138` (def),
`runtime.py:564` (only call).

`rg -n "expires_at|valid_until" lattice/topology.py` → all hits are storage/propagation of the
timestamp (`accept_candidate` store, transient-card expiry, discovery `expires_at`) — **no
comparison against `now`, and no comparison of a cert `valid_until` against `now`.**

---

## Per-component adjudication

### Mechanism — CONFIRMED
`cert.verify` is signature-only; the candidate path neither calls `is_valid_at` nor compares
`card.expires_at` to `now`. Executed against the tree (`.venv`):

- `cert.is_valid_at(now) == False` for a cert with `valid_until = now - 1 day`; `cert.verify(root_id)`
  **passes**.
- `verify_peer_card(signed_card, expired_cert, root_id)` — the exact final check at
  `topology.py:328` — **passes** with an expired cert.
- `PeerCard.model_validate` **accepts** a properly signed card whose `expires_at` is in the past
  (`_check_expiry` at `models.py:181` only bounds lifetime versus `issued_at`).

### Trigger — CONFIRMED
A node whose operational certificate window has lapsed but which still (a) gossips its own card
and (b) serves a well-known document containing that expired cert. Both are true of a daemon that
has run past its certificate lifetime: the well-known served at `GET /.well-known/lattice` is the
static `self._well_known_document` loaded at startup (`runtime.py:183/300`, `api.py:227`), and the
card embeds `self._identity.certificate` (`gossip.py:196`) — the certificate loaded at startup.
There is **no automatic rotation or renewal** anywhere in the runtime
(`create_operational_certificate(..., valid_until=now + 30 days)` at `cli.py:115` and the manual
`rotate` command at `cli.py:746-770` are the only issuance sites; the runtime schedules no cert
task). A third party gossiping the lapsed node's card produces the same path. Acceptance takes at
most one gossip batch plus one 60 s verify cycle.

### Frequency — CONFIRMED-QUALIFIED
The claim's population ("every gossiped card whose node's cert window has lapsed") is grounded by
a concrete cadence: the default operational-certificate lifetime is 30 days (`cli.py:115`,
`cli.py:770`) and rotation is a manual operator step with no warning, so any node left running
≥30 days without a manual `rotate` triggers this deterministically. This is an operator-conditioned
cadence, not a per-request one; I retain the claim's DEMONSTRATED framing but record that it is
conditional on the operator not rotating within the 30-day window (ungroundable exact rate).

### Outcome — PARTIALLY REFUTED (one half overstated)
- Cert half (substantive): `verify_candidate` promotes the node to `VERIFIED`, records the expired
  key via `record_operational_key`, stores a transient card, and `_fill_discovery`
  (`topology.py:440`) selects `VERIFIED` peers into the discovery set → `select_gossip_targets`
  (`topology.py:467`) gossips to it. Wrong durable state per `PROTOCOL.md` §3.3 MUST.
- **Card half: the differential outcome is overstated.** The card's `expires_at` gates candidate
  retention (`prune_candidates`, 60 s), and the *live* well-known fetch — not the card — supplies
  the authoritative endpoints and certificate. Verifying an "expired card" therefore yields
  essentially the same durable state as the cert half. The card-expiry omission is a real spec
  violation but not a distinct harm.
- **Impact bound (adversarial check): this is not authentication bypass and not key substitution.**
  The identity binding (root key → node ID, root signature on the well-known, live DNS fetch) is
  still enforced, so an expired cert cannot be used to impersonate a different node or to keep an
  old operational key alive against a node that *did* rotate (the rotated key appears in the
  served well-known, so old-key cards fail). The harm is limited to freshness/state hygiene: a
  lapsed node is materialised as `VERIFIED` and is gossiped with. This is why I keep M rather than
  H; an outcome-only reviewer could argue L, but the pinned scale's explicit clause ("divergence
  between two paths that must agree") plus the §3.3 MUST make M the defensible reading.

### Divergence — CONFIRMED
`verify_gossip_sender_card` (`runtime.py:564`) rejects the same expired cert that the topology path
accepts. A single gossip batch from a lapsed node on the wire is rejected for identity-keyed rate
limiting and simultaneously accepted for trust via `receive_batch` → `verify_candidate`.

---

## Additional mechanisms / earlier failure sites (same or adjacent trace)

1. **Earlier failure site on the exact trace: `resolution.py:107`.** `resolve_with_ip` (called by
   `verify_candidate` at `topology.py:222`) validates the well-known and calls `cert.verify` at
   `resolution.py:107` with the same signature-only check. Fixing only `topology.py` leaves the
   resolver admitting expired certs into **pins**, which feed bootstrap pinning
   (`runtime.py:_pin_bootstrap_peers`) and message-certificate resolution
   (`runtime.py:_certificate_for_node`). The check belongs in the shared cert/well-known
   verification layer (or `OperationalCertificate`), not only in `topology.py`.
2. **Adjacent trace: `runtime.py:658 verify_inbound_message` does not check `is_valid_at`
   either.** `_certificate_for_node` returns the pinned/loaded cert and
   `verify_message(message, cert, root_identity)` verifies the signature only. A message signed
   with an expired operational certificate (a sender that ran past the 30-day window without
   rotation, whose pin holds the expired cert) is accepted into **durable custody**. This is the
   same missing check on the message path, with the custody semantics of the M band.
3. **Sequence monotonicity (same §3.3 MUST sentence) is unenforced.** `record_operational_key`
   (`repositories.py:293`) upserts on `(node_id, certificate_sequence)` and `PeerRepository.transition`
   (`repositories.py:251-276`) overwrites `current_certificate_sequence` unconditionally; nothing
   compares the new sequence against the stored one. Reachability is limited here (the candidate
   path only runs for peers not already known, so a lower-sequence cert cannot overwrite a known
   peer via this route), so I price it latent — but it is part of the same MUST and must be handled
   by the same fix.

## Side discoveries (single-pass, priced)

- **Message path accepts expired certs (adjacent trace, item 2 above).** Severity M (custody
  accepted on a signature the spec says MUST be rejected), frequency grounded the same way as the
  claim (30-day default, no auto-rotation), production reachable via `POST /lattice/v1/messages`.
  Fix constraint: must be fixed at the cert layer together with topology, or a topology-only fix
  leaves it in place.
- **Expired transient cards are propagated.** `CacheRepository.list_transient_cards`
  (`repositories.py:551`) and `select_batch_to_send` (`gossip.py:232`) do not filter `expires_at`;
  pruning runs on the 60 s `expiry_cleanup` task, so an expired card can be re-gossiped for up to
  ~60 s. Severity L (bounded window, no lasting state). Latent in the sense that harm is a transient
  protocol wart.

## Fix-direction constraints

- Check certificate validity (`valid_from <= now < valid_until`) at the **shared** verification
  boundary (`resolution.py` / `OperationalCertificate`), so both the candidate path and the pin /
  bootstrap / message paths are covered; a `topology.py`-only patch ships the adjacent message and
  pin defects underneath.
- Enforce the card's `expires_at` against `now` at intake (`accept_candidate`), not only lifetime
  versus `issued_at`.
- Enforce certificate `sequence` monotonicity in the same change (the same §3.3 sentence); do not
  treat the validity-window fix as complete.

## Checked and clean

- `verify_gossip_sender_card` correctly rejects an expired cert (`runtime.py:564`); the divergence
  is real, not a misread.
- `MAX_OPERATIONAL_CERTIFICATE_LIFETIME_SECONDS = 90 days` bounds cert lifetime; the 30-day
  generation default is within it.
- `PeerCard._check_expiry` correctly bounds `expires_at` against `issued_at`; it simply does not
  compare to `now` (confirmed by execution).
- `prune_candidates` correctly deletes candidates past `expires_at`; `list_candidates` simply does
  not filter, which is why the ≤60 s window exists.

## Enumeration

```
$ rg -n "is_valid_at" lattice/
lattice/identity.py:138:    def is_valid_at(self, when: datetime | None = None) -> bool:
lattice/runtime.py:564:            if not cert.is_valid_at(self._clock.now()):

$ rg -n "\.verify\(|verify_message\(|verify_peer_card\(" lattice/ | grep -v "def "
lattice/resolution.py:107:  cert.verify(root_identity)          # no is_valid_at  -> expired cert accepted (pin/resolver)
lattice/topology.py:322:    cert.verify(root_identity)          # no is_valid_at  -> expired cert accepted (candidate)
lattice/topology.py:328:    verify_peer_card(...)               # no is_valid_at
lattice/gossip.py:272:    verify_peer_card(...)               # wrapper
lattice/cli.py:366:       cert.verify(...)                 # offline pin display
lattice/runtime.py:563:   cert.verify(root_identity)          # followed by is_valid_at at :564 (rate-limit path only)
lattice/runtime.py:658:   verify_message(...)                 # no is_valid_at  -> expired cert message accepted to custody
lattice/protocol/signing.py:43/58: certificate.verify(...) # no is_valid_at
```

Verdict per enumerated cert-verification site: `resolution.py:107` finding (earlier site on trace);
`topology.py:322/328` finding (the claim); `runtime.py:658` finding (adjacent trace, side);
`runtime.py:563` examined-clean (has the check); `cli.py:366` out-of-scope offline display;
`gossip.py:272` examined-clean wrapper.

## Bound

- No live daemon or real DNS/peer interaction was run; the "lapsed node still serves its expired
  well-known" premise is derived from the static `self._well_known_document` and
  `self._identity.certificate` loads, not observed on infrastructure. What the deployed nginx
  serves after a node is retired is unverified (upstream strictness / operator behaviour boundary).
- Exact real-world rate at which operators let the 30-day certificate lapse is unmeasurable here;
  the frequency is grounded on the code's cadence (30-day default, manual rotation only), not on
  observed deployment data.
- `cli.py` was not read end to end; the rotation surface was read only far enough to confirm it is
  manual and 30-day-defaulted.
