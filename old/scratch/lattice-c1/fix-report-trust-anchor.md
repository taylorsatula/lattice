# Fix report — trust-anchor lifecycle (rows PIN, SEQ, EXP, ROT, CANON)

Files written (only these): `lattice/runtime.py`, `lattice/resolution.py`, `lattice/topology.py`,
`lattice/storage/repositories.py`, `lattice/identity.py`, `lattice/protocol/signing.py`.
`cli.py` untouched (sibling owns it). No commits; changes in working tree.

## Changed (per function, +added/-removed vs pre-fix snapshot b145ad9)

- `storage/repositories.py:DomainPinRepository.upsert` (+71/-1) — compare-and-set: when the
  existing pin binds the same node, prior = max(pin cert seq, `peers.current_certificate_sequence`,
  `MAX(peer_operational_keys.certificate_sequence)`); refuse lower sequence, refuse equal sequence
  with a different operational key. Different-node rewrites are deliberately NOT refused here so
  `cmd_trust_accept_transfer` keeps working (probed, B7); node-binding refusal lives at the
  re-resolution/pin boundary. The previously never-read `current_certificate_sequence` column is
  now read.
- `storage/repositories.py:PeerRepository.record_operational_key` (+43/-1) — stateful gate: refuse
  lower-than-max recorded sequence, refuse lower than `peers.current_certificate_sequence`, refuse
  same-sequence key swap; same-seq same-key stays idempotent.
- `protocol/signing.py:verify_message`, `verify_peer_card` (+15/-2, +1 import) — after
  `certificate.verify(root_identity)`, `certificate.is_valid_at()` else `IdentityError` (mirrors the
  exemplar).
- `resolution.py:resolve_with_ip` (+6/-1) — after cert.verify: `is_valid_at` else ResolutionError
  (expired certs rejected at intake, so pin()/bootstrap/candidate paths inherit it).
- `resolution.py:WellKnownResolver.pin` (+18/-11) — compare-and-refuse: existing pin with a
  different `node_id` → ResolutionError (transfer or explicit local reset required);
  `RepositoryError` from the upsert compare-and-set → ResolutionError (fail-closed idiom).
- `topology.py:verify_candidate` (+40/-12) — SEQ gate across pin AND peer rows (first contact
  passes; `result.certificate_sequence < prior` → TopologyError); `record_operational_key` moved
  BEFORE create/transition (no partially adopted state on refusal) with RepositoryError →
  TopologyError.
- `topology.py:_verify_against_well_known` (+14/-8) — card signature now verified over the
  RECEIVED card dict (new `card_dict` param, threaded from `verify_candidate`); cert expiry check
  `cert.is_valid_at(clock.now())` after cert.verify.
- `runtime.py:_pin_bootstrap_peers` (+40/-10) — guard now consults the pin table too; explicit
  compare-and-refuse against the existing pin's node binding; pin upsert gated by the
  compare-and-set; adopted key recorded via `record_operational_key` (ledger).
- `runtime.py:_certificate_for_node` (+55/-12) — freshness mechanism: serve the stored pin cert
  while valid and `last_verified_at` within `refresh_interval_seconds`; when lapsed/stale, advance
  the trust anchor via `resolver.pin()` (monotonicity-gated, persisted into `domain_pins`, the
  table `verify_inbound_message` reads); no-pin branch now persists the resolved anchor instead of
  re-fetching per message; node mismatch never adopted.
- `identity.py:OperationalCertificate.verify` (+9/-1 docstring only, no behavior change) — records
  the CANON decision: the authoritative cert preimage is `to_dict()` (UTC `Z`, second precision);
  `from_dict` normalizes any `+00:00` encoding, so all cert verify sites already agreed — the
  disagreement was the CARD preimage (raw vs `model_dump`), fixed in topology.

Same-hazard extensions inside named functions (beyond the enumerated line ranges, reported):
`verify_candidate` stores the received card JSON verbatim in transient cards (re-serialized
`model_dump` broke `+00:00` card signatures downstream); bootstrap records the adopted key and
drops the 2nd-lookup comment.

## Exemplars mirrored
`runtime.py:verify_gossip_sender_card` — `cert.verify(root_identity)` THEN `cert.is_valid_at(now)`;
and the repo's `except <Error> as exc: raise ResolutionError(...)` fail-closed idiom.

## Verification: EXECUTED
Real infrastructure, no mocks: Dockerized HTTPS well-known server on `127.0.0.1:443` (real TLS
against a probe CA, real DNS via `localhost`, real Ed25519 roots/ops/certs, real migrated SQLite,
real `RuntimeCoordinator.start()` bootstrap). Hostile inputs: a live well-known advertising a
different node ID; a root-signed lower-sequence cert; an expired cert; a rotated cert; a
`+00:00`-encoded peer card.

Command: `timeout 300 .venv/bin/python /tmp/lattice-probe/probe.py` (+ a 2-check follow-up probe).
Observed: **18/18 PASS**, then **2/2 PASS** —
(a) A1 bootstrap pins live node A; A2 steady-state restart keeps pin on A; A3 hostile
re-resolution refused ("refusing to re-pin localhost to node …; pinned to …"), pin still A; A4
after explicit `reset_domain`, restart rebinds to live node B;
(b) B2 re-pin refused ("certificate sequence 3 would roll back recorded sequence 5"), pin seq
still 5; B3 `verify_candidate` → "certificate sequence rollback … 3 does not advance 5"; B4/B5/B6
repo gates; B7 transfer-style different-node upsert still allowed;
(c) C1 expired-cert inbound message → RuntimeError "… operational certificate is expired or not
yet valid" (401-equivalent);
(d) D1 rotated-cert message verified `(node, False)`; D2 pin advanced to seq 2; F1/F2
mid-lifetime rotation adopted via pin-staleness refresh;
(e) E1 `+00:00` card passes `verify_gossip_sender_card`; E2 passes
`_verify_against_well_known`/`verify_candidate`; E3 transient card stored verbatim; E4 the old
`model_dump` preimage demonstrably fails with SignatureError.

Probes and all fixtures removed (container killed+deleted, /tmp/lattice-probe deleted).

## Test suite
`pytest tests/`: **158 passed, 5 failed, 1 skipped**. All 5 failures are pre-existing fixture
time-skew exposed by the mandated EXP enforcement: `tests/test_topology.py` pins `FakeClock` at
2026-01-01 while `conftest.other_node` mints certs with `valid_from=datetime.now(UTC)` (real now
2026-09-28), so the cert is legitimately "not yet valid" at the fake date. Test files are outside
my write scope; the real-clock behavior is proven correct by probes C/D.

## Found but not touched (owed)
- `identity.verify_rotation` still has zero callers; a rotation-statement ingestion path would be
  a new mechanism — out of scope. Rotation adoption instead happens at re-resolution/pin
  boundaries (probed D/F).
- Residual cost, disclosed: while a pinned peer's cert is expired/stale AND its domain is
  unreachable, each inbound message from it triggers one well-known fetch attempt (bounded by
  transport timeouts); healthy domains are bounded to one refresh per `refresh_interval_seconds`
  (300s default) via `last_verified_at`.
