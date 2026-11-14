# Merge manifest — lattice-c1 (Phase 5 dedupe)

Inputs: 23 primed hunter reports (79 findings), 13 blind reports (41 findings), 2 orchestrator-decided
inputs (OV-1, OV-2). Total input entries: 122. Tickets created: 57. Drops by calibration rule: 0.
S- entries (no ticket, "needs one more pass"): 4. Flags: 5 tier disagreements (recorded, not resolved).

Convention note: where verifier-corrected tiers conflict within a merged entry, the ticket carries the
highest corrected tier and this manifest records the disagreement. No entry was dropped by a standing
calibration rule (0 REFUTED verdicts); the REACHABILITY KIND rule was applied by carrying gate/test-only
markers onto tickets rather than dropping.

## Primed findings (input order)

### hunt-a1 (HTTP entry surface)
- hunt-a1#1 XFF first-element trust → kept → G1 (kata#9qbf)
- hunt-a1#2 canonical to_address ownership bypass → kept → F2 (kata#rq3k)
- hunt-a1#3 cold-sender unbounded queue → merged into A1 (kata#w7m6)
- hunt-a1#4 malformed to_address 500 → kept → F1 (kata#99bq)
- hunt-a1#5 admin_submit ResolutionError 500 → kept → F3 (kata#pdb3)
- hunt-a1#6 structural errors → 401 → merged into Q1 (kata#47qy)

### hunt-a2 (operator CLI)
- hunt-a2#1 startup key/cert mismatch → kept → D4 (kata#jzv1)
- hunt-a2#2 rotate destructive writes before validation → kept → K3 (kata#wz8m)
- hunt-a2#3 init accepts values its validator rejects → kept → K4 (kata#47n1)

### hunt-b1a (lifecycle & cadence)
- hunt-b1a#1 shared-connection rollback → merged into C1 (kata#6b8f)
- hunt-b1a#2 first-run monotonic sentinel delay → kept → J1 (kata#0p5c)

### hunt-b1b (outbound delivery & signing)
- hunt-b1b#1 transport TypeError → kept → B1 (kata#tda2)
- hunt-b1b#2 rejected receipt retried → kept → E1 (kata#twpy)
- hunt-b1b#3 unresolved-domain set unbounded → merged into A1 (kata#w7m6)
- hunt-b1b#4 redirect SSRF (latent) → kept → B2 (kata#bpyf)
- hunt-b1b#5 receipt signature never verified → kept → E2 (kata#jbbw)

### hunt-b1c (inbound custody / rate limit / webhook)
- hunt-b1c#1 cold-sender queue unbounded → merged into A1 (kata#w7m6)
- hunt-b1c#2 canonical to_address bypass → merged into F2 (kata#rq3k)
- hunt-b1c#3 malformed address 500 → merged into F1 (kata#99bq)
- hunt-b1c#4 transient custody failure → final rejected → kept → E3 (kata#pb3v)
- hunt-b1c#5 sub-1.0/min permanent lockout → kept → G4 (kata#6kqz)

### hunt-c1 (persistence & migrations)
- hunt-c1#1 shared-connection cross-contamination → merged into C1 (kata#6b8f)
- hunt-c1#2 migrations not transactional → kept → I1 (kata#hv81)
- hunt-c1#3 WAL-blind backup → kept → I2 (kata#dqa1) [tier conflict L vs M recorded]

### hunt-c2 (connection & cache layer)
- hunt-c2#1 shared-connection transactions → merged into C1 (kata#6b8f)
- hunt-c2#2 corrupt cache crash → kept → I3 (kata#kvbw)
- hunt-c2#3 extensionless cache path ValueError → S- / needs one more pass (verifier: no in-tree producer of a suffixless path; library-API only)

### hunt-d1 (network policy & SSRF)
- hunt-d1#1 redirect policy bypass → merged into B2 (kata#bpyf)
- hunt-d1#2 unanchored private_suffixes → kept → P1 (kata#aefa)
- hunt-d1#3 IPv6 unbracketed URL → kept → B3 (kata#bghd)
- hunt-d1#4 NetworkPolicy construction normalization skip → kept → P2 (kata#zkm1)
- hunt-d1#5 CGNAT 100.64/10 not rejected → S- / needs one more pass (verifier: environment-armed, ungroundable in-tree)

### hunt-d2 (credentials & config)
- hunt-d2#1 bearer_credential_name ignored → kept → M1 (kata#njgm)
- hunt-d2#2 credential exceptions escape → kept → M2 (kata#mpne)
- hunt-d2#3 TOMLDecodeError escapes ConfigError → kept → M3 (kata#6bse)

### hunt-e1 (identity & key lifecycle)
- hunt-e1#1 expired certs accepted → kept → D1 (kata#y175)
- hunt-e1#2 rotation has no receiving-side path → kept → D2 (kata#3vdm)
- hunt-e1#3 sequence monotonicity unenforced → kept → D3 (kata#jffh)
- hunt-e1#4 no startup self-check → merged into D4 (kata#jzv1)

### hunt-e2 (canonicalization & protocol models)
- hunt-e2#1 §4.1 strict JSON not applied → kept → L2 (kata#ak3t)
- hunt-e2#2 §11 media type unenforced → kept → L3 (kata#2k63)
- hunt-e2#3 preimage over re-serialized objects → kept → N3 (kata#z9kq); its verifier-priced added
  mechanism (stuck-candidate ValueError retry loop) split out as N2 (kata#ktws)

### hunt-f1 (gossip propagation)
- hunt-f1#1 self-attested card defeats gossip rate limit → kept → G3 (kata#bq2m)
- hunt-f1#2 attributed_to always None → kept → H4 (kata#axh1)

### hunt-f2 (topology & peer state)
- hunt-f2#1 expired certs on topology path → merged into D1 (kata#y175)
- hunt-f2#2 stale candidate demotes established peer → kept → H2 (kata#x2g2)
- hunt-f2#3 block() discovery set not cleared → kept → H3 (kata#vckf) [reachability TESTS ONLY]

### hunt-g1 (resolution & addressing)
- hunt-g1#1 malformed cert escape / batch starvation → kept → A3 (kata#y6ty)
- hunt-g1#2 pin path never checks cert window → merged into D1 (kata#y175) (verifier: same family as hunt-e1#1)

### hunt-h1 (message models & lifecycle)
- hunt-h1#1 expiry sweep vs in-flight lease → kept → I6 (kata#st0g) (merged with hunt-s3#2)

### hunt-h2 (webhook delivery & inbound custody)
- hunt-h2#1 poison domain aborts batch → kept → A2 (kata#x105)
- hunt-h2#2 failed domains never discarded → merged into A1 (kata#w7m6)
- hunt-h2#3 cross-sender message_id collision → kept → E4 (kata#yv24)

### hunt-k1 (deploy & packaging)
- hunt-k1#1 ExecStart argparse failure → kept → K1 (kata#fz1a)
- hunt-k1#2 ExecReload SIGHUP → kept → K2 (kata#q04n) [tier conflict M vs L recorded; gate behind K1 recorded]

### hunt-q-error (error-path enumeration)
- hunt-q-error#1 cold-sender queue unbounded → merged into A1 (kata#w7m6)
- hunt-q-error#2 rejected receipt retried → merged into E1 (kata#twpy)
- hunt-q-error#3 transient failure → final rejected → merged into E3 (kata#pb3v)
- hunt-q-error#4 401 misclassification / canonical unknown-sender terminal → kept → Q1 (kata#47qy)
- hunt-q-error#5 malformed to_address 500 → merged into F1 (kata#99bq)
- hunt-q-error#6 audit gap on deferral/terminal branches → kept → Q2 (kata#1jnj)

### hunt-s1 (API ↔ runtime seam)
- hunt-s1#1 canonical to_address guard → merged into F2 (kata#rq3k)
- hunt-s1#2 unresolved-domain eviction → merged into A1 (kata#w7m6)
- hunt-s1#3 admin_submit 500 → merged into F3 (kata#pdb3)
- hunt-s1#4 malformed address 500 → merged into F1 (kata#99bq)
- hunt-s1#5 message rate limiter after early returns → kept → A4 (kata#eyy7)

### hunt-s3 (storage ↔ runtime seam)
- hunt-s3#1 circuit writes uncommitted → kept → I5 (kata#hna1)
- hunt-s3#2 expiry sweep vs in-flight lease → merged into I6 (kata#st0g)
- hunt-s3#3 claim re-select same-second → kept → I7 (kata#ym88)
- hunt-s3#4 connection-wide rollback (claim observed-but-lost) → merged into C1 (kata#6b8f)

### q-contract (docs vs code)
- q-contract#1 bootstrap pin rewrite → kept → M4 (kata#za42)
- q-contract#2 documented recovery destroys root key → kept → K5 (kata#k60v)
- q-contract#3 §9 error codes → kept → L1 (kata#wy8z)
- q-contract#4 audit retention 30 days → kept → L4 (kata#ag8g)
- q-contract#5 §5.3 cold-sender 503 undocumented → kept → L5 (kata#4m8d)

### seam-s2 (transport ↔ topology seam)
- seam-s2#1 transport TypeError (gate mechanism) → merged into B1 (kata#tda2)
- seam-s2#2 IPv6 unbracketed URL → merged into B3 (kata#bghd)

### seam-s4 (protocol ↔ verification seam)
- seam-s4#1 rejected receipt retried → merged into E1 (kata#twpy)
- seam-s4#2 receipt signature never verified → merged into E2 (kata#jbbw)

## Blind-pass findings (input order by report)

### blind-hunt-a1
- F1 malformed from/to address 500 → merged into F1 (kata#99bq) [tier conflict M vs L recorded]
- F2 XFF trust → merged into G1 (kata#9qbf)
- F3 unbounded _buckets → kept → G2 (kata#67kb)
- F4 §11 media type → merged into L3 (kata#2k63)

### blind-hunt-b1a
- B1A-1 cross-thread transaction interleaving → merged into C1 (kata#6b8f)
- B1A-2 first-run sentinel delay → merged into J1 (kata#0p5c)
- B1A-3 unbounded executor drain → kept → J2 (kata#zmks)

### blind-hunt-b1b
- F1 rejected receipt retried → merged into E1 (kata#twpy)
- F2 cold-sender queue unbounded → merged into A1 (kata#w7m6)

### blind-hunt-b1c
- b1c-1 gossip batch byte bound / 413 circuit network-wide → kept → H1 (kata#g3fy)
- b1c-2 rejected receipts never persisted / non-identical bytes → kept → E5 (kata#snfv)

### blind-hunt-c1
- conn-txn shared-connection transactions → merged into C1 (kata#6b8f)
- wal-backup WAL-blind backup → merged into I2 (kata#dqa1) [tier conflict M vs L recorded]
- mig-atomic migrations not transactional → merged into I1 (kata#hv81)

### blind-hunt-c2
- c2-1 shared-connection transactions (202 custody ack without durable custody) → merged into C1 (kata#6b8f) [tier conflict H vs M/L recorded]
- c2-2 corrupt cache crash → merged into I3 (kata#kvbw)

### blind-hunt-d1
- #1 redirect SSRF (gated) → merged into B2 (kata#bpyf)
- #2 IPv6 unbracketed URL → merged into B3 (kata#bghd)
- #3 unanchored private_suffixes → merged into P1 (kata#aefa)
- #4 NetworkPolicy normalization skip → merged into P2 (kata#zkm1)
- #5 CGNAT 100.64/10 → S- / needs one more pass

### blind-hunt-g1
- G1-1 malformed cert escape → merged into A3 (kata#y6ty)
- G1-2 pin path never checks cert window → merged into D1 (kata#y175)
- G1-S1 cold-sender queue unbounded → merged into A1 (kata#w7m6)

### blind-hunt-h2
- BH2-1 poison domain batch abort → merged into A2 (kata#x105)
- BH2-2 failed domains never discarded → merged into A1 (kata#w7m6)
- BH2-3 cross-sender message_id collision → merged into E4 (kata#yv24)

### blind-hunt-k1
- #1 ExecStart argparse → merged into K1 (kata#fz1a)
- #2 ExecReload SIGHUP → merged into K2 (kata#q04n) [tier conflict M vs L recorded]

### blind-q-contract
- F1 rejected receipt retried → merged into E1 (kata#twpy)
- F2 cert expiry + sequence monotonicity unenforced → split across D1 (kata#y175) and D3 (kata#jffh)
- F3 receipt signature never verified → merged into E2 (kata#jbbw) [tier conflict M vs L recorded]
- F4 §9 error codes → merged into L1 (kata#wy8z)
- F5 §4.1 strict JSON → merged into L2 (kata#ak3t)
- F6 §11 media type → merged into L3 (kata#2k63)
- F7 §6 peer-card root_public_key omission → kept → L6 (kata#z0fw)
- F8 audit retention → merged into L4 (kata#ag8g)
- F9 well-known regenerate-on-endpoint-change MUST → S- / needs one more pass (latent; MUST unimplementable under invariant 2 as built)

### blind-seam-s2
- F1 transport TypeError → merged into B1 (kata#tda2)
- F2 IPv6 unbracketed URL → merged into B3 (kata#bghd)

### blind-q-error
- q-error-H-queue cold-sender queue unbounded → merged into A1 (kata#w7m6)

## Orchestrator-decided inputs

- OV-1 (_LockedConnection implicit `with conn:` commit bypass, CPython 3.12; CONFIRMED by direct
  execution) → merged into C1 (kata#6b8f), provenance orchestrator-decided.
- OV-2 (every OutboundTransport.request() raises TypeError on fields= before network I/O, urllib3
  2.7.0; CONFIRMED by direct execution; highest-consequence finding of the run) → merged into B1
  (kata#tda2), provenance orchestrator-decided.

## Verified clean (with caveats where noted)

Per-report "Checked and clean" claims carried forward (unverified-clean surfaces the verifier passes
did not refute). Highlights: require_admin / require_content_length / require_ready gating; custody
202+rejected-receipt per PROTOCOL §8 shape; claim/lease owner-guarded CAS semantics; retry/backoff/expiry
arithmetic; circuit-breaker threshold/reset arithmetic; rate-bucket snapshot/restore round-trip; shutdown
ordering (scheduler before executors, drain before persist); webhook idempotency-key derivation and
delivery exception surface; preimage agreement for well_known/message/transfer/rotation/contact_card/
webhook_envelope kinds (cross-kind confusion impossible); SQL construction fully parameterized; FK
ordering at the custody boundary; wheel packaging file set == source; nginx config vs code constants;
systemd credential-name wiring; root-key confinement on every serving path (invariant 2); resolution
fail-closed gate ordering except the cert block; addressing parse_address fail-closed.

Census caveats bounding clean verdicts: audit INFO events written by no stock deployment (log-level
gate) — the "clean" audit paths are mostly write-dead; `tests/` never exercises a real transport
(MagicMock spec masks the kwargs fault); candidate intake caps enforceable only against honest
attribution; block feature has no production caller (blocked-sender chain reachable only via tests);
b1b E2 candidate (durable claim held by in-flight future at stop) dispositioned NOT a defect by the
verifier; stale `dist/` wheels with 14 deleted legacy modules out of scope per invariant 8.

## S- entries (needs one more pass; no ticket)

- hunt-c2#3 — extensionless cache path ValueError; verifier: no in-tree producer at all (library-API only).
- hunt-d1#5 and blind-hunt-d1 #5 — CGNAT 100.64.0.0/10 not rejected in public mode; environment-armed,
  ungroundable in-tree; TLS handshake blocks the POST-forwarding outcome.
- blind-q-contract F9 — §5.1 regenerate-well-known-on-endpoint-change MUST; latent, doc/architecture conflict.

## Single-pass side discoveries (unverified; recorded for coverage, not verdicted)

hunt-a1: parse_address lowercases while config.domain is not normalized (folded into F2's case-sensitivity
mechanism); RequestValidationError handler puts a Python repr in detail (cosmetic). hunt-a2: create-then-chmod
window on secret staging files; CLI commands cannot reach systemd-encrypted credentials outside the unit.
hunt-b1a: circuit writes uncommitted (→ I5); cmd_serve start() outside try/finally (latent);
RuntimeSettings not TOML-configurable. hunt-b1b: owner-string double prefix (cosmetic). hunt-c1: placeholder
root keys are permanent (ensure_root_history DO NOTHING with "" fallback). hunt-c2: cross-process cache
recreation guard; deprecated sqlite adapters. hunt-d1: outbound response body has no size cap; private CA
bundle is additive not exclusive; empty-suffix fail-open (LATENT); Host header forwarded on redirect (gated,
folded into B2 constraints). hunt-d2: _is_https_url/_is_valid_domain shallow; server.workers dead knob
(recorded in M1). hunt-e1: b64url_decode leniency; Message.timestamp never freshness-checked (protocol-
conformant). hunt-e2: contact_card has no protocol model; webhook_envelope absent from doc §4.4;
resolution content-type substring match (folded into L3). hunt-f1: candidate_ttl_seconds config is dead;
candidate caps bypassable by introducer/hostname variation (design risk). hunt-f2: count-then-insert TOCTOU;
verify-loop fetch amplification; expired transient cards visible up to 60s. hunt-g1/hunt-h2 covered above.
hunt-h1: inbound_service.stage() comment drift; outbound expiry produces no audit event (folded into Q2).
hunt-h2/k1: classify_status production-dead and 3xx-divergent from deliver; webhook_state write-only;
no pruning of terminal inbound/webhook/audit rows (audit half folded into L4). hunt-k1: root-run pre-start
migration ownership risk (design risk). q-contract: PeerCard §6 omission (= L6); §1/§4.4 contact_card
internal inconsistency. q-error: starlette 404/405 bypass the problem-details handler (SD1); cold-sender 503
precedes the 403 check (SD2); _certificate_for_node swallows ResolutionError (SD3). seam-s1/s2/s3/s4:
design risks as reported. blind-b1a: S1 is_ready ignores _started (TESTS ONLY); S2 _persist_rate_limits
first-failure aborts remainder; S3 _is_https_url accepts scheme-only string. blind-b1c: transient-card
growth pricing. blind-c1: S1 uncommitted cache writes (= I5); S2 durable schema v2 in dist wheels
(out-of-scope per invariant 8); S3 release-fixture coverage gap. blind-c2: S1 commit-commits-peer's-work
non-isolation (same root as C1); S2 LOOSE_ENDS Phase 8 claim false. blind-hunt-d1: SD1 empty-suffix
fail-open (LATENT, folded into P1 constraints); SD2 Host header forwarding (gated). blind-hunt-k1:
nginx has no limit_req despite ARCHITECTURE.md claim (docs-vs-config). blind-q-contract SD1 protocol
responses carry wrong media type (L, unpriced-by-verifier envelope; recorded here only); SD2/S3/S4 as
reported. blind-q-error SD1/SD2/SD3 as reported.

## Counts

- Input entries: 122 (79 primed + 41 blind + 2 orchestrator-decided)
- Tickets created: 57 (short IDs recorded beside each kept entry above)
- Dropped by calibration rule: 0 (0 REFUTED verdicts)
- S- / needs-one-more-pass: 4 entries (hunt-c2#3, hunt-d1#5, blind-hunt-d1 #5, blind-q-contract F9)
- Flags (tier disagreements recorded on tickets, not resolved): C1 [H vs M vs L], E2 [M vs L],
  I2 [M vs L], F1 [M vs L], K2 [M vs L]; plus the K2 reachability gate-behind-K1 correction.
- Verified-clean: carried per report above with census caveats.
