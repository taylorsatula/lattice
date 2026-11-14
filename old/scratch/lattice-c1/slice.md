# Slice — lattice-c1 (Phase 6)

57 finding tickets. Sliced by defect class and round. Round 1 first (egregious: security, data
loss, live breakage, trust) + findings other fixes build on; then round 2 (consistency); round 3
(polish/docs) is opt-in. Systemic/tree-wide mechanisms come before sub-module instances within a
round. One bucket = one picker = one mental model.

## Round 1 — egregious

**C1 — Outbound federation I/O, SSRF boundary & network policy** (7)
`tda2`(H) transport dead · `bpyf`(H) redirect SSRF · `bghd`(M) IPv6 URL · `y6ty`(H) cert escapes
resolver · `x105`(H) poison domain aborts batch · `zkm1`(L) NetworkPolicy unnormalized · `aefa`(M)
private_suffixes unanchored · (`g3fy` moved to C7).
Coupling: `bpyf` gated behind `tda2` — fix together. `y6ty`/`x105` share `_resolve_pending_senders`
isolation.

**C2 — Identity, certificate & signature enforcement** (8)
`za42`(H) pin binding silently rewritten · `jffh`(M) sequence monotonicity unenforced · `y175`(M)
expired certs accepted · `3vdm`(M) rotation has no receiving path · `k60v`(M) recovery destroys root
key · `jzv1`(L) expired cert at startup · `z9kq`(L) preimage re-serialized vs received bytes · `wz8m`(L)
rotate-operational non-atomic.

**C3 — Rate limiting & unauthenticated availability (DoS)** (6)
`bq2m`(H) self-attested card defeats gossip limits · `67kb`(H) buckets never evicted · `w7m6`(H)
cold-sender queue unbounded · `9qbf`(M) leftmost XFF trusted · `eyy7`(M) limiter after 401/403 · `6kqz`(L)
rate<1 locks out.

**C4 — Durable storage concurrency & migration atomicity** (8)
`6b8f`(H) statement lock ≠ transaction isolation · `dqa1`(M) backup omits WAL · `ym88`(L) claim
re-select collision · `st0g`(L) expiry vs leased message · `hna1`(L) circuit writes bypass txn ·
`hv81`(L) migrations no txn · `kvbw`(L) corrupt cache crash · `zmks`(L) stop() doesn't bound drain.

## Round 2 — consistency

**C5 — Custody receipt semantics** (7)
`jbbw`(M) receipt signature never verified · `twpy`(M) final rejected retried · `rq3k`(M) canonical
to_address bypasses guard · `47qy`(M) structural errors as 401 · `snfv`(L) rejected receipts not
persisted · `yv24`(L) cross-sender id collision · `pb3v`(L) transient failure → final rejected.

**C6 — HTTP error mapping & public-route contract** (5)
`pdb3`(L) Resolution/AddressError → 500 · `99bq`(M) malformed address → 500 · `2k63`(L) media-type/
version rejection unimplemented · `ak3t`(L) strict-JSON not applied to public bodies · `wy8z`(L)
error-code table unimplemented.

**C7 — Topology, gossip & discovery** (6)
`ktws`(M) stuck candidate re-fetched · `vckf`(M) block() doesn't clear discovery · `g3fy`(M)
oversized gossip bodies · `axh1`(L) attribution always None · `x2g2`(L) stale candidate demotes
established peer · `aefa`(M, if not fixed in C1).

**C8 — Config, credentials & CLI ergonomics** (4)
`6bse`(L) invalid TOML escapes ConfigError · `mpne`(L) malformed creds escape CredentialError ·
`njgm`(L) webhook.bearer_credential_name ignored · `47n1`(L) init accepts validator-rejected values.

**C9 — Outbound queue & scheduler cadence** (2)
`1jnj`(L) terminal transitions consume retries, no audit · `0p5c`(L) first-run arithmetic delays
maintenance.

## Round 3 — polish / docs (opt-in)

**C10 — Deploy & systemd** (2): `q04n`(M) ExecReload SIGHUP kills daemon · `fz1a`(M) ExecStart config
arg rejected.

**C11 — Document ↔ code drift** (3+): `z0fw` PROTOCOL 6 omits root_public_key · `4m8d` PROTOCOL 5.3
undocumented 503 · `ag8g` THREAT_MODEL 4.6 audit retention unimplemented.

## Unfiled / notes
- 4 `S-` entries flagged "needs one more pass" by dedupe — NOT ticketed, not offered.
- 5 verifier tier disagreements recorded in the manifest.
- Run-level ticket `kata#1824` (not a finding).
