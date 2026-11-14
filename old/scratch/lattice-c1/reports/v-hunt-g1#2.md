# v-hunt-g1#2 — PRIMED VERIFIER: hunt-g1 finding 2

Claim under test: **hunt-g1#2 [M] — Pin path never checks the operational certificate validity
window** (`scratch/lattice-c1/reports/hunt-g1.md`).

Verdict: **ADJUSTED.** The mechanism is real and reproduced at the resolution site, but the finding
is not an independent defect — it is the resolution-site instance of the already twice-reported
"expired certificate accepted" family (`hunt-e1#1`, `hunt-f2#1`), and the harm it names is delivered
by `verify_message`, not independently by the pin path. Severity stays M (matches the merged
family); frequency is grounded with one caveat.

Reachability kind: **PRODUCTION** (a real domain fetch whose `.well-known/lattice` serves an
already-expired certificate).

---

## Frame re-derived from source (before checking the claim)

- **What `resolve_with_ip` checks today.** `resolution.py:103-109` builds the cert and calls
  `cert.verify(root_identity)`; there is no `is_valid_at`, no `valid_from`/`valid_until` comparison.
  Confirmed by reading resolution.py:104-109 and by `rg -n "is_valid_at" lattice/` → definition
  (identity.py:138) + one caller (runtime.py:564, gossip sender card) only. Confirmed.
- **What the pin consumer checks.** `runtime._certificate_for_node` (runtime.py:665-681) returns the
  stored pin cert whenever a pin exists; `runtime.verify_inbound_message` (runtime.py:654-658) calls
  `verify_message`, which is `certificate.verify(root_identity)` + `verify_object(...)` with no
  window check (protocol/signing.py:51-54). Confirmed.
- **Whether the pin is refreshed.** `pin()` is called only from `resolution.resolve_address`
  (resolution.py:172, only when `get_pin` is None) and `runtime._resolve_pending_senders`
  (runtime.py:913, cold senders). `rg -n "\.pin\(" lattice/` returns those two only; `_build_scheduler`
  (runtime.py:342-393) has no pin-refresh task. Pins are TOFU-forever. Confirmed.
- **Cert lifetime.** `lattice init` / `keys rotate-operational` mint 30-day certs (cli.py:113-116,
  766-771), bounded ≤90d at creation (identity.py:256). Confirmed.
- **The validity predicate.** `OperationalCertificate.is_valid_at` (identity.py:138-141) is correct:
  half-open `valid_from <= when < valid_until`, UTC-aware.

## Reproduction (independent, real keys, real resolver)

Heredoc script with the real `WellKnownResolver`, in-process fake transport, and a root-signed
well-known document whose operational certificate window is `valid_from = now-60d`,
`valid_until = now-30d`:

```
cert.is_valid_at(now) = False
PIN SUCCEEDED; stored cert valid_until = 2026-08-29T03:17:18Z
```

Mechanism **CONFIRMED**: an already-expired, root-signed certificate passes `resolve_with_ip` and is
persisted by `pin()`.

## Sub-claim disposition

| Sub-claim | Verdict | Decisive artifact |
|---|---|---|
| `resolve_with_ip`/`pin` omit the validity-window check | CONFIRMED | resolution.py:104-109; reproduction above |
| The pin-consuming path (`_certificate_for_node` → `verify_message`) omits it too | CONFIRMED | runtime.py:665-681, 654-658; signing.py:51-54 |
| Pins never refreshed; expiry is a scheduled event | CONFIRMED | `pin()` callers enumerated; runtime.py:342-393 |
| Trigger: any pinned peer whose cert passes `valid_until` | CONFIRMED (with caveat) | see Frequency |
| Outcome: expired key keeps authenticating inbound messages; divergence from gossip path | CONFIRMED but **misdirected** — see below |
| **Framing as a distinct "pin path" finding** | **REFUTED** | same root defect already recorded |

**Refuted sub-claims, named:**

1. *Distinct-finding framing.* This is not a new defect. `hunt-e1#1` (M, CONFIRMED by
   `v-hunt-e1#1`) is the same root defect — `is_valid_at` omitted at certificate-consuming sites,
   diverging from the one checking path (`runtime.py:564`) — and `v-hunt-e1#1` already recorded
   `resolution.py:107-118` as Added mechanism **A1**. `hunt-f2#1` (M) records the topology site
   (`topology.py:_verify_against_well_known` / `verify_candidate`). hunt-g1#2 is the third framing of
   one defect, not a second site-dependent outcome.
2. *Outcome attribution.* The harm hunt-g1#2 names — "expired operational key continues to
   authenticate inbound messages" — is delivered by `verify_message` (hunt-e1#1's site), not
   independently by the pin site. If `verify_message` checks the window, an expired pinned cert
   yields a 401 (hunt-e1#2's territory); if only `resolve_with_ip` checks it, an
   already-pinned-then-expired cert still passes (the pin is never refreshed). So the pin site is
   neither necessary nor sufficient for the claimed outcome. A not-yet-valid / expired cert is
   admitted at resolve time, but the admission only becomes an acceptance through the consumers.

Not refuted: the mechanism (reproduced), the trigger population, the frequency, the severity.

## Severity / frequency

- **Severity: M — unchanged, and consistent with the merged family.** The outcome is the M-scale
  "divergence between two paths that must agree" plus a wrong authorization/custody decision on
  expiry. Not H: the signing key is the certificate's own operational key, so this is a
  revocation/enforcement lapse, not an identity forgery (same reasoning as `v-hunt-e1#1`). Because
  the defect is already carried at M by `hunt-e1#1`/`hunt-f2#1`, hunt-g1#2 must not be counted as an
  additional M ticket for the same defect.
- **Frequency: DEMONSTRATED, one caveat carried.** Population = any pinned peer whose stored cert has
  passed `valid_until` while the peer keeps signing with that key. Cadence: 30-day issuance, pins
  never refreshed, so any pin older than one cert lifetime qualifies. Caveat (already recorded in
  `v-hunt-e1#1`): if the peer *did* rotate, the stale pin produces a signature mismatch → 401
  (hunt-e1#2), not expired acceptance; the expired-acceptance path requires the peer to miss
  rotation. The code neither forces nor detects rotation, so the population is permitted and
  undetected but operator-cadence-gated.

## Added mechanisms / earlier failure sites / new reachability

None that are new. Every site on this trace is already in the corpus:
- resolution/pin site — `v-hunt-e1#1` A1;
- bootstrap pin site (`_pin_bootstrap_peers`, runtime.py:412-486) — `v-hunt-e1#1` A2;
- contacts-import site (cli.py:363-367) — `v-hunt-e1#1` A3;
- topology candidate adoption (expired cert → `record_operational_key` + peer `VERIFIED`,
  topology.py:240-283) — `hunt-f2#1`.
I found no additional site, no earlier failure site, and no new reachability on this trace.

## Fix-direction constraints

1. Adding `is_valid_at` at `resolve_with_ip` alone does **not** repair the defect. Certificates expire
   *after* pinning, and pins are never refreshed; the check must be at every consumption site
   (`verify_message`, `verify_peer_card`, `_verify_against_well_known`), with a pin/peer freshness
   mechanism, or the resolution check merely converts acceptance into the hunt-e1#2 permanent 401.
2. Sequence monotonicity (`hunt-e1#3`) is the companion: an older-but-valid cert re-legitimizes a
   retired key; expiry alone does not close the rollback.
3. The sender cannot self-detect expiry (the daemon never validates its own cert window —
   `hunt-e1#4`); receiver-side enforcement is the only available control.
4. Any refresh must preserve root-history/pin consistency, since `_root_identity_for_node`
   (runtime.py:684-707) prefers peer root history over the pin.

## Checked and clean

- `OperationalCertificate.is_valid_at` (identity.py:138-141) — correct half-open, UTC-aware predicate;
  the defect is caller omission, not the predicate.
- `verify_gossip_sender_card` (runtime.py:536-569) — the one complete path; correctly calls
  `cert.verify` then `is_valid_at` then `verify_object`.
- `resolve_with_ip`'s other gates (status, content-type, strict JSON, schema, domain match, node-ID
  re-derivation, root signature) — fail-closed and unaffected by this finding.
- `create_operational_certificate` (identity.py:240-281) — enforces `valid_from < valid_until`,
  lifetime ≤ 90d, sequence ≥ 1.
- `domain_pins.upsert` does update `last_verified_at`/`operational_certificate` when called; the gap
  is the absence of a periodic caller, not a refusal to refresh.

## Enumeration

```
rg -n "is_valid_at" lattice/ --glob '!**/__pycache__/**'
```
→ identity.py:138 (definition), runtime.py:564 (gossip sender card) only. No occurrence in
resolution.py, protocol/signing.py, topology.py, cli.py.

```
rg -n "\.pin\(" lattice/ --glob '!**/__pycache__/**'
```
→ resolution.py:172, runtime.py:913. No other call site.

## Bound

- No live daemon or live peer was exercised; the acceptance outcome rests on the traced consumer
  path (reproduced at the resolver boundary only).
- Upstream well-known serving strictness is unverifiable from the tree: whether a real deployment's
  `/.well-known/lattice` keeps serving an expired cert is a deployment fact.
- Dedup judgment here is by site + mechanism + outcome; the final merge is the orchestrator's. Two
  reports of the same defect family (`hunt-e1#1`, `hunt-f2#1`) are already CONFIRMED M, so hunt-g1#2
  should fold into that ticket rather than open a third.
