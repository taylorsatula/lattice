# v-hunt-g1#1 — primed verifier

Claim under test: **hunt-g1 Finding 1** (`scratch/lattice-c1/reports/hunt-g1.md`), reported **H**.
Location in claim: `lattice/resolution.py:WellKnownResolver.resolve_with_ip` (lines 104–109).

Verdict: **CONFIRMED**. Corrected tier: **H** (unchanged). Reachability kind: **PRODUCTION**.

## Re-derived frame (from source, before reading the claim's conclusions)

- `resolve_with_ip` fetches the remote document, validates it against `WellKnownDocument`
  (`lattice/protocol/models.py`), verifies the root signature with a broad
  `except Exception → ResolutionError`, then at line 105 does
  `cert = OperationalCertificate.from_dict(doc.operational_certificate.model_dump(mode="json"))`
  **outside any try**, and wraps only `cert.verify(root_identity)` with `except IdentityError`
  (line 108).
- `OperationalCertificate.from_dict` (`lattice/identity.py:112`) calls `load_public_key_b64url`
  → `Ed25519PublicKey.from_public_bytes` on an attacker-supplied string, and `b64url_decode` on
  the signature. Both raise **`ValueError`** on a bad value, not `IdentityError`.
- `OperationalCertificate.verify` → `lattice.crypto.verify` catches everything and re-raises
  **`SignatureError`** (`crypto.py:76`). `SignatureError(ValueError)` is a *sibling* of
  `IdentityError(ValueError)` — `issubclass(SignatureError, IdentityError) == False` (checked in
  an interpreter). So a bad signature escapes `except IdentityError`.
- The model does **not** close the door: `OperationalCertificateModel._check_base64url`
  (`models.py`) only checks that `b64url_decode` succeeds. `b64url_decode("") == b""`, so
  `signature: ""` is schema-valid; the decoded length of `operational_public_key`/`signature` is
  never checked. The attacker root-signs its own document, so the malformed cert is covered by a
  valid root signature.

The decisive artifact is the handler pair at `resolution.py:105–109`: the raise sites that feed it
(`from_public_bytes` → `ValueError`; `crypto.verify` → `SignatureError`) are outside the one
`except IdentityError`. The function's own contract ("Raises ResolutionError on failure") is
violated.

## Independent reproduction

Mechanism (`resolve_with_ip` directly, real Ed25519 keys, fake transport serving a root-signed
document with a mutated cert), `/tmp/repro_g1.py`, `.venv` interpreter:

```
sig_empty:          ESCAPES as lattice.crypto.SignatureError: signature verification failed
sig_forged:         ESCAPES as lattice.crypto.SignatureError: signature verification failed
opkey_bad_len:      ESCAPES as builtins.ValueError: An Ed25519 public key is 32 bytes long
valid_but_forged:   ESCAPES as lattice.crypto.SignatureError: signature verification failed
```

Trigger + frequency (`/tmp/repro_g1_full.py`): a real `RuntimeCoordinator`, fake transport serving
a corrupted cert for `000.evil.test` and a valid doc for `zzz.victim.test`; both domains queued
via `queue_domain_resolution`; `_resolve_pending_senders()` called three times:

```
queued:     ['000.evil.test', 'zzz.victim.test']
round 1:    RAISED SignatureError; queue=['000.evil.test', 'zzz.victim.test']
round 2:    RAISED SignatureError; queue=['000.evil.test', 'zzz.victim.test']
round 3:    RAISED SignatureError; queue=['000.evil.test', 'zzz.victim.test']
victim pinned?  False
hostile pinned? False
```

`_resolve_pending_senders` (`runtime.py:900–920`) catches only `ResolutionError` (line 914). The
`SignatureError` propagates out of the `for domain in batch:` loop; the discard at lines 918–919 is
only reached after a *successful* `pin`, so the hostile domain stays in `_unresolved_domains`.
Every subsequent 30 s tick (`runtime.py:348`) rebuilds `batch = sorted(...)`, aborts at the same
sorted position, and never reaches the victim. The task-level `except Exception` in
`_RecurringTask._run` (`runtime.py:133`) only logs — the scheduler thread survives, so this is a
silent, indefinite per-round abort, not a crash.

## Sub-claim adjudication

| Sub-claim | Verdict |
|---|---|
| Malformed cert escapes as `SignatureError`/`ValueError`, not `ResolutionError` | CONFIRMED (both classes) |
| `signature: ""` passes `_check_base64url` | CONFIRMED (`b64url_decode("") == b""`) |
| wrong-length / forged signature / non-32-byte op key all escape | CONFIRMED (reproduced, 4 variants) |
| escape aborts the whole batch loop mid-batch | CONFIRMED |
| hostile domain is only discarded after a successful pin, so it stays in the queue | CONFIRMED |
| subsequent batches abort at the same sorted position | CONFIRMED |
| `_certificate_for_node` `resolve()` under `except ResolutionError: pass` → 500 | CONFIRMED as a mechanism; reachability requires a peer with a domain but no pin (see below) |
| `admin_submit` (api.py:392) → 500 | CONFIRMED but **not caused by the escape** — corrected below |
| cli.py:578 → raw traceback | CONFIRMED |

Nothing in the claim's core mechanism, trigger, or frequency is refuted. No half is retracted.

## Severity / frequency corrections

**Severity: H, unchanged.** Cross-peer reach (one hostile peer starves the resolution of *other*
peers' cold domains), permanent on the 30 s cadence, and the starved sender's message is
eventually erased (`messages.record_failure` → `mark_terminal(..., erase_content=True)` after
`RetryPolicy.max_attempts = 10`, `messages.py:40,177-184`), so it is genuine message loss, not
just a delayed delivery. This is exactly the H band ("cross-peer reach", "message loss").

**Frequency: ADJUSTED in characterization, tier unchanged.** The claim's trigger is correctly
*adversarial*, not a routine cadence: it needs one hostile peer that (a) sends a schema-valid
cold-sender POST to `POST /lattice/v1/messages` to enqueue its domain and (b) serves a root-signed
well-known with a malformed operational cert. That is one attacker action, not a recurring
operator/system event. The *persistence* is what is cadenced (re-aborted every 30 s indefinitely),
and the *affected population* is every cold/unpinned domain that sorts after the hostile domain.
Note the claim's illustrative name `aaa.evil.test` only blocks domains sorting after `aaa…`; a
leading-digit name (`000.evil.test`, also valid to `parse_address`, which only rejects `:/@` and
length > 253) sorts ahead of essentially every alphabetic legitimate domain and blocks the whole
queue. Reachability is PRODUCTION; the trigger is adversary-supplied.

## Additional mechanisms / earlier failure sites / new reachability (same trace)

1. **Bootstrap path aborts daemon startup.** `_pin_bootstrap_peers` (`runtime.py:420–429`) wraps
   `self._resolver.resolve(domain)` with `except ResolutionError` only, and `start()`
   (`runtime.py:403`) calls it with no surrounding try. A configured bootstrap peer whose
   well-known carries the malformed cert raises `SignatureError` out of `resolve` →
   `_pin_bootstrap_peers` → `start()` → daemon fails to start. Gated on a malicious/misconfigured
   bootstrap peer (operator-controlled), so narrower than the primary path; same root cause.
2. **`_certificate_for_node` 500 path (reachability clarified).** `runtime.py:665–681`: when a peer
   is known by `node_id` with a `domain` but has **no domain pin**, `_domain_for_node` returns the
   domain, `get_pin` returns `None`, and `resolve(domain)` (line 678) under `except ResolutionError:
   pass` lets `SignatureError` escape through `verify_inbound_message` → `receive_message`, which
   catches only `BlockedSenderError`/`RuntimeError` (`api.py:292,301`) → unhandled 500 on the
   public messages route. This state (peer in `peer_store` without a pin) is reachable: gossip
   candidate verification in `topology.verify_candidate` creates the peer but does **not** write a
   domain pin, and `reset_domain` removes a pin while leaving the peer. Trigger is production.
3. **`admin_submit` correction.** `api.py:392–393` catches only `RuntimeError`, but
   `resolve_destination` = `resolve_address`, which raises `ResolutionError(ValueError)`; `AddressError
   (ValueError)` is also possible. So this route returns 500 ("Address resolution failed" was the
   intent) for **any** unresolvable/ malformed `to_address`, not specifically for the Finding-1
   escape. The escape is one more input that reaches the wrong handler; the narrow `except` is the
   real cause. Authenticated admin-only, so L.
4. **topology.py** has the identical `except IdentityError`-only pattern twice
   (`topology.py:223` around `resolve_with_ip`, and `topology.py:318–324` around `cert.verify`).
   Both escapes are absorbed by `_run_verify_candidates`'s per-candidate `except Exception`
   (`runtime.py:1124–1129`), so the impact is a logged failure and the candidate never being
   removed/re-verified — the loop continues to other candidates. L.
5. **Failed domains are never dropped despite the docstring.** `_resolve_pending_senders`'s
   docstring says "On failure, drops it from the queue", but the `except ResolutionError` branch
   `continue`s without `discard`. Independent of the escape, any permanently-failing domain (DNS
   NXDOMAIN, TLS failure, malformed doc once escaped) is retried on every 30 s tick forever —
   unbounded queue retention + repeated outbound fetches. L.

## Fix-direction constraints

- Fixing `resolution.py` is necessary and primary: make the whole cert-handling block
  (`from_dict` and `verify`) fail closed into `ResolutionError`, matching the function's contract.
  Without it, the other public/admin callers (`_certificate_for_node`, `admin_submit`, `cli`,
  `topology`, bootstrap) keep their own 500 / traceback / startup-failure surfaces.
- Hardening `_resolve_pending_senders` alone (catch `Exception` per domain) fixes the cross-peer
  starvation but leaves the escape semantics at every other caller; and the hostile domain is still
  re-fetched every 30 s. Defense in depth: the loop must also honor its docstring and discard (or
  quarantine) domains that fail, otherwise the queue is unbounded.
- A repair must not merely "escape structure-breaking" (`except Exception` around the loop);
  the semantic contract is that *no* remote-content failure is a non-`ResolutionError`. The same
  `except IdentityError`-narrow pattern at `topology.py:223/318` and the `except RuntimeError`-only
  handler at `api.py:393` must be corrected too, or the escape class simply moves.
- Custody is not at risk on the pin-consuming path (`_certificate_from_pin` can only see pins that
  were created by a *successful* pin, so a malformed cert is never persisted); the exposure is
  resolution/availability, not signature acceptance. Do not over-claim key bypass.

## Checked and clean (on the tested trace)

- `OperationalCertificateModel` base64url shape check and `WellKnownDocument` root-signature check
  are functioning; the defect is strictly the missing length/applicability check downstream of a
  valid root signature, i.e. an attacker must control the peer's own root key. No forgery of
  another node is possible.
- `_resolve_pending_senders` lock handling is correct (batch snapshot taken under lock; no lock held
  across the network call) — the abort is a control-flow defect, not a deadlock.
- `pin()` cannot persist a cert that fails to verify, because `resolve()` raises first.
- The `_RecurringTask._run` `except Exception` frame keeps the scheduler alive; the defect is
  per-round starvation, not a process crash.

## Enumeration

`rg -n "except IdentityError|except ResolutionError|except RuntimeError|from_dict|resolve\(" lattice/resolution.py lattice/runtime.py lattice/topology.py lattice/cli.py lattice/api.py`

| Site | Handler | Disposition |
|---|---|---|
| resolution.py:105–109 | `from_dict` outside try; `except IdentityError` only | **Finding 1 — root cause** |
| runtime.py:914 | `except ResolutionError` (no `except Exception`) | **Finding 1 — amplifier (starvation)** |
| runtime.py:428–429 | `except ResolutionError` (bootstrap, in `start()`) | additional mechanism #1 |
| runtime.py:678–680 | `except ResolutionError: pass` (`_certificate_for_node`) | additional mechanism #2 |
| topology.py:223 | `except ResolutionError` around `resolve_with_ip` | absorbed by runtime.py:1126; L |
| topology.py:318–324 | `except IdentityError` around `cert.verify` | absorbed; L |
| api.py:393 | `except RuntimeError` around `resolve_destination` | additional mechanism #3; L |
| cli.py:578–579 | `except ResolutionError` around `resolve` | raw traceback; L |

## Bound

- No live daemon or real hostile network peer was exercised; the trigger was reproduced in-process
  with the real `RuntimeCoordinator`, real resolver, real Ed25519 keys, and a fake transport. The
  30 s scheduler cadence and the sorted-batch ordering are read from source, not wall-clock observed.
- Sender-side erase-after-10-attempts is read from `messages.py:40,177–184`; the sender's retry loop
  was not run end-to-end.
- The exact set of production callers that reach `_certificate_for_node`'s `resolve()` branch
  (peer-without-pin) was reasoned from `topology.verify_candidate` and `reset_domain`, not counted
  in a running system.
- Did not modify any file; the only write is this report.
