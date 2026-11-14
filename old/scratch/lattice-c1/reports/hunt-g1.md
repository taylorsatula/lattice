# hunt-g1 — resolution & addressing (lattice/resolution.py, lattice/addressing.py)

Pass type: blind hunter. Both assigned files read end-to-end; callees and all callers
traced (identity.py, crypto.py, canonical.py, encoding.py, protocol/models.py,
transport.py, storage/repositories.py, runtime.py, api.py, topology.py, cli.py call
sites). Both findings below were reproduced with an in-process fake transport and
real Ed25519 keys (no files modified; heredoc scripts only).

## Findings

1. [H] — Malformed operational certificate escapes as SignatureError/ValueError, not ResolutionError
- Location: lattice/resolution.py:WellKnownResolver.resolve_with_ip (lines 104–109)
- Evidence: `cert = OperationalCertificate.from_dict(doc.operational_certificate.model_dump(mode="json"))` (line 105, outside any try) and `except IdentityError as exc:` (line 108) — but `SignatureError` (lattice/crypto.py:14) and `ValueError` from `Ed25519PublicKey.from_public_bytes` are siblings of `IdentityError`, not subclasses, so both escape `resolve_with_ip`/`resolve`/`pin`.
- Trigger (PRODUCTION): a remote peer's `https://domain/.well-known/lattice` is root-signed and schema-valid but its operational certificate fails verification — e.g. `signature` is `""` (empty b64url passes the model's `_check_base64url`), is wrong-length, is forged, or `operational_public_key` decodes to non-32 bytes. Empirically reproduced: all four variants escape as `lattice.crypto.SignatureError` or `builtins.ValueError`.
- Frequency: DEMONSTRATED. The worst path needs only one hostile POST to the public route `POST /lattice/v1/messages` with a cold-sender `from_address` (`user@aaa.evil.test`): api.py:307 queues the domain; `RuntimeCoordinator._resolve_pending_senders` (runtime.py:913) runs every 30 s and catches only `ResolutionError` (runtime.py:914). The escape aborts the whole `for domain in batch:` loop mid-batch, and the domain is only ever discarded after a *successful* pin (runtime.py:918–919) — so it never leaves `_unresolved_domains` and every subsequent batch aborts at the same sorted position.
- Outcome: permanent cold-sender resolution starvation with cross-peer reach — every cold domain sorting after the hostile one can never be pinned, so their senders receive 503 forever, retry on the sender side until `RetryPolicy` exhausts (10 attempts), then the message content is erased (messages.py:record_failure → mark_terminal with erase). One hostile domain converts into message loss for arbitrary other peers. Secondary outcomes from the same escape: `runtime._certificate_for_node` (runtime.py:~675) calls `resolve()` under `except ResolutionError: pass` → `SignatureError` propagates through `verify_inbound_message` → api.py receive_message catches only `BlockedSenderError`/`RuntimeError` → unhandled 500 on the public messages route; `admin_submit` (api.py:392) → 500 on the admin route; cli.py:578 (transfer command) → raw traceback.
- Confidence: traced — mechanism, trigger, and frequency all verified by execution. No unproven component.

2. [M] — Pin path never checks the operational certificate validity window
- Location: lattice/resolution.py:WellKnownResolver.resolve_with_ip (lines 103–109; no `is_valid_at` anywhere in the file) / pin (line 123–139)
- Evidence: after `cert.verify(root_identity)` the code proceeds to pin; the only `is_valid_at` enforcement in the daemon is on the peer-card path (`runtime.py:564`, `_verify_peer_card`: `if not cert.is_valid_at(self._clock.now()): return None`). The pin-consuming path — `runtime._certificate_for_node` → `messages.verify_message` (protocol/signing.py:52–59, which only calls `certificate.verify` + `verify_object`) — also never checks the window.
- Trigger (PRODUCTION): any peer whose domain is pinned; the peer's operational certificate passes its `valid_until` (certificates are issued with 30-day lifetimes — cli.py:115 — and bounded by MAX_OPERATIONAL_CERTIFICATE_LIFETIME_SECONDS). Pins are TOFU-forever; nothing re-checks or re-pins on expiry. Empirically reproduced: a well-known document with a root-signed but already-expired (valid_until 30 days in the past) operational certificate is accepted and pinned.
- Frequency: DEMONSTRATED — certificate expiry is a scheduled event for every pinned peer on a ~30-day cadence; nothing in tree refreshes pins. The bad acceptance (signatures from an expired operational key keep authenticating inbound messages indefinitely) occurs whenever the peer keeps signing past expiry or the old key leaks after expiry.
- Outcome: an expired (or not-yet-valid) operational key continues to authenticate inbound messages through the domain-pin path, while the same certificate would be rejected on the gossip peer-card path — divergence between two verification paths that must agree; the certificate lifetime bound is unenforced on exactly the path that custody acceptance (HTTP 202) relies on.
- Confidence: traced — mechanism and trigger verified by execution; frequency grounded in the 30-day issuance cadence.

## Checked and clean
- resolution.py:51 — `except (TransportError, NetworkPolicyError)` → ResolutionError: correct, complete for transport failures.
- resolution.py:63, 72, 83, 89, 100 — broad `except Exception → ResolutionError` conversions around strict_json_loads, model_validate, b64url_decode, from_public_bytes, verify_with_root: fail-closed conversions of hostile remote content; each converts and chains the cause. Clean. (E4 dispositioned below.)
- resolve_with_ip ordering is fail-closed at every step: status != 200 → content-type gate → strict JSON (duplicate-key and non-finite rejection via canonical.py) → dict check → Pydantic `extra="forbid"` schema → domain match (both sides lowercased: resolver lowercases, model validator lowercases `doc.domain`) → root-key decode → node-ID derivation match → root signature over the full document → cert. Happy path verified end-to-end with real keys.
- resolve_address / pin / get_pin — TOFU semantics (existing pin trusted without re-fetch; `reset_domain` is the operator remedy) is the documented design; pin↔trust binding preserved: pin key, `doc.domain`, and the fetched URL hostname are the same lowercased string, and the repository lowercases domain keys on both upsert and get (repositories.py:101, 116) so no case-split pins. `pin()` upsert clears `transfer_node_id`/`trust_reset_at` on re-pin (repo behavior, consistent with trust reset). Endpoints stored come from the validated model with the https-only, no-credentials check (models.py `_validate_https_url`).
- No root private key is loaded, derived, or exported anywhere in resolution.py (invariant 2 respected).
- addressing.py parse_address — node-ID regex identical to models.NODE_ID_RE; domain length bound 253 matches the model; `:/@` exclusion prevents scheme/host injection into the fetch URL, and the transport independently re-validates the hostname (NetworkPolicy.hostname_allowed) and TLS (`assert_hostname`); `?`/`#` in a domain only redirect the fetch within the attacker's own host and cannot cross the pin↔doc.domain equality, so no cross-domain confusion. Whole-address lowercasing (username included) is consistent system-wide (cli.py:295, gossip.py:208, repository key normalization) — not a mismatch risk.
- to_canonical / to_human — clean, raise AddressError when the required half is missing.
- resolved_ip is produced by our own transport (`FederationResponse.resolved_ip` set from the policy-validated IP), not from remote response content — not a spoofable field.

## Enumeration
Command (closes the E4 class over both assigned files):
`rg -n "except" lattice/resolution.py lattice/addressing.py`

| Site | Code | Disposition |
|---|---|---|
| resolution.py:63 | strict_json_loads → `except Exception` → ResolutionError | examined-clean (fail-closed conversion) |
| resolution.py:72 | model_validate → `except Exception` → ResolutionError | examined-clean |
| resolution.py:83 | b64url_decode → `except Exception` → ResolutionError | examined-clean |
| resolution.py:89 | from_public_bytes → `except Exception` → ResolutionError | examined-clean |
| resolution.py:100 | verify_with_root → `except Exception` → ResolutionError | examined-clean |
| resolution.py:108 | `except IdentityError` (too narrow) | **Finding 1** |
| addressing.py:78 | `except AddressError: return None` in node_id_from_address | examined-clean — intended contract ("Return the node ID if canonical, else None"); no callers in tree or tests (dead helper), not a defect |

## Design risks
TOFU pins have no refresh mechanism of their own: when a peer rotates its operational
key, the stale pin keeps verifying against the old certificate, so the peer's new-key
messages are 401-rejected until an operator runs `reset_domain`. No automated
rotation handling exists in runtime/peers/topology (`verify_rotation` has no runtime
caller). Combined with Finding 2, pin freshness depends entirely on manual operator
action. Design intent around rotation workflow is not documented enough for me to
call the stale-pin rejection itself a defect; the unenforced validity window is
reported as Finding 2.

## Side discoveries (single-pass candidates, not primary findings)
- runtime.py `verify_inbound_message` calls `parse_address(model.from_address)` outside its try (the try only wraps `Message.model_validate`), and api.py receive_message catches only `BlockedSenderError`/`RuntimeError`; a model-valid Message with a malformed `from_address` (no `@`, empty username) raises `AddressError` → unhandled 500 on the public `POST /lattice/v1/messages` route. Same for `_extract_domain_from_address(message["to_address"])` later in that handler. The parsing itself (addressing.py) is correctly fail-closed; the mishandling is in runtime.py/api.py (outside this assignment's files).
- topology.py:318–324 `_verify_against_well_known` repeats the same `except IdentityError`-only pattern around `cert.verify`; there the escape is absorbed by `_run_verify_candidates`'s broad `except Exception` (runtime.py:1126) — logging-only impact, candidate not removed.
- cli.py:578 (domain transfer command) catches only `ResolutionError` around `resolver.resolve` → the Finding-1 escape produces a raw traceback instead of the command's error message.

## Bound
- Assigned files fully read; no paths left unopened in resolution.py or addressing.py.
- The daemon's live inbound/gossip behavior under a real hostile peer was reasoned from code, not exercised against a running daemon (no live infrastructure in this pass); both findings were nonetheless reproduced in-process with the real resolver class and real keys.
- My enumeration covered only the assigned files' exception sites; the same escape class in runtime.py/api.py/cli.py/topology.py is dispositioned above only at the specific call sites that consume resolution.py output.
