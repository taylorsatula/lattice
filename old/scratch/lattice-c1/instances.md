# Enumeration instance ledger — lattice-c1

Instances pre-binned and attached to mechanism hunts as starting points. A hunt that receives these
must disposition each: finding / examined-clean / out-of-scope-with-reason (Phase 3 rule). Each
enumeration publishes the composed command that bounds it.

## E1 — spawn / context propagation
`rg -n "Thread\(|run_in_executor|copy_context|ContextVar|submit\(" lattice`
CLOSED bound: 4 hits, all deliberate.
- `runtime.py:127` `self.executor.submit(self._run)` — scheduler thread submits its own tick.
- `runtime.py:269,273` `ThreadPoolExecutor(...)` — delivery + maintenance executors (invariant 4
  permits these as lifecycle glue).
- `api.py:406` / `messages.py:88` `submit(...)` — outbound queue submit, not a spawn.
Disposition pending hunt B1.

## E2 — unbounded waits / shutdown
`rg -n "\.result\(|\.join\(|wait_for|shutdown\(|Event\(|\.wait\(" lattice`
CLOSED bound: 5 hits.
- `runtime.py:146,149,156` — scheduler `Event.wait(timeout=...)` + `join(timeout=...)`, bounded.
- `runtime.py:489,490` `shutdown(wait=True, cancel_futures=False)` — **candidate**: in-flight
  delivery futures not cancelled on stop; check whether a durable queue item is left claimed.
Disposition pending hunt B1.

## E3 — sanctioned clock / env / file access in `lattice/`
`rg -n "datetime\.now\(|time\.time\(|os\.getenv\(|os\.environ|open\(" lattice`
CLOSED bound: 20 hits. Two classes:
- `datetime.now(UTC)` / `time.time()` in `lattice/` — check whether any of these is in a signed or
  canonicalized field where a caller-supplied clock should be honored instead (gossip.py:31,
  messages.py:36, protocol/models.py:33, topology.py:57, webhook.py:38, repositories.py:25).
- `os.environ.get("CREDENTIALS_DIRECTORY")` at `cli.py:628`; `open(path)` at `config.py:176`.
Disposition pending hunts A2, D2, E2, H1.

## E4 — except-and-continue / swallowed errors
`rg -n "except" lattice` → 98 sites. Binned by subsystem:
- `resolution.py` 8 sites (broad `except Exception` x5 at :63,72,83,89,100).
- `topology.py` ~9 sites (broad x5).
- `runtime.py` ~12 sites (broad `except Exception` in maintenance/restore paths).
- `gossip.py` 92,130,246 (broad) — per-card loop continues past failure.
- `api.py` handlers convert to Problem Details — check each preserves the right status/code.
Disposition pending area hunts + error-path Q1.

## E5 — transactions / dual-write
`rg -n "commit\(|with self\._conn|with conn|transaction" lattice/storage lattice/runtime.py`
CLOSED bound: `with self._conn:` used as the transaction idiom throughout repositories (~35 sites);
explicit `with conn:` in `cache.py:60`, `connection.py:102`. **Dual-write candidates**: any place a
durable write and a cache write occur in one logical operation without a shared transaction — the
rate-limit snapshot persistence (`runtime.py` ~502/776-816) and the claim/custody write pair.
Disposition pending hunts C1, C2, I1, S3.

## E6 — SQL string building
`rg -n "f\"" lattice/storage lattice/runtime.py | rg -i "select|insert|update|delete"`
CLOSED bound: 3 hits.
- `repositories.py:284` `updates.append(f"{state_col} = ?")` — `state_col` from a fixed dict literal
  at :265-269 → **whitelist-safe** (values parameterized).
- `repositories.py:290` `f"UPDATE peers SET {', '.join(updates)}"` — joined fragments are all fixed
  literals + `state_col` above; values parameterized → safe.
- `migrations.py:120` — error message, not SQL.
Disposition: examined-clean unless a hunt finds a non-whitelisted column source.

## Seam inventory (deliberately shallow; deliverable = contract check)

| Seam | Boundary | Contract | Endpoint symbols |
|---|---|---|---|
| S1 | API ↔ runtime | route handler's assumptions about coordinator return shapes and raised exceptions | `api.py:receive_gossip`↔`runtime.verify_gossip_sender_card`; `api.py:receive_message`↔`runtime.verify_inbound_message`/`queue_domain_resolution`; `api.py:admin_submit`↔`runtime.allow_submission`/`resolve_destination`/`sign_local_message`; `api.py` exception maps ↔ `BlockedSenderError`/`CustodyError`/`RuntimeError` |
| S2 | transport ↔ topology | `FederationResponse.resolved_ip` is policy-validated; topology groups peers by its prefix | `transport.FederationResponse`↔`topology.prefix_from_ip`; `resolution.resolve_with_ip`↔`topology` candidate intake; `peers.observed_prefix` |
| S3 | storage ↔ runtime | repository return shapes vs caller expectations; claim/lease semantics; transaction boundaries | `repositories.PeerRepository.transition`/`get_peer`; claim + custody write pair; `cache_repo.save_rate_bucket` vs durable transitions |
| S4 | protocol ↔ verification | signed-object preimage/kind/`MEDIA_TYPE` vs verifier expectations | `protocol/signing.py:verify_*`↔`identity.sign/verify_object`; `canonical.signature_preimage`; kind constants ↔ each call site |
