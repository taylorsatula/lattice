# v-hunt-b1b#1 — PRIMED VERIFIER verdict on hunt-b1b#1

Claim under test: **hunt-b1b#1 [H]** — `OutboundTransport.request()` raises `TypeError` on every
call; all outbound federation I/O is dead.

Method: re-derived the frame from source before reading the claim's conclusions; verified the
urllib3 call chain on the repo's own pinned `.venv` (urllib3 2.7.0, `uv.lock`); traced every
caller of `OutboundTransport.request` and every exception handler on the path.

**Verdict: CONFIRMED.** Corrected tier: **H** (unchanged). One sub-claim is REFUTED as stated
(the remote 500 is not reachable "by any peer today"); one secondary mechanism is corrected
(the IPv6 failure is caught, not uncaught).

---

## 1. Re-derived frame

`lattice/transport.py:OutboundTransport.request()` (lines 76–123) does:

```
ip = self._resolve_and_validate(hostname)                 # DNS + policy, before any HTTP
target_url = f"https://{ip}:{port}{parsed.request_uri}"
...
response = self._pool.urlopen(
    method, target_url, body=body, headers=request_headers,
    fields=fields, assert_hostname=hostname, preload_content=True)
```

`self._pool` is a plain `urllib3.PoolManager` (line 59). Signature facts established from the
installed package, not from the claim:

- `PoolManager.urlopen(self, method, url, redirect=True, **kw)` — no `fields`, no `assert_hostname`.
  Both land in `**kw`.
- `PoolManager.urlopen` forwards `**kw` to `HTTPSConnectionPool.urlopen`, whose signature ends
  `... preload_content=True, decode_content=True, **response_kw`. So both names land in
  `response_kw`.
- `HTTPConnectionPool.urlopen` calls `self._make_request(..., **response_kw)`.
- `_make_request` has **no** `**kwargs` (explicit signature confirmed for both `HTTPConnectionPool`
  and `HTTPSConnectionPool`; `HTTPSConnectionPool` does not override `_make_request` or `urlopen`).

Therefore `TypeError` is raised at the `_make_request(...)` call site, before `conn.request()` —
the request is never sent. `request()` catches only `urllib3.exceptions.HTTPError`; `TypeError`'s
MRO is `(TypeError, Exception, ...)`, so it escapes.

Empirical reproduction on the repo venv, unmodified pool construction:

```
>>> pool.urlopen("POST", "https://127.0.0.1:1/x", body=b"x", headers={"Host":"example.com"},
...              fields=None, assert_hostname="example.com", preload_content=True)
TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'
>>> ... (fields absent) ...
TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument 'assert_hostname'
```

Pinned dependency (`uv.lock:861` `urllib3 2.7.0`; `pyproject.toml` `urllib3>=2.0.0`). The two
failing names are invalid at `urlopen` level for the entire urllib3 2.x line (they are `request()`
and `HTTPSConnection`-constructor parameters respectively); the pinned version is decisive and was
verified directly.

Callers of `request()` — enumerated (`rg -n "_transport.request" lattice/*.py`):

| Site | Call | Handler around it |
|---|---|---|
| `runtime.py:964` `_send_outbound_message` | POST message | catches `TransportError` only |
| `runtime.py:1113` `_send_gossip_batch` | POST gossip batch | catches `TransportError` only |
| `resolution.py:50` `WellKnownResolver.resolve_with_ip` | GET well-known | catches `(TransportError, NetworkPolicyError)` only |

No caller passes `fields` (signature parameter is dead code).

## 2. Component-by-component verification

- **Mechanism — CONFIRMED (traced + empirical).** `TypeError` on every call with a validated IPv4
  address. No part unproven.
- **Trigger — CONFIRMED (production).** Any outbound HTTP operation: outbound message delivery,
  gossip batch, well-known resolution. `_resolve_and_validate` runs first (DNS + policy) and, for a
  public host resolving to a public IP in `public` mode, returns the IP; the very next statement is
  the broken `urlopen`. The webhook path is independent (`webhook.py:58` builds its own
  `PoolManager`; `webhook.py:91` passes only valid kwargs) — the claim's "webhook unaffected" is
  correct.
- **Frequency — CONFIRMED (demonstrated).** `request()` is the only egress for federation; every
  invocation reaches the broken call. Not gated, not test-only.
- **Blast radius sub-claims** — each traced:
  - **Outbound delivery churn/data loss — CONFIRMED.** `_run_outbound_delivery` (runtime.py:922)
    claims rows via `OutboundMessageService.claim_for_delivery` → `claim_pending`
    (repositories.py:702: sets `status='leased'`, `lease_expires_at = now+5min`,
    `attempt_count = attempt_count + 1`), then calls `_send_outbound_message`. The `TypeError`
    escapes the `except TransportError` (runtime.py:965), so `record_failure`/`release_lease` never
    run. The task wrapper `_RecurringTask._run` (runtime.py:130) catches and logs, releasing only the
    non-overlap lock — the leased rows are abandoned until `lease_expires_at`, then re-claimed
    (attempt_count++), cyclically, until `expire_messages` (repositories.py:844) sets them
    `expired` and overwrites `content`/`message_json` with `[erased]`. Default TTL 86400 s
    (`config.py:213`). No outbound message can be delivered; all are erased undelivered. **H.**
  - **Gossip never sent — CONFIRMED.** `_send_gossip_batch` (runtime.py:1113) catches only
    `TransportError`; `TypeError` escapes to `_RecurringTask._run`.
  - **`_resolve_pending_senders` batch abort — CONFIRMED, production-reachable today.**
    `_resolve_pending_senders` (runtime.py:900) catches only `ResolutionError`; `pin()` →
    `resolve()` → `resolve_with_ip` propagates `TypeError`. Trigger: **any** inbound message from an
    unpinned domain hits the cold-sender branch (`api.py:receive_message` → `queue_domain_resolution`
    at api.py ~305), then the 30 s `cold_sender_resolution` task (runtime.py:346) aborts its whole
    batch on the first entry. This does not require finding 1's repair — it fires with the bug in
    place.
  - **`cmd_serve` startup crash — CONFIRMED, production.** `RuntimeCoordinator.start()`
    (runtime.py:390) calls `_pin_bootstrap_peers()` (runtime.py:412) outside any guard;
    `_pin_bootstrap_peers` catches only `ResolutionError` around `resolver.resolve(domain)`
    (runtime.py:428). A `TypeError` propagates through `start()`; `cli.py:718` calls
    `runtime.start()` with no `try`, before `uvicorn.run`. On a fresh deployment with
    `gossip.bootstrap` configured (`config.py:53`; config example line 196) whose named peer is not
    already known **and whose DNS resolves to a policy-allowed IP**, the daemon exits instead of
    serving. **H.**
  - **Additional reachability the claim omitted: candidate verification never completes.**
    `_run_verify_candidates` (runtime.py:1120) → `TopologyService.verify_candidate` (topology.py:201)
    → `resolve_with_ip` (topology.py:223) catches only `ResolutionError`; `TypeError` escapes to the
    outer `except Exception` in `_run_verify_candidates`. Net effect: no gossip-introduced peer can
    ever reach `VERIFIED`, so the topology never matures. Same root cause, additional symptom.
- **Remote HTTP 500 on `POST /lattice/v1/messages` — REFUTED as stated.**
  The claim says a 500 is "remotely triggerable by any peer sending a message whose sender node is
  known-with-domain but unpinned." The 500 mechanism itself is real: `_certificate_for_node`
  (runtime.py:665) catches only `ResolutionError` around `resolver.resolve(domain)`, the `TypeError`
  escapes, and `api.py:receive_message` catches only `BlockedSenderError`/`RuntimeError` (TypeError
  is neither) → unhandled → 500. **But the necessary state — a peer record with a domain and no
  domain pin — is not produced by any automatic path while finding 1 stands:**
  - `TopologyService.verify_candidate` creates exactly that state (topology.py:243
    `create_peer(..., domain=result.domain, ...)`, no `DomainPinRepository.upsert`) — but it is
    itself blocked at `resolve_with_ip` by the same `TypeError`. **Gated behind finding 1's repair.**
  - `_pin_bootstrap_peers` writes the pin alongside the peer (runtime.py:452–476), so bootstrapped
    peers are pinned → `get_pin(domain)` succeeds → `resolve()` is never reached.
  - `accept_candidate` stores only a cache candidate, never a peer (topology.py:187).
  - The only path that leaves a peer with a domain and no pin **today** is the offline operator
    command `cmd_trust_reset_domain` (cli.py:418, `DomainPinRepository.delete`), which deletes the
    pin but leaves the `peers` row's domain. After that reset and a daemon restart, an attacker who
    knows the node id (public in gossip cards) can send `from_address = "user@<node_id>"` and obtain
    a 500 before signature verification. So the 500 has a **narrow production trigger today
    (operator trust-reset + known node id)** and a **broad trigger once finding 1 is repaired
    (every verified peer)**.
  This is a qualification of a sub-claim, not of the finding: the finding remains H on the strength
  of delivery death, startup crash, and topology death.

## 3. Corrected severity and frequency

- **Severity: H — unchanged.** Data loss (durable outbound custody erased at expiry with no delivery
  attempt ever made), remote-triggerable startup denial for bootstrapped deployments, and total
  federation failure. Fits the H clause ("data loss or corruption"; "remote crash ... reachable by a
  network peer"). No upward adjustment needed; no downward basis.
- **Frequency: CONFIRMED as demonstrated, with one nuance.** "100% of real network operations"
  holds for every request whose first policy-allowed address is IPv4. When the first allowed
  address is IPv6, the rewritten URL `https://::1:<port>/...` is un-bracketed and
  `PoolManager.urlopen` raises `urllib3.exceptions.LocationParseError` during `parse_url` **before**
  the keyword check. That exception **is** a subclass of `HTTPError`
  (`LocationParseError → LocationValueError → ValueError, HTTPError`), so it is converted to a
  `TransportError` by `request()` and handled as a retryable failure — not the uncaught `TypeError`.
  The hunter's phrasing ("dual-stack hostnames fail even apart from the kwargs fault") is accurate;
  only its implied equivalence to the uncaught path is worth flagging. Both outcomes are still
  total failure of the operation.
- **Reachability kind: PRODUCTION** for the mechanism, the delivery data loss, the gossip death, the
  cold-sender loop abort, the topology-verification death, and the startup crash. The remote-500
  sub-claim is **production (operator trust-reset)** or **gated-behind-finding-#1** (candidate
  verification).
- **CI masking: CONFIRMED.** `tests/conftest.py:211–217` installs `_FakeTransport` on
  `runtime._transport` and `runtime._resolver._transport`; `conftest.py:343–344` defines
  `mock_transport` as `MagicMock(spec=OutboundTransport)`. No test exercises the real `urlopen`
  call, which is why the defect is invisible to the suite.

## 4. Fix-direction constraints (beyond the reported symptom)

1. **Do not "fix" by deleting the two kwargs.** The intent of `assert_hostname=hostname` is to
   verify the peer certificate against the original hostname while connecting to the pre-validated
   IP (`Host` header is already set to `hostname`; SNI would otherwise be the IP). Removing the
   kwargs connects to `https://<ip>/...`, so urllib3 derives SNI and certificate identity from the
   IP; with the default `ssl.create_default_context()` (`check_hostname=True`) a normal hostname
   certificate fails verification. The repair must supply `assert_hostname`/`server_hostname` at
   **pool-construction** time (e.g. `PoolManager.connection_from_host(host=ip, port=port,
   scheme="https", pool_kwargs={...})` or a per-request pool), because per-request kwargs cannot be
   honoured by a pooled connection. `fields` is dead (no caller passes it) and can be dropped from
   the signature.
2. The IPv6 URL rewrite (`f"https://{ip}:{port}..."`) must bracket IPv6 literals
   (`https://[::1]:port/...`); otherwise the hostname-verification fix is still unreachable for
   dual-stack peers whose first allowed address is IPv6. This is a separate defect on the same trace.
3. Any repair must preserve the existing `except TransportError` mapping: the resolve/gossip/
   delivery/topology callers all assume `request()` raises `TransportError` for network faults. If
   the repair surfaces a new exception type, the `except ResolutionError` /
   `except (TransportError, NetworkPolicyError)` handlers at resolution.py:50, runtime.py:428,
   runtime.py:665, and topology.py:223 will still leak it. Consider whether unexpected transport
   faults should be normalized to `TransportError` at the transport boundary.
4. A regression test must perform a real `urlopen` (or assert the exact kwargs accepted by the
   pinned urllib3); the `MagicMock(spec=OutboundTransport)` mock cannot detect this class of fault,
   since mock specs do not validate keyword acceptance of the underlying library.

## Checked and clean

- `_resolve_and_validate` runs before the broken call and does emit a real, policy-validated IP for
  public hosts in `public` mode (`network_policy.py:hostname_allowed` returns True; `validate_ip`
  passes public IPs). The frame does reach `urlopen`.
- `webhook.py` egress (`webhook.py:58,91`) uses its own `PoolManager` and only valid `urlopen`
  kwargs; it is genuinely unaffected by hunt-b1b#1.
- `record_success`/`record_failure` are unreachable on this path, but their transaction boundaries
  (`repositories.py:702/743/775/844`, each `with self._conn:`) are internally consistent; the leak
  here is the missing handler, not a repository fault.
- `_RecurringTask._run` (runtime.py:130) does catch and log, so the delivery/gossip/cold-sender
  failures do not kill the worker thread; only the `start()` path propagates.
- `LocationParseError ⊂ HTTPError` verified via `__mro__`, which is why the IPv6 fault is mapped to
  `TransportError` while the kwargs fault is not.
- `DomainPinRepository` lowercases domains consistently on `upsert`/`get`/`delete`, so no
  case-mismatch false path to `resolve()` exists.

## Enumeration

Class: every caller of `OutboundTransport.request` (closure of the defect surface).

```
rg -n "_transport\.request" lattice/*.py
lattice/resolution.py:50:   response = self._transport.request("GET", url)
lattice/runtime.py:964:     response = self._transport.request("POST", endpoint, body=body, headers=headers)
lattice/runtime.py:1113:    response = self._transport.request("POST", endpoint, body=body, headers=headers)
```

| Site | Operation | Handler | Disposition |
|---|---|---|---|
| resolution.py:50 | well-known GET | `except (TransportError, NetworkPolicyError)` at resolution.py:51 | finding (TypeError escapes) |
| runtime.py:964 | outbound message POST | `except TransportError` at runtime.py:965 | finding (data loss + churn) |
| runtime.py:1113 | gossip batch POST | `except TransportError` at runtime.py:1114 | finding (gossip dead) |

Class is closed: three call sites, all affected, all enumerated.

## Side discoveries (single-pass, not folded into the verdict)

- **IPv6 unbracketed rewrite** (`transport.py:request`, `target_url = f"https://{ip}:{port}..."`).
  Separate latent defect, same trace. Trigger: any hostname whose first policy-allowed
  `getaddrinfo` result is IPv6. Production-reachable today. Outcome: `LocationParseError` →
  `TransportError` → retryable failure for that endpoint (no uncaught crash). Frequency:
  latent/ungrounded (depends on the peer's DNS answer order; a dual-stack peer returning AAAA first
  is plausible but not demonstrable without live DNS). Severity L (bounded: one peer's endpoints
  fail). Fix constraint: bracket IPv6 literals; the `parsed.port`/`request_uri` handling is
  otherwise correct.
- **`fields` is a dead parameter** on `OutboundTransport.request` — no caller supplies it. Not a
  defect; noted so the repair drops it rather than trying to make it work. Not priced.

## Bound

- Generalization "invalid on every urllib3 2.x" was not verified across all 2.x releases; the pinned
  and installed 2.7.0 (`uv.lock:861`) was verified directly, and that is the deployed artifact.
- The startup-crash consequence was traced from code (`cli.py:718` has no guard around
  `runtime.start()`), not observed on a live host; live DNS/TLS and a running daemon were
  unavailable.
- The remote-500 path was traced through source; it was not exercised against a live daemon. The
  determining fact — that no automatic path creates a peer-with-domain-without-pin while finding 1
  stands — rests on the caller enumeration of `create_peer` (topology.py:243; runtime.py:452/467)
  and the fact that `verify_candidate` is itself blocked at `resolve_with_ip`.
- Attacker-volume frequency for any resource-exhaustion consequence is not demonstrable here and is
  out of this finding's scope.
