# q-error — error-path misreporting (tree-wide `except` enumeration)

Pass type: blind hunter. Scope: every `except` clause in `lattice/` (98 clauses),
checked for truthful reflection in log level, HTTP status/code, audit record, and
retry/terminal decisions. Whole tree read end-to-end (all 34 modules under `lattice/`).

Reachability kinds are stated per finding per the standing calibration.

---

## Findings

### 1. [H] Cold-sender resolution queue is unbounded, retried forever at DEBUG level
- Location: `lattice/runtime.py:_resolve_pending_senders` (lines 899–921), `queue_domain_resolution` (895–898); reached via `lattice/api.py:receive_message` (303–316)
- Evidence:
  ```python
  for domain in batch:
      try:
          self._resolver.pin(domain)
      except ResolutionError as exc:
          logger.debug("async pin failed for %s: %s", domain, exc)
          continue
  ```
  The docstring on the same method says "On failure, drops it from the queue" — the code does not drop it; the domain stays in `_unresolved_domains` forever and is re-fetched (DNS + HTTPS GET, 10 s connect timeout) every 30 s cycle.
- Trigger: any unauthenticated network peer POSTs `/lattice/v1/messages` with a schema-valid message whose `from_address` is `user@<any-unpinned-domain>`. `verify_inbound_message` returns the cold-sender path BEFORE signature verification and BEFORE `allow_message` (rate limiter runs at api.py:335, after the 503 return at 316). `queue_domain_resolution` then adds the domain to a set with no cap, no expiry, and no removal on failure.
- Frequency: DEMONSTRATED — population is every unauthenticated POST to the public messages route; each request with a fresh domain-form `from_address` permanently enqueues one domain; the node then performs one HTTPS resolution attempt per queued domain per 30 s until restart. One spray of N requests yields N perpetual fetches every 30 s.
- Outcome: unbounded memory growth of `_unresolved_domains`; unbounded recurring outbound network egress driven by remote unauthenticated input; the whole batch resolves serially on one maintenance worker, starving `verify_candidates`/`gossip_round`/`refresh_topology` as the queue grows; persistent failures are logged at DEBUG (invisible at default INFO level), so operators see nothing.
- Confidence: traced (mechanism, trigger, frequency all verified in code; ordering before rate limit confirmed at api.py:303–335). Reachability: PRODUCTION (public route, no auth, no signature, no rate limit on this path).

### 2. [M] Sender retries a final "rejected" receipt and mislabels it "invalid custody receipt"
- Location: `lattice/runtime.py:_send_outbound_message` (lines 978–1000)
- Evidence:
  ```python
  if (
      data.get("message_id") != message_id
      or data.get("node_id") != to_node_id
      or data.get("status") != "accepted"
  ):
      logger.warning("invalid custody receipt from %s for %s: %s", ...)
      self._outbound.record_failure(message_id, owner, retryable=True)
  ```
  PROTOCOL.md §8: "A `202 Accepted` with a rejected receipt is final."
- Trigger: our node delivers a message; the destination answers 202 with a valid signed receipt whose `status` is `"rejected"`. In-tree producers of that receipt: `api.py:339` CustodyError branch (Finding 3), `api.py:293` BlockedSenderError branch (blocked-sender producer itself is TESTS ONLY today — `BlockStore.block` has no production caller). Any federated peer (outside-written, hostile content) can also return a rejected receipt directly.
- Frequency: DEMONSTRATED for the mechanism — every outbound delivery whose destination responds 202+rejected. Producer population today: hostile/foreign peers, in-tree destinations hitting Finding 3, or destinations that blocked us (once a production block route exists). Not everyday, but each occurrence burns the full retry schedule.
- Outcome: a receipt that is well-formed and deliberately final is (a) logged and audited as `OUTBOUND_FAILED reason="invalid custody receipt"` — a false statement about a valid receipt — and (b) marked retryable, so the sender retries a final rejection through the whole `RetryPolicy` (10 attempts, backoff to 24 h) or until TTL, hammering a destination that has already refused, instead of stopping per §8.
- Confidence: traced (mechanism and trigger verified; no in-tree code path honors §8 finality — `grep` confirms no other consumer of receipt `status`). Reachability: PRODUCTION via hostile peer or Finding 3; the blocked-sender producer is TESTS ONLY (marked per calibration).

### 3. [M] Transient storage failure is converted into a final "rejected" custody receipt
- Location: `lattice/api.py:receive_message` (lines 338–345), fed by `lattice/messages.py:InboundMessageService.accept` (284–290)
- Evidence:
  ```python
  except CustodyError:
      # Durable custody could not be established; final signed rejection.
      rejected = runtime.inbound_service.build_receipt(
          str(message.get("message_id", "")), "rejected")
      return JSONResponse(status_code=202, content=rejected)
  ```
  `accept` wraps any `repo.create` failure as `CustodyError` — including sqlite I/O errors, disk-full, and `database is locked` beyond the 5 s busy timeout, which are transient server-side conditions, not a decision to refuse custody.
- Trigger: a signature-verified message arrives while the destination's durable write fails — e.g. an operator runs a writing CLI command (`contacts import`, `trust accept-transfer`, `upgrade`) against the same durable DB concurrently with the daemon and holds a write past the 5 s busy timeout, or the disk fills.
- Frequency: DEMONSTRATED population but uncommon cadence — every inbound accept whose durable insert raises; the concrete producers are cross-process write contention and disk-full (both reachable in a normal deployment with operator CLI use). I cannot ground a rate; the trigger requires a storage fault or a cross-node `message_id` collision (inbound_messages.message_id is single-column UNIQUE, so a second node reusing an existing message_id also lands here).
- Outcome: a temporary inability to write is reported to the sender as a FINAL refusal (202 + rejected receipt; §8: "the sender stops retrying"). Per invariant 5, a 202 issued when durable custody was not established is reportable; the correct signal for a transient failure is 503 + Retry-After. Today Finding 2 partially masks the loss (the sender retries anyway); if Finding 2 is repaired to honor §8, this path permanently drops messages during storage outages.
- Confidence: traced mechanism; trigger storage-fault-dependent (unproven frequency). Reachability: PRODUCTION, environment-armed (requires DB failure or message_id collision).

### 4. [M] Unknown-sender / structural errors returned as 401; canonical-form senders get terminal failure where domain-form senders get 503
- Location: `lattice/api.py:receive_message` line 301; produced by `lattice/runtime.py:verify_inbound_message` (635, 656) and `_certificate_for_node` (680)
- Evidence:
  ```python
  except RuntimeError as exc:
      return _problem(401, "Message rejected", str(exc))
  ```
  with `raise RuntimeError(f"no operational certificate for sender: {from_node_id}")` (runtime.py:656) and `except ResolutionError: pass` in `_certificate_for_node` (runtime.py:680).
- Trigger: (a) A message whose `from_address` is canonical (`user@lat_...`) from a node this destination has never seen (no peer row, no pin) → `_certificate_for_node` returns None → RuntimeError → 401. On the SENDER side (`_send_outbound_message`), 401 is neither 202 nor 429/5xx → `record_failure(retryable=False)` → message marked `failed` and content erased — permanent loss on first contact. (b) A schema-invalid message body → `RuntimeError("invalid message: ...")` → 401 instead of 400. PROTOCOL §9 maps unknown node → 404 and malformed input → 400; only signature failure is 401.
- Frequency: DEMONSTRED — population is (a) every first-contact message from a peer using a canonical `from_address` (contact cards export exactly this form — `cmd_contacts_export` builds `username@node_id`) during the window before the destination gossips/pins the sender, and (b) every malformed message any peer sends. Normal-operation cadence: happens on each new peer pairing.
- Outcome: divergence between two paths that must agree — the domain-form from_address gets the cold-sender path (503 + `queue_domain_resolution` + sender retry, api.py:303–316) while the canonical-form from_address of the SAME logical condition ("sender unknown") gets 401, which the sender treats as terminal and erases. Additionally the 401 problem code (`LATTICE_UNAUTHORIZED`) misclassifies "sender not yet known" and "malformed body" as authentication failures.
- Confidence: traced (all branches verified; sender-side terminal handling of 401 verified at runtime.py:1005–1013). Reachability: PRODUCTION.

### 5. [L] Malformed `to_address` crashes the handler — HTTP 500, non-problem-details body
- Location: `lattice/api.py:receive_message` line 322 → `lattice/addressing.py:parse_address` (raises `AddressError` when the address has no `@`)
- Evidence:
  ```python
  to_domain = _extract_domain_from_address(message.get("to_address", ""))
  ```
  `Message` (protocol/models.py) validates `to_address` only as a 1–320 char string, never as an address; `verify_inbound_message` parses only `from_address`. An uncaught `AddressError` propagates out of the sync route.
- Trigger: a known, signature-valid peer sends a message whose `to_address` lacks `@` (e.g. `"garbage"`). Passes model validation and signature verification, then raises at line 322.
- Frequency: DEMONSTRATED — any hostile or buggy peer with a valid certificate can send this; the messages route is public. Cadence: once per such message (and the sender retries it, see below).
- Outcome: an input-validation fault is reported as HTTP 500 (server fault) instead of 400, in plain JSON rather than the §9 problem-details format; the sender-side treats 5xx as retryable, so it re-sends the doomed message for the full retry schedule. Bounded: no state corruption, no custody taken.
- Confidence: traced (model fields and handler order verified; no try/except around the call). Reachability: PRODUCTION (requires hostile/buggy known peer — outside-written content).

### 6. [L] Circuit-open / no-endpoint failure paths consume retry attempts and terminally erase messages with no audit record
- Location: `lattice/runtime.py:_run_outbound_delivery` (lines 928–940) and the terminal branches of `lattice/messages.py:record_failure` (154–173)
- Evidence:
  ```python
  if self._circuit_is_open(row["to_node_id"]):
      self._outbound.record_failure(row["message_id"], owner, retryable=True)
      continue
  ```
  No `logger` call and no `_audit_outbound_failed` on this path (nor on the `endpoint is None` path at 928–931, nor on the corrupt-`message_json` path at 926–932), while every actual send failure is audited.
- Trigger: an outbound message to a peer whose circuit breaker is tripped (3 consecutive failures) or whose endpoints are unknown. `claim_pending` increments `attempt_count` each cycle; when `should_retry` returns False, `mark_terminal("failed")` erases content — with zero audit entries ever written for that message.
- Frequency: DEMONSTRATED — every message destined to a peer that is down or endpoint-less for the duration of the retry window; that is a common occurrence for any intermittent peer.
- Outcome: messages can be terminally failed and content-erased leaving no `OUTBOUND_FAILED` (or any) audit trail, breaking the audit invariant held by every other outbound failure path. Bounded bad outcome: observability/audit gap only.
- Confidence: traced (mechanism and trigger verified; no audit call exists in the branch). Reachability: PRODUCTION.

---

## Checked and clean

- **resolution.py** (all 7 except sites): every failure class — transport, content-type, JSON, schema, key decode, signature, certificate — is re-raised as `ResolutionError` with the failing cause in the message; status and content-type mismatches included. Correct.
- **topology.py** (9 sites): each verification-step failure re-raised as `TopologyError` with cause; candidate removal on card-invalid and verify-fail is correct; `ResolutionError` at 224 intentionally retains the candidate for retry until candidate TTL. Correct.
- **identity.py:299, canonical.py:57/59, crypto.py:27/62/105, protocol/models.py (5 sites), config.py:45**: all re-raise a narrower, contextual error (`IdentityError`, `JSONParseError`, `SignatureError`, `ModelError`, `ConfigError`). Correct.
- **gossip.py:92/130**: card-validation and accept failures are surfaced per-card as `accepted=False` with a reason string in the 200 response `errors[]` list — truthful reporting to the sender. gossip.py:246 (corrupt transient card skipped when selecting a batch) is silent but operates on the disposable cache written by our own `json.dumps`; noted under side discoveries.
- **webhook.py:98/111**: network/HTTP failures return `WebhookResult(retryable=True)` and upsert state; 429/5xx retryable, other 4xx terminal — classification matches the doc. Correct.
- **transport.py:78/85/92/141**: gaierror and urllib3 HTTPError → `TransportError` with cause; per-address policy failures try the next address before failing. Correct.
- **cli.py (21 sites)**: every site prints the failing operation to stderr with the exception text and returns 1 (KeyboardInterrupt → 130). Correct operator-facing reporting; root-key operations are offline CLI commands per invariant 2.
- **storage/migrations.py:30/113, storage/cache.py:27/65**: migration failures raise `MigrationError` naming the failed script number; cache schema mismatch rebuilds the disposable cache by design. Correct.
- **runtime.py** remaining sites: 133 (recurring-task exception log), 409/510 (rate-limit restore/persist — logged, disposable state), 429/458 (bootstrap warnings + continue), 524 (readiness probe), 550/554/567 (gossip sender-card verification → None, IP-fallback per PROTOCOL §5.2 — intended), 659 (signature invalid → 401 per §9 `LATTICE_INVALID_SIGNATURE`), 788 (self-written timestamp parse), 809/824 (circuit DB write failures logged, fail-open on disposable cache), 965 (TransportError → retryable + circuit + audit), 1037 (received_at fallback), 1114/1128 (gossip/verify-candidate warnings). All examined and correct.
- **messages.py submit/accept duplicate handling**: `get_existing_receipt` pre-check and the UNIQUE-race branch return the stored receipt byte-identically per PROTOCOL §5.3 — correct idempotency for the same (message_id, from_node_id).
- **rate_limit.py, peers.py, credentials.py, encoding.py, addressing.py:78, network_policy.py, protocol/signing.py**: no swallowed-error misreporting found (addressing.py:78 documents the None return).

## Enumeration

Composed command (closes the class; `\b` excludes `exception_handler`/`logger.exception` substrings — the plain `rg -n 'except'` returns 109 raw matches of which 11 are non-clause substrings):

```
rg -n '\bexcept\b' lattice/ -g '*.py' --no-heading | wc -l   # → 98
rg -n '\bexcept\b' lattice/ -g '*.py' --no-heading
```

Zero-check: the pattern was validated against known sites (e.g. `lattice/api.py:301` matches; `lattice/api.py:137` `@app.exception_handler` does not), so the 98 count is a true clause count, not a shape-missed zero.

Full instance table (site → caught → disposition → misreport?):

| Site | Caught | Disposition | Misreport? |
|---|---|---|---|
| identity.py:299 | ValueError | clean | no |
| resolution.py:51 | TransportError, NetworkPolicyError | clean | no |
| resolution.py:63 | Exception | clean | no |
| resolution.py:72 | Exception | clean | no |
| resolution.py:83 | Exception | clean | no |
| resolution.py:89 | Exception | clean | no |
| resolution.py:100 | Exception | clean | no |
| resolution.py:108 | IdentityError | clean | no |
| addressing.py:78 | AddressError | clean (documented None) | no |
| messages.py:102 | Exception | clean | no |
| messages.py:129 | Exception | clean (UNIQUE→CustodyError, else re-raise) | no |
| messages.py:256 | Exception | clean (unreachable after api pre-validation) | no |
| messages.py:284 | Exception | race branch clean; wrap feeds **F3** | yes (via F3) |
| topology.py:125 | ValueError | clean | no |
| topology.py:179 | Exception | clean | no |
| topology.py:214 | Exception | clean | no |
| topology.py:224 | ResolutionError | clean (retry-by-design) | no |
| topology.py:229 | TopologyError | clean | no |
| topology.py:303 | Exception | clean | no |
| topology.py:313 | Exception | clean | no |
| topology.py:323 | IdentityError | clean | no |
| topology.py:333 | Exception | clean | no |
| canonical.py:57 | JSONDecodeError | clean | no |
| canonical.py:59 | UnicodeDecodeError | clean | no |
| gossip.py:92 | Exception | clean (reason surfaced in response) | no |
| gossip.py:130 | Exception | clean (reason surfaced) | no |
| gossip.py:246 | Exception | clean; side discovery (silent skip) | no |
| cli.py:213,231,239,257,291,334,348,383,423,433,555,579,594,645,668,686,698,805 | various | clean (stderr + exit 1) | no |
| cli.py:1008,1011,1014 | CLIError/Config/Credential/KeyboardInterrupt | clean | no |
| api.py:189 | ValueError | clean (400 bad Content-Length) | no |
| api.py:293 | BlockedSenderError | clean per §8; producer TESTS ONLY (side discovery) | no |
| api.py:301 | RuntimeError | **F4** | yes |
| api.py:339 | CustodyError | **F3** | yes |
| api.py:346 | RuntimeError | clean (400) | no |
| api.py:393 | RuntimeError | clean (400) | no |
| api.py:407 | RuntimeError, ValueError | clean (400) | no |
| crypto.py:27 | ValueError | clean (PEM→DER fallback) | no |
| crypto.py:62 | ValueError | clean | no |
| crypto.py:105 | Exception | clean (SignatureError w/ cause) | no |
| webhook.py:98 | urllib3 HTTPError | clean | no |
| webhook.py:111 | Exception | clean | no |
| transport.py:78 | socket.gaierror | clean | no |
| transport.py:85 | ValueError | clean | no |
| transport.py:92 | NetworkPolicyError | clean | no |
| transport.py:141 | urllib3 HTTPError | clean | no |
| runtime.py:133 | Exception | clean (exception log) | no |
| runtime.py:409 | Exception | clean | no |
| runtime.py:429 | ResolutionError | clean (warning + continue) | no |
| runtime.py:458 | Exception | clean (warning + continue) | no |
| runtime.py:510 | Exception | clean | no |
| runtime.py:524 | Exception | clean (not-ready) | no |
| runtime.py:550,554,567 | Exception | clean (None → IP fallback per §5.2) | no |
| runtime.py:635 | Exception | feeds **F4** | yes (via F4) |
| runtime.py:659 | IdentityError, ValueError | clean (401 per §9) | no |
| runtime.py:680 | ResolutionError | feeds **F4** | yes (via F4) |
| runtime.py:788 | ValueError | clean | no |
| runtime.py:809 | Exception | clean (fail-open, disposable cache) | no |
| runtime.py:824 | Exception | clean | no |
| runtime.py:914 | Exception | folded into **F6** (no-audit terminal) | partial |
| runtime.py:930 | — (endpoint None) | folded into **F6** | partial |
| runtime.py:939 | — (circuit open) | **F6** | yes |
| runtime.py:965 | TransportError | clean | no |
| runtime.py:980 | Exception | feeds **F2** | yes (via F2) |
| runtime.py:1029 | Exception | folded into **F6** scope | partial |
| runtime.py:1037 | ValueError | clean (fallback `now()`) | no |
| runtime.py:1114 | TransportError | clean | no |
| runtime.py:1128 | Exception | clean (exception log) | no |
| migrations.py:30 | ValueError | clean (skip non-numbered file) | no |
| migrations.py:113 | sqlite3.Error | clean (MigrationError w/ script) | no |
| cache.py:27 | OperationalError | clean (disposable rebuild) | no |
| cache.py:65 | sqlite3.Error | clean (CacheError) | no |
| config.py:45 | ValueError | clean (ConfigError) | no |
| __init__.py:5 | ModuleNotFoundError | clean (dev version) | no |
| models.py:93,134,177,297,409 | Exception | clean (ModelError w/ context) | no |

Total: 98 clauses dispositioned (6 findings, 4 partially folded, remainder clean).

## Design risks (2)

1. **Custody receipts are never signature-verified by the sender** (`runtime.py:983–987` checks field equality only). A destination — or anything that can make the sender see a 202 body — can acknowledge custody it never took. No current misbehavior in-tree beyond the trust gap itself.
2. **The cold-sender 503 precedes both rate limiting and signature verification** (api.py:303–335). Fixing Finding 1 by capping the queue should also consider moving at least an IP-fallback rate check ahead of the queueing, or the spray surface remains.

## Side discoveries (single-pass candidates, not confirmed work)

- **Canonical `to_address` to another node is accepted into custody** (api.py:322–330): `_extract_domain_from_address` returns `""` for `user@lat_<other-node>` (parsed.domain is None), so the own-domains check is skipped and no node-id comparison exists anywhere on the inbound path — this node takes durable custody of messages addressed to a different node, contra PROTOCOL §7 "Reject messages addressed to a different node". Out of this pass's error-path scope; needs its own verification pass.
- **`BlockStore.block`/`topology.block` has no production caller** — no admin route or CLI command invokes it; the blocked-sender enforcement chain (§8 rejected receipts for blocked peers) is reachable only through tests today.
- `_RecurringTask.maybe_run` (runtime.py:120–133) leaves the task lock permanently held if `executor.submit` raises during shutdown (join-timeout race); harmless in the current shutdown order, daemon threads.
- `gossip.py:246` silently drops a corrupt transient card from outgoing batches; row persists until expiry. Disposable cache; negligible.

## Bound

- All 34 modules under `lattice/` were read end-to-end (including `storage/`, `protocol/`, migrations SQL schemas for UNIQUE constraints). Tests and `docs/` were consulted for intent (PROTOCOL §5.2, §5.3, §8, §9) but not dispositioned.
- No live infrastructure: SQLite contention behavior (SQLITE_BUSY timing beyond the 5 s busy timeout) and DNS/egress timing claims in Findings 1 and 3 are argued from code and documented timeouts, not measured.
- The enumeration pattern cannot match exception handling done without `except` (e.g. `try/finally`, `contextlib.suppress` — none found via `rg 'suppress'`), and does not cover unhandled-exception paths; Finding 5 is exactly such a path and was found by reading, not by the enumeration.
