# v-hunt-q-error#6 — PRIMED VERIFIER

Claim under test: `hunt-q-error#6` in `scratch/lattice-c1/reports/q-error.md`, reported tier **L**.
Verdict: **ADJUSTED**. Mechanism confirmed; frequency and the "zero audit entries ever" outcome
partially refuted. Tier unchanged: **L**. Reachability: **PRODUCTION**.

---

## Frame re-derived from source (before accepting the claim's outcome phrasing)

Independently established facts:

- `_run_outbound_delivery` (`lattice/runtime.py:922`) claims a batch via
  `self._outbound.claim_for_delivery(owner, limit=5)` and has three pre-send branches before
  `_send_outbound_message`:
  - corrupt `message_json` (cannot `json.loads`): `record_failure(..., retryable=False)` (926–931)
  - `endpoint is None`: `record_failure(..., retryable=True)` + `_circuit_record_failure` (932–936)
  - `_circuit_is_open(node_id)`: `record_failure(..., retryable=True)` only (937–940)
- None of the three branches calls `_audit_outbound_failed` (`runtime.py:855`) or any `logger`
  method. Every post-send branch does (`965–974` TransportError, `993–998` invalid receipt,
  `1005–1010` 429/5xx, `1013–1018` non-2xx terminal).
- `claim_pending` (`lattice/storage/repositories.py:702`) sets `attempt_count = attempt_count + 1`
  in its UPDATE (`:718`), so each claim — including a deferral that never touches the network —
  consumes one attempt.
- `record_failure` (`lattice/messages.py:158`): retryable path reads `attempt_count`; if
  `should_retry` is False (`attempt_count < max_attempts`; `max_attempts = 10`, `messages.py:43`)
  it calls `mark_terminal(..., "failed", erase_content=True)` (`messages.py:184–192`), which erases
  `content`, `extension`, and `message_json`. Non-retryable path terminates immediately.
- `mark_terminal` (`repositories.py:775`) writes no audit row; `record_failure` writes none.
- The audit grammar in the tree has exactly five codes — `INBOUND_ACCEPTED`, `OUTBOUND_DELIVERED`,
  `OUTBOUND_FAILED`, `WEBHOOK_DELIVERED`, `WEBHOOK_FAILED` (`runtime.py:831–889`); there is no
  OUTBOUND_EXPIRED or deferral code.

So the mechanism the claim names is real: an outbound message can reach terminal `failed` with
content erased without any `OUTBOUND_FAILED` (or other) audit row.

## Sub-claim adjudication

| # | Sub-claim | Verdict |
|---|---|---|
| a | Circuit-open branch calls no audit / no logger | CONFIRMED (`runtime.py:937–940`) |
| b | `endpoint is None` branch calls no audit / no logger | CONFIRMED (`runtime.py:932–936`) |
| c | Corrupt-`message_json` branch calls no audit (and is immediately terminal) | CONFIRMED (`runtime.py:926–931`, `retryable=False`) |
| d | `claim_pending` increments `attempt_count` each cycle; terminal via `should_retry` | CONFIRMED (`repositories.py:718`; `messages.py:184–192`) |
| e | Terminal transition erases content with no audit record | CONFIRMED (`mark_terminal` `repositories.py:775`) |
| f | Trigger = outbound message to a peer whose circuit is tripped or whose endpoint is unknown | CONFIRMED (reachable; see reachability) |
| g | **"zero audit entries ever written for that message"** for a down peer | **PARTIALLY REFUTED** — see below |
| h | Frequency: **"every message destined to a peer that is down or endpoint-less for the duration of the retry window"** | **PARTIALLY REFUTED** — overstated; see below |
| i | Outcome is bounded to an observability/audit gap | CONFIRMED |

### Refuted halves (g) and (h)

The circuit breaker trips only after `_CB_THRESHOLD = 3` consecutive failures (`runtime.py:767`,
`_circuit_is_open` requires `failures >= threshold`). For a **down-but-known** peer (endpoint
resolves, transport fails), attempts 1–3 go through `_send_outbound_message`, whose TransportError
branch (`runtime.py:965–974`) calls `record_failure(retryable=True)` **and**
`_audit_outbound_failed(..., reason="TransportError: ...")`. So that message is not left with
"zero audit entries ever" — it carries three `OUTBOUND_FAILED` rows before the circuit opens. What
is genuinely un-audited is (i) the deferral cycles at attempts 4–10 and (ii) the terminal
`mark_terminal("failed")` transition itself. Sub-claim (g) therefore holds only for the two
populations whose first claim already bypasses the send path:

- **endpoint-less peer** (`peer_endpoint_for_node` returns None, `runtime.py:739`): every claim hits
  the `endpoint is None` branch, so zero audit rows for the whole life of the message; and
- **message first claimed while the circuit is already open** (tripped by an earlier message to the
  same node): every claim hits the circuit branch, zero audit rows.

The claim's frequency sentence ("every message ... to a peer that is down") folds the down-but-known
case into the zero-audit population, which is false. The corrected frequency: DEMONSTRATED for the
mechanism and for the two zero-audit populations; the down-but-known population retains partial
(early-attempt) audit and its final transition is silently un-audited. The common cadence is "any
message enqueued for a peer whose circuit is open at first claim, or any message whose destination
node has no known endpoint".

## Reachability

PRODUCTION. Outbound messages are created by `POST /lattice/v1/admin/messages/submit`
(`api.py:379–409`, admin-gated) and by the CLI submit path; `resolve_address` for a canonical
`user@lat_...` address returns a node_id **without** network resolution or pin creation
(`resolution.py:154–180`), so `peer_endpoint_for_node` returns None and the endpoint-less branch is
directly reachable by an operator addressing a not-yet-resolved node. The circuit-open branch is
reachable whenever a peer has accumulated 3 consecutive failures from any earlier delivery.

## Added mechanisms / earlier failure sites

1. **Outbound expiry has the same missing-audit gap, over a larger population.**
   `_run_expiry_cleanup` (`runtime.py:1134`) calls `self._outbound.expire()` (`runtime.py:1135`,
   recurring 60 s task) → `OutboundMessageService.expire` → `expire_messages`
   (`repositories.py:844`), which sets `status='expired'` and erases `content`/`extension`/
   `message_json` (`RETURNING message_id`) with no `_audit_*` call anywhere. There is no
   OUTBOUND_EXPIRED code in the five-code audit vocabulary. This is the same observability fault on
   a distinct terminal transition and a broader population (every undelivered message that reaches
   TTL). Reachability PRODUCTION; severity L; frequency DEMONSTRATED (every message not delivered
   before expiry). A repair of F6 that touches only the three pre-send branches leaves this intact.
2. **Deferral cycles burn the delivery retry budget.** Because `claim_pending` increments
   `attempt_count` for every claim including circuit-open deferrals, a message whose destination's
   circuit is open for all ten cycles is terminally failed and content-erased having **never been
   sent once**. This is the "consume retry attempts" half of the title, confirmed; it is a
   behavioural consequence of the same branches, not a separate defect, but it constrains the fix
   (see below).

## Fix-direction constraints

- Attaching `_audit_outbound_failed` directly at the three runtime branches is **wrong**: on a
  non-terminal retryable failure `record_failure` only releases the lease (`messages.py:196–197`),
  so an unconditional audit there would log `OUTBOUND_FAILED` for deferrals that did not fail —
  manufacturing a false audit field of its own kind. The audit must be tied to the terminal
  transition (e.g. when `record_failure`/`mark_terminal` actually moves the row to `failed`), or
  use a distinct deferral event code.
- The terminal "is this the last attempt" decision lives inside
  `OutboundMessageService.record_failure` (`messages.py:158–198`), not in `_run_outbound_delivery`.
  The runtime branches cannot distinguish "released for retry" from "terminally failed" from the
  return value as written (`release_lease`/`mark_terminal` both return bool). A correct repair needs
  `record_failure` to surface which transition occurred (or a terminal-audit hook in
  `mark_terminal`), otherwise the audit fires on every deferral.
- Any repair must also cover the expiry transition (added mechanism 1), or the same message can
  still be silently content-erased on a different path.
- If the fix chooses to stop counting deferrals as attempts (added mechanism 2), that must be a
  deliberate retry-policy change, not a side effect; today a never-sent message can consume the full
  budget.

## Checked and clean

- The four post-send failure branches each call `record_failure` **and** `_audit_outbound_failed`:
  TransportError (`runtime.py:965–974`), invalid custody receipt (`993–998`), HTTP 429/5xx
  (`1005–1010`), HTTP non-2xx terminal (`1013–1018`). Audit wiring is correct on the actual send
  path; the gap is confined to the three pre-send branches.
- `_audit_outbound_delivered` is called on the accepted-202 path (`1001–1003`).
- `record_success`/`release_lease`/`mark_terminal` semantics: the terminal decision and content
  erasure in `messages.py:158–198` and `repositories.py:775` are internally consistent; the defect
  is the absence of an audit call, not the erasure itself (terminal erasure is intended per
  `docs/ARCHITECTURE.md:50`).
- `docs/LOOSE_ENDS.md:33` claims "Audit wiring completed — `_audit_outbound_failed()` called on
  delivery failures"; that statement is accurate for the send path but does not cover the pre-send
  terminal branches, so it is not a contradicting authority.

## Enumeration

Class = every call that can drive an outbound message to a terminal state, and every audit call that
could observe it:

```
rg -n "mark_terminal|expire_messages|_outbound\.expire|record_failure|_audit_outbound_failed|_audit_outbound_delivered" lattice/ -g '*.py'
```

Instance disposition:

| Site | Disposition |
|---|---|
| `runtime.py:965–974` TransportError | audited (OUTBOUND_FAILED) — clean |
| `runtime.py:993–998` invalid receipt | audited — clean |
| `runtime.py:1005–1010` 429/5xx | audited — clean |
| `runtime.py:1013–1018` non-2xx terminal | audited — clean |
| `runtime.py:926–931` corrupt json (terminal) | **no audit** — F6 |
| `runtime.py:932–936` endpoint None | **no audit** (terminal after 10 attempts) — F6 |
| `runtime.py:937–940` circuit open | **no audit** (terminal after 10 attempts) — F6 |
| `runtime.py:1135` `_outbound.expire()` → `expire_messages` | **no audit** — added mechanism 1 |
| `messages.py:158–198` `record_failure` | no audit at any transition — root of F6 |
| `repositories.py:775` `mark_terminal` | no audit — root of F6 |

## Bound

- Audit persistence is logging-level gated: `_write_audit_entry` (`runtime.py:80`) writes only when
  `logger.isEnabledFor(level)`. Whether a repaired audit call actually produces durable rows in a
  given deployment depends on the live logging configuration, which I did not reach. The existing
  audited branches carry the same gate; the finding is about *calls missing*, independent of the
  gate.
- I did not reach live peer behaviour or the real cadence with which operators submit canonical
  addresses for unresolved nodes; the endpoint-less trigger is traced in code, its deployment
  frequency is grounded in the CLI/admin submit population, not measured.
