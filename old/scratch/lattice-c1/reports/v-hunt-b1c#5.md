# v-hunt-b1c#5 — primed verifier

Claim under test: **hunt-b1c#5** in `scratch/lattice-c1/reports/hunt-b1c.md`, reported tier **L**
("Per-minute rate below 1.0 permanently locks out all inbound traffic (LATENT)").

## Verdict

**CONFIRMED** at tier **L**, frequency **latent** (unchanged). The mechanism is traced
arithmetically; the trigger is an operator configuration value; no in-tree code path produces it.
One sub-claim is refuted at the level of wording (cold senders get 503, not 429); the outcome the
finding describes stands.

## Re-derived frame (from source, before the claim)

- `lattice/config.py:92-98` `RateLimitConfig.__init__`: `messages_per_minute = float(data.get(...))`,
  `gossip_per_minute = float(data.get(...))`, validated only by
  `if self.messages_per_minute <= 0 or self.gossip_per_minute <= 0: raise ConfigError`.
  Defaults are `60` / `30` (`config.py:21-22`). `load_config` parses TOML via `tomllib`
  (`config.py:171-178`); nothing else validates these fields (`rg` over `lattice/` shows the
  `<= 0` guard is the only check; `cli.py` only calls `load_config`).
- `lattice/runtime.py:263-266` constructs `RateLimiter(messages_per_minute=..., gossip_per_minute=...)`
  — **only two arguments**. `capacity_minutes` therefore always takes its default `1.0`
  (`rate_limit.py:81`); it is not configurable anywhere in the tree.
- `lattice/rate_limit.py:83-88`: `if messages_per_minute <= 0 ... raise`; `_messages_rate = mpm/60`;
  `_gossip_rate = gpm/60`.
- `_bucket` (line 97): `capacity = rate * 60.0 * self._capacity_minutes`. With `capacity_minutes = 1.0`
  this is exactly `messages_per_minute` (resp. `gossip_per_minute`).
- `TokenBucket.__post_init__` (lines 32-38) sets `_tokens = capacity`.
- `consume(1.0)` (line 64): refills to `min(capacity, ...)`, then `if self._tokens >= 1.0`.

Decisive arithmetic (`python3`, exact):

```
mpm=0.5  rate=0.008333  cap=0.5   consume(1.0) -> always False
mpm=0.9  rate=0.015     cap=0.9   consume(1.0) -> always False
mpm=1.0  rate=0.0166    cap=1.0   consume(1.0) -> possible
mpm=60   rate=1.0       cap=60.0  consume(1.0) -> possible
```

Callers: `api.py:265` `allow_gossip(peer_id)` before `receive_batch`; `api.py:335`
`allow_message(from_node_id)` after signature verification and recipient check, before
`inbound_service.accept`. Both return `_problem(429, ...)` on `False`.

## Component verdicts

- **Mechanism — CONFIRMED.** `capacity = mpm` and `consume` requires `>= 1.0` token; any
  `messages_per_minute < 1.0` (or `gossip_per_minute < 1.0`) yields `capacity < 1.0`, which clamps
  the refill so `consume(1.0)` can never succeed. Buckets start at `capacity` and never exceed it,
  so the denial is permanent from construction, not a warm-up. Arithmetic exact, no ambiguity.
- **Trigger — CONFIRMED (config).** `RateLimitConfig` accepts any float `> 0`; `0.5` is legal TOML
  and passes validation. `_bucket`'s formula uses only the per-minute rate (capacity_minutes fixed
  at 1.0), so the threshold is exactly `mpm < 1.0`. A node configured for a sub-1/min rate (e.g.
  "one per couple of minutes") is bricked at `__init__` and no message can be accepted, ever.
- **Frequency — LATENT (claim correct, left unchanged).** No in-tree producer emits a sub-1 rate;
  tests use `60/30` (`conftest.py:150`, `test_runtime.py:56`) and `2/2` (`test_api.py:58`). The
  trigger is a one-time operator config choice with no cadence I can ground, so latent is the
  correct label. (Because latent, it correctly sits at the L cap.)

## Sub-claims refuted / corrected

- **"every inbound message ... rejected with 429 ... from every peer"** — partially inaccurate.
  Cold senders never reach the rate-limit call: `receive_message` returns **503** for the
  `cold_sender` branch (`api.py:302-318`) before `allow_message`; blocked senders get a signed
  **202 rejected** (`api.py:293-299`). The accurate statement is: every *known, non-blocked* sender
  receives 429, and the node takes no custody from anyone (cold senders get 503 instead). The
  finding's outcome — "no inbound traffic is ever accepted" — holds for every peer; only the status
  code named for the cold subset is wrong. This is a wording defect, not a mechanism defect.
- **"silently, from process start"** — CONFIRMED. No startup warning, no log; the first request
  from each peer is 429.

## Additional mechanisms / earlier failure sites (same trace)

1. **Non-finite rate accepted** (see Side discovery S1 below) — `nan` passes `x <= 0` (nan
   comparisons are False in both `config.py:98` and `rate_limit.py:83`), and `nan` capacity makes
   `consume(1.0)` permanently False. Same validation gap, same outcome, distinct trigger value.
2. **Earlier failure site**: the validation gap is at `config.py:98` (and mirrored at
   `rate_limit.py:83`); both must be repaired for the config layer and the library layer to agree.
   A fix only in `RateLimiter.__init__` leaves `RateLimitConfig` accepting `nan`/sub-1 into other
   callers of the config object; a fix only in `config.py` leaves the library contract
   (`rate_per_second > 0`, capacity any positive) still able to produce a sub-token bucket if a
   future caller sets `capacity_minutes < 1.0`.
3. **New reachability**: none beyond config. Cold-sender spam that avoids the token bucket is
   finding hunt-b1c#1's trace, not this one; noted to avoid conflating.

## Fix-direction constraints

- The threshold is a *capacity-vs-demand* mismatch, not a rate formula error. The principled fix is
  `capacity = max(1.0, rate * 60.0 * capacity_minutes)` (guarantee at least one token of burst) so
  legitimate sub-1/min rates still admit one message per refill window; an alternative is to
  validate `messages_per_minute >= 1.0 and gossip_per_minute >= 1.0` in `RateLimitConfig`, but that
  forbids a reasonable operator configuration.
- A repair must reject or normalize **non-finite** values too: `nan` currently passes `<= 0` in
  both guards, `inf` is harmless but should be deliberate. Use `math.isfinite` + `> 0`, not `<= 0`.
- Because `capacity_minutes` is a live constructor parameter, the fix belongs in `_bucket`
  (or `RateLimiter.__init__`), not only in the config validator. Guard both `message` and `gossip`
  kinds; they fail independently.
- Escaping the lockout is not the same as validating intake: repairing capacity alone leaves a
  sub-1/min config that admits exactly one message per >1 minute and then silently queues the rest
  as 429 — acceptable, but the operator gets no signal that their configured rate is below the
  protocol's minimum message cadence.

## Checked and clean

- `RateLimiter.__init__` guard `<= 0` correctly rejects `0` and negatives (verified with `tomllib`
  for `0`, `-inf`).
- `TokenBucket.consume` refill arithmetic `min(capacity, tokens + elapsed*rate)` is correct and
  clamps; `_last_updated` advances on the failed branch (no double-crediting); locks are
  leaf-level (bucket lock taken while holding no other lock in the consuming path).
- `snapshot`/`restore` mirror the same `rate*60*capacity_minutes` capacity, so restored buckets
  are consistent with freshly built ones — the sub-1 defect is preserved across restart, not
  masked (restore does not rescue the node).
- `capacity_minutes` has exactly one construction site (`runtime.py:263`), so the "always 1.0"
  premise used above is closed: `rg -n "RateLimiter\(|capacity_minutes"` → one instantiation,
  default only.
- `float(...)` accepts TOML integers and floats uniformly; integer configs `>= 1` are unaffected.

## Enumeration

Composed command closing the class (rate-limit configuration and construction surface):

```
rg -n "RateLimiter\(|capacity_minutes|messages_per_minute|gossip_per_minute" lattice/ tests/
```

Instance table:

| Site | Disposition |
|---|---|
| `rate_limit.py:79-88` ctor guards + rate derivation | examined — `<= 0` guard misses nan and sub-1 capacity |
| `rate_limit.py:97` capacity formula | **finding site** — `capacity = mpm` |
| `rate_limit.py:64` `consume(1.0)` | **finding site** — demand 1.0 vs capacity < 1.0 |
| `rate_limit.py:130-131,155-156` snapshot/restore capacity | same formula, consistent — clean |
| `runtime.py:263-266` sole constructor | confirmed only 2 args passed; `capacity_minutes=1.0` |
| `config.py:92-98` validation | **earlier failure site** — accepts any float > 0 |
| `config.py:206-207` sample config | integers 60/30, in-range |
| `tests/conftest.py:150`, `tests/test_runtime.py:56` | 60/30 — no coverage of sub-1 |
| `tests/test_api.py:58` | 2/2 — capacity 2, no coverage of sub-1 |
| `api.py:265` `allow_gossip` | caller, 429 path confirmed |
| `api.py:335` `allow_message` | caller, 429 path confirmed; cold/blocked excluded |

## Side discoveries

**S1 — [L] Non-finite `messages_per_minute`/`gossip_per_minute` passes validation and bricks the node (latent).**
Location: `lattice/config.py:98` and `lattice/rate_limit.py:83`, shallowest at `config.py:98`.
Evidence: `if self.messages_per_minute <= 0 ...` — `float('nan') <= 0` is `False`, so `nan` is
accepted; `rate = nan/60`, `capacity = nan`; `TokenBucket.__post_init__`'s `<= 0` guards also pass
under nan; `consume`: `min(nan, ...) = nan`, `nan >= 1.0` is `False` → every request 429.
Trigger: operator writes `messages_per_minute = nan` (valid TOML 1.0 float, parsed by `tomllib` as
`float('nan')`). Frequency: latent (operator config, no in-tree producer, no cadence). Outcome:
total permanent inbound lockout, identical to the main finding. Fix-direction constraint: the
validation must use `math.isfinite(x) and x > 0`, not `x <= 0`; applies to both fields at both
guard sites. Note `inf` is accepted but harmless (`capacity = inf`, consume succeeds) — a fix
should decide inf deliberately rather than by accident. Confidence: mechanism and trigger traced;
frequency latent. This is the same validation gap as the main finding with a distinct trigger
value; it is not counted as a new independent defect for the main verdict.

**S2 — [S-] `capacity_minutes` is a public constructor parameter with no validation against `< 1.0`.**
Location: `lattice/rate_limit.py:81,97`. If any future caller passes `capacity_minutes < 1.0` with a
sub-1 per-minute rate, the same lockout occurs; today the sole caller (`runtime.py:263`) uses the
default, so this is unreachable. Single-pass observation; no current runtime trigger. Not promoted.

## Bound

- Live provider / deployment behaviour not exercised: whether an operator would in practice choose a
  sub-1 `messages_per_minute`, and whether the deployment's config loader (nginx/systemd, out of
  Python scope per invariant 7) adds any schema that rejects it. The defect is proven conditional on
  a legal TOML value reaching `RateLimitConfig`; nothing in the Python tree prevents that.
- No test in the tree exercises `messages_per_minute < 1.0` or `nan`, so the defect is unverified by
  the suite (tests-only reachability does not exist; the trigger is config-only).
- `cli.py` offline/admin commands and non-serving config consumers were not enumerated beyond the
  `load_config` call sites listed; none of them consume `rate_limit` independent of `RuntimeCoordinator`.
