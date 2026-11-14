# Fix report — C1 rows CERT (y6ty) and POIS (x105)

Executor: swarm-executor (resolution.py, runtime.py, topology.py, api.py). Status: EXECUTED.

## Files / functions changed

- `lattice/resolution.py` — `WellKnownResolver.resolve_with_ip` only, plus one dead import
  removed by the same change (`IdentityError` was imported solely for the removed except
  clause). +9/−4.
  - CERT: the entire cert block (`OperationalCertificate.from_dict` AND `cert.verify`) moved
    inside the try; the narrow `except IdentityError` became `except Exception` →
    `raise ResolutionError(f"operational certificate invalid for {domain}: {exc}") from exc`.
    Previously `from_dict` sat OUTSIDE the try and raised plain `ValueError` for a wrong-length
    `operational_public_key`, and `cert.verify` raised `SignatureError` — both `ValueError`
    siblings of `IdentityError`, escaping `resolve`/`pin` against the "Raises ResolutionError"
    contract. `except Exception` mirrors the five sibling blocks in the same function
    (well-known JSON, model_validate, root key decode, node-ID derivation, root signature), all
    of which already use `except Exception → ResolutionError`.
- `lattice/runtime.py` — `queue_domain_resolution` and `_resolve_pending_senders` only. +22/−3.
  - POIS (ingestion): `queue_domain_resolution` now strips/lowers and rejects malformed domains
    (empty, >253 chars, any of `:/@`, any whitespace) with a warning and returns without
    queueing. Shape rules mirror `addressing.parse_address`'s "minimal domain shape" checks
    (`: / @` forbidden, ≤253) extended with whitespace, which parse_address does not check and
    which was the poison vector ("not a domain" parses as a valid address host but detonates in
    the transport URL parser).
  - POIS (isolation): `_resolve_pending_senders` keeps its `except ResolutionError → debug +
    continue` branch and adds `except Exception → warning + continue` per item, so one hostile
    or broken domain cannot abort the batch. This also tolerates a `TransportError` escaping
    `resolve_with_ip` (the NOTE's requirement) and any residual leak. Failure semantics for
    well-shaped domains are unchanged (stay queued, retried next 30 s tick, sender gets 503 +
    Retry-After) — only the abort propagation is removed.
- `lattice/topology.py` — the two narrow except sites in `verify_candidate` and
  `_verify_against_well_known`, plus two dead imports removed by the same change
  (`IdentityError`, `ResolutionError` were used only by the widened except clauses). +14/−6.
  Note: the assignment said "sites near lines 223 and 318"; grep `except IdentityError` yields
  exactly ONE such site (323, in `_verify_against_well_known`). The second narrow-except site
  at ~223 is `except ResolutionError` in `verify_candidate`; both were corrected.
  - `_verify_against_well_known` (cert block): `except IdentityError` → `except Exception` →
    `TopologyError("operational certificate invalid: ...")`. Same hazard as CERT: `from_dict`
    plain `ValueError` and `verify` `SignatureError` escaped into candidate verification and
    startup (bootstrap peers). Mirrors the adjacent `except Exception → TopologyError` blocks
    in the same function.
  - `verify_candidate` (well-known fetch): `except ResolutionError` → `except Exception` →
    `TopologyError("well-known resolution failed: ...")`, so a leaked `ValueError`/
    `TransportError` sibling from `resolve_with_ip` fails closed per verify_candidate's
    TopologyError contract instead of surfacing raw.
- `lattice/api.py` — the `RuntimeError`-only handler in `admin_submit` only. +4/−1.
  - `except RuntimeError` → `except (RuntimeError, ValueError)`. `resolve_destination` →
    `resolve_address` raises `ResolutionError` and `AddressError` (both `ValueError`) for
    malformed/unresolvable addresses; these previously escaped the handler as a raw 500 on the
    admin submit route. Now a 400 problem response. The other two `except RuntimeError`
    handlers (~301, ~346) were not named and were not touched.

Exemplar mirrored: `runtime.py:verify_gossip_sender_card` (all cert operations inside one
failure boundary) for block sequencing, and the pre-existing
`except … as exc: raise ResolutionError(f"… invalid for {domain}: {exc}") from exc` idiom in
`resolve_with_ip` itself for the conversion. No new helpers, flags, abstractions, or
dependencies introduced.

## Verification — EXECUTED

Repo venv `.venv/bin/python`. Real loopback TLS infrastructure, no mocks, no fakes, no test
files: a private CA + leaf cert (SANs for the probe hostnames) generated with `cryptography`,
an `http.server` HTTPS server on `[::1]:8443` (macOS resolves `*.localhost` → `::1`), and a
fully real `RuntimeCoordinator` (real sqlite via `migrate`/`open_connection`/`initialize_cache_db`,
private-mode `NetworkPolicy` trusting only the probe CA, real `OutboundTransport`). Three
well-known documents with real Ed25519 root keys and real root signatures:
`bad.localhost` (wrong-length 16-byte `operational_public_key`), `bad2.localhost`
(well-formed cert signed by a forger root), `good.localhost` (fully valid).

Probe: `.venv/bin/python /tmp/c1_probe/probe.py` (run twice per state — once against the
pre-fix code, byte-identical restored afterwards via hash check; probe script and all fixtures
in /tmp deleted after). All runs bounded by `timeout 120`. Port-carrying domains
(`bad.localhost:8443`) reach the unprivileged-port listener because `resolve_with_ip` does no
domain shape validation — the real code path, zero interposition.

Pre-fix baseline (defects reproduced):
- `resolve_with_ip("bad.localhost:8443")` → **LEAKED ValueError: "An Ed25519 public key is 32
  bytes long"**; `resolve_with_ip("bad2.localhost:8443")` → **LEAKED SignatureError: "signature
  verification failed"**.
- `_resolve_pending_senders` → **batch ABORTED by leaked ValueError** at the first sorted
  hostile domain; `good.localhost:8443` **NOT pinned — cold-sender admission still denied**.
- Poison domains (`'not a domain'`, `'spaced bad.example'`, `'bad:443'`, `''`) all entered the
  queue via `queue_domain_resolution`.

Post-fix (same probe, identical input):
- `resolve_with_ip` on both hostile docs → **ResolutionError: "operational certificate invalid
  for …"**; `pin()` likewise raises `ResolutionError`, not ValueError/SignatureError.
- Poison domains rejected at ingestion (queue stays `[]`); well-shaped `unreachable.example`
  still queues.
- `_resolve_pending_senders` → **batch COMPLETED (no abort)** past both hostile domains;
  **`good.localhost:8443` pinned, node_id matches: True** (durable sqlite pin verified via
  `get_pin`). The real `TransportError` from the unreachable domain is converted to
  `ResolutionError` inside `resolve_with_ip` and isolated per item (stays queued for retry,
  per existing semantics).
- Hostile cert inputs were exactly the trigger class: remote-controlled well-known JSON with
  valid root signature but malformed / forged operational certificate.

Regression: `timeout 900 .venv/bin/python -m pytest` → **163 passed, 1 skipped** (existing
suite, not authored by me). `ruff check` (repo-configured) on all four files → all checks
passed. `py_compile` clean on all four files.

## Found but not touched

- The sibling executor's `transport.py` fix (parse_url → TransportError) had already landed in
  the working tree before my run; my `except Exception` isolation in `_resolve_pending_senders`
  covers a `TransportError` escaping `resolve_with_ip` regardless, per the NOTE.
- `_resolve_pending_senders`'s docstring claims failure "drops it from the queue", but the
  pre-existing code retains failing domains for retry (503 + Retry-After design). I did not
  change discard semantics — the HOW names isolation + ingestion validation only — but the
  docstring/behavior mismatch is flagged for the orchestrator.
- `lattice/api.py` ~301 and ~346 have the same `except RuntimeError`-only shape but were not
  named in the assignment; `verify_inbound_message` already wraps its failure modes in
  RuntimeError, so no known leak there. Not touched.
