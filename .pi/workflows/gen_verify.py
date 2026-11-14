#!/usr/bin/env python3
"""Generate the Phase 4 verification workflow for lattice-c1.

Reads:
  scratch/lattice-c1/hunt_envelopes.json   (saved from the hunt workflow's return value)
  .pi/workflows/lattice-c1-hunt.js         (for the AREAS file/question list)
  scratch/lattice-c1/preamble.md           (baked byte-verbatim into every prompt)

Writes:
  .pi/workflows/lattice-c1-verify.js

Per Standard tier:
  - one PRIMED verifier per finding (points at the source report + finding id)
  - one BLIND pass per area that produced at least one H finding (target withheld)

Run:  .venv/bin/python .pi/workflows/gen_verify.py
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRATCH = ROOT / "scratch" / "lattice-c1"
HUNT_JS = ROOT / ".pi" / "workflows" / "lattice-c1-hunt.js"
OUT = ROOT / ".pi" / "workflows" / "lattice-c1-verify.js"

preamble = (SCRATCH / "preamble.md").read_text()
hunt_js = HUNT_JS.read_text()
envs = json.loads((SCRATCH / "hunt_envelopes.json").read_text())

m = re.search(r"const AREAS = (\[.*?\]);\n", hunt_js, re.S)
if not m:
    sys.exit("could not extract AREAS from hunt script")
# Pilot areas are not in the full-wave script; add them so H findings from the pilot get a
# blind third pass too.
PILOT_AREAS = {
    "hunt-b1a": {
        "files": "`lattice/runtime.py` — `_RecurringTask`, `_RuntimeScheduler`, `RuntimeCoordinator.__init__`, `_build_scheduler`, `start`, `stop`, `_restore_rate_limits`, `_persist_rate_limits`, `is_ready`, `is_running`, `_write_audit_entry`; `lattice/config.py`; `lattice/__init__.py`.",
        "question": "does the coordinator startup/shutdown/scheduling/readiness lifecycle preserve its own invariants under concurrent operation and restart — executor shutdown ordering, recurring-task cadence arithmetic, the scheduler stop handshake, rate-limit restore/persist ordering and partial failure, readiness gating, audit writes under contention?",
    },
    "hunt-b1b": {
        "files": "`lattice/runtime.py` — `resolve_local_address`, `resolve_destination`, `sign_local_message`, `peer_endpoint_for_node`, `allow_submission`, `_circuit_is_open`, `_circuit_record_success`, `_circuit_record_failure`, `_run_outbound_delivery`, `_send_outbound_message`, `queue_domain_resolution`, `_resolve_pending_senders`; `lattice/messages.py`; `lattice/transport.py`.",
        "question": "does outbound delivery preserve custody, retry, and circuit-breaker invariants — queue claim/release semantics, retry/backoff/expiry arithmetic, custody-transfer handshake validation, circuit threshold/reset, allow_submission↔readiness interaction, local-message signing preimages?",
    },
    "hunt-b1c": {
        "files": "`lattice/runtime.py` — `verify_gossip_sender_card`, `verify_inbound_message`, `_certificate_for_node`, `_domain_for_node`, `_root_identity_for_node`, `_known_root_key_for_node`, `_certificate_from_pin`, `_run_webhook_delivery`, `_run_gossip_round`, `_send_gossip_batch`, `_run_verify_candidates`, `_run_refresh_topology`, `_run_expiry_cleanup`; `lattice/rate_limit.py`; `lattice/webhook.py`; `lattice/api.py` handlers `receive_gossip`/`receive_message`.",
        "question": "does the inbound path enforce sender authenticity, custody, rate limits, and webhook idempotency correctly — verify/block/custody ordering, token-bucket arithmetic and restore, webhook retry classification and idempotency, gossip per-card failure isolation and batch bounds?",
    },
}
areas = {a["pass_id"]: a for a in json.loads(m.group(1))}
areas.update(PILOT_AREAS)

tasks: list[dict] = []
for env in envs:
    pid = env.get("pass_id")
    report = env.get("report_path")
    findings = env.get("findings") or []
    for f in findings:
        tasks.append({
            "kind": "primed",
            "pass_id": "v-" + f["id"],
            "report_path": report,
            "finding_id": f["id"],
            "tier": f.get("tier", "?"),
            "title": f.get("title", ""),
        })
    if any((f.get("tier") == "H") for f in findings) and pid in areas:
        tasks.append({
            "kind": "blind",
            "pass_id": "blind-" + pid,
            "files": areas[pid]["files"],
            "question": areas[pid]["question"],
        })

if not tasks:
    sys.exit("no verification tasks derived (empty envelopes?)")

js = r'''export const meta = {
  name: 'lattice-c1-verify',
  description: 'lattice-c1 Phase 4 verification wave — primed per finding + blind per H area',
  phases: [
    { title: 'Primed', detail: 'one verifier per finding' },
    { title: 'Blind', detail: 'unprimed pass per area with an H survivor' },
  ],
}

const PREAMBLE = __PREAMBLE__;
const TASKS = __TASKS__;

const SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['pass_id','report_path','verdict','corrected_tier','refuted_subclaims','added_mechanisms','fix_constraints','unreachable'],
  properties: {
    pass_id: { type: 'string' },
    report_path: { type: 'string' },
    verdict: { enum: ['CONFIRMED','REFUTED','ADJUSTED'] },
    corrected_tier: { enum: ['H','M','L','S-'] },
    refuted_subclaims: { type: 'string' },
    added_mechanisms: { type: 'string' },
    fix_constraints: { type: 'string' },
    unreachable: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['id','tier','title'],
        properties: { id:{type:'string'}, tier:{enum:['H','M','L','S-']}, title:{type:'string'} }
      }
    }
  }
};

if (!PREAMBLE.includes('SEVERITY SCALE (pinned)')) throw new Error('preamble marker missing');
if (!Array.isArray(TASKS) || TASKS.length === 0) throw new Error('task list bad');

function promptFor(t) {
  const head = PREAMBLE + '\n\n=== END PREAMBLE ===\n\n';
  const out = 'Report path (write here and only here): scratch/lattice-c1/reports/' + t.pass_id + '.md\n';
  if (t.kind === 'primed') {
    return head
      + 'ASSIGNMENT ' + t.pass_id + ' — PRIMED VERIFIER.\n' + out
      + 'Pass type: PRIMED VERIFIER. Adversarial and symmetric — do not assume the claim is correct, do not assume it is incorrect. Two failures are equally fatal: sycophantic confirmation (checking inside the claim frame and inheriting its errors) and reflexive refutation (killing a real finding to look rigorous).\n\n'
      + 'CLAIM UNDER TEST: finding id ' + t.finding_id + ' in report ' + t.report_path + ' (reported tier ' + t.tier + '). Read that finding from the report file.\n\n'
      + 'Method:\n'
      + '- FIRST re-derive the frame from source (what rows the query returns, what the caller passes, what the constant holds). Do not begin from the claim phrasing.\n'
      + '- Trace the named runtime path to its actual failure site. Confirm or refute EACH component: mechanism / trigger / frequency. Name any refuted half.\n'
      + '- Correct severity and frequency with the trace that produced the correction.\n'
      + '- Record additional mechanisms, earlier failure sites, new reachability, and fix-direction constraints.\n'
      + '- State the reachability kind (production / tests-only / gated-behind-<id>).\n'
      + '- Record what you could not reach as a boundary.\n\n'
      + 'Return the StructuredOutput envelope: pass_id, report_path, verdict, corrected_tier, refuted_subclaims, added_mechanisms, fix_constraints, unreachable, findings (empty unless you discovered new ones).';
  }
  return head
    + 'ASSIGNMENT ' + t.pass_id + ' — BLIND THIRD PASS.\n' + out
    + 'Pass type: blind hunter (target withheld). You are NOT told what is claimed.\n\n'
    + 'Read end to end:\n' + t.files + '\n\n'
    + 'Neutral question: ' + t.question + '\n\n'
    + 'Null result is acceptable and expected \u2014 do not manufacture findings. State the reachability kind of every finding.\n\n'
    + 'Return the StructuredOutput envelope: pass_id, report_path, verdict (CONFIRMED if you found at least one defect, else REFUTED), corrected_tier (highest you found, or S-), refuted_subclaims, added_mechanisms, fix_constraints, unreachable, findings = inventory [{id,tier,title}] of what you found.';
}

const primed = TASKS.filter(function (t) { return t.kind === 'primed'; });
const blind = TASKS.filter(function (t) { return t.kind === 'blind'; });

log('verify wave: ' + primed.length + ' primed + ' + blind.length + ' blind');

const r1 = await parallel(primed.map(function (t) {
  return function () { return agent(promptFor(t), { label: 'verify:' + t.pass_id, phase: 'Primed', agentType: 'swarm-verifier', schema: SCHEMA }); };
}));
const r2 = await parallel(blind.map(function (t) {
  return function () { return agent(promptFor(t), { label: 'blind:' + t.pass_id, phase: 'Blind', agentType: 'swarm-verifier', schema: SCHEMA }); };
}));

return {
  primed_dispatched: primed.length, primed_returned: r1.filter(Boolean).length,
  blind_dispatched: blind.length, blind_returned: r2.filter(Boolean).length,
  primed: r1.filter(Boolean), blind: r2.filter(Boolean),
};
'''
js = js.replace("__PREAMBLE__", json.dumps(preamble)).replace("__TASKS__", json.dumps(tasks))
OUT.write_text(js)
print(f"wrote {OUT} ({len(js)} bytes)")
print(f"tasks: {sum(1 for t in tasks if t['kind']=='primed')} primed, {sum(1 for t in tasks if t['kind']=='blind')} blind")
print("primed pass ids:", ", ".join(t["pass_id"] for t in tasks if t["kind"] == "primed")[:300])
