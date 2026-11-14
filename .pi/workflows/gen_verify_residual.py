#!/usr/bin/env python3
"""Generate the RESIDUAL verify wave for lattice-c1 — only the passes that never returned.

Reads the verify script (for PREAMBLE + TASKS) and the verify journal (for returned pass ids),
filters TASKS to the missing ones, and emits `.pi/workflows/lattice-c1-verify-residual.js`.

Key difference from the original verify script: ONE flat parallel() over all tasks. No inter-phase
barrier, so a single hung agent cannot block the rest from starting.

Run:  .venv/bin/python .pi/workflows/gen_verify_residual.py
"""
from __future__ import annotations

import glob
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFY_JS = ROOT / ".pi" / "workflows" / "lattice-c1-verify.js"
OUT = ROOT / ".pi" / "workflows" / "lattice-c1-verify-residual.js"
RUNID = "wf_850a5c320756"

js = VERIFY_JS.read_text()
preamble = json.loads(re.search(r"const PREAMBLE = (\".*?\");\n", js, re.S).group(1))
tasks = json.loads(re.search(r"const TASKS = (\[.*?\]);\n", js, re.S).group(1))

journals = glob.glob(f"/var/folders/*/*/T/pi-subagents-*/*/*/tasks/{RUNID}.workflow.jsonl")
if not journals:
    sys.exit("no journal")
returned = set()
for line in open(journals[0]):
    rec = json.loads(line)
    try:
        returned.add(json.loads(rec["text"])["pass_id"])
    except Exception:  # noqa: BLE001
        pass

missing = [t for t in tasks if t["pass_id"] not in returned]
if not missing:
    sys.exit("nothing missing")

body = r'''export const meta = {
  name: 'lattice-c1-verify-residual',
  description: 'lattice-c1 Phase 4 residual — only passes that never returned (flat, no barrier)',
  phases: [{ title: 'Residual' }],
}
const PREAMBLE = __PREAMBLE__;
const TASKS = __TASKS__;
const SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['pass_id','report_path','verdict','corrected_tier','refuted_subclaims','added_mechanisms','fix_constraints','unreachable'],
  properties: {
    pass_id: { type: 'string' }, report_path: { type: 'string' },
    verdict: { enum: ['CONFIRMED','REFUTED','ADJUSTED'] },
    corrected_tier: { enum: ['H','M','L','S-'] },
    refuted_subclaims: { type: 'string' }, added_mechanisms: { type: 'string' },
    fix_constraints: { type: 'string' }, unreachable: { type: 'string' },
    findings: { type: 'array', items: { type: 'object', additionalProperties: false,
      required: ['id','tier','title'], properties: { id:{type:'string'}, tier:{enum:['H','M','L','S-']}, title:{type:'string'} } } }
  }
};
if (!PREAMBLE.includes('SEVERITY SCALE (pinned)')) throw new Error('preamble marker missing');
if (!Array.isArray(TASKS) || TASKS.length === 0) throw new Error('task list bad');
function promptFor(t) {
  const head = PREAMBLE + '\n\n=== END PREAMBLE ===\n\n';
  const out = 'Report path (write here and only here): scratch/lattice-c1/reports/' + t.pass_id + '.md\n';
  if (t.kind === 'primed') {
    return head + 'ASSIGNMENT ' + t.pass_id + ' — PRIMED VERIFIER.\n' + out
      + 'Pass type: PRIMED VERIFIER. Adversarial and symmetric. Do not assume the claim is correct or incorrect.\n\n'
      + 'CLAIM UNDER TEST: finding id ' + t.finding_id + ' in report ' + t.report_path + ' (reported tier ' + t.tier + '). Read that finding from the report file.\n\n'
      + 'Method: FIRST re-derive the frame from source. Trace the named runtime path to the actual failure site. Confirm or refute EACH component (mechanism / trigger / frequency); name any refuted half. Correct severity and frequency with the trace. Record added mechanisms, earlier failure sites, new reachability, fix-direction constraints. State the reachability kind (production / tests-only / gated-behind-<id>). Record what you could not reach as a boundary.\n\n'
      + 'IMPORTANT: if you run a live probe, bound it with `timeout`, and KILL any process or server you start before returning. Do not leave orphans.\n\n'
      + 'Return the StructuredOutput envelope: pass_id, report_path, verdict, corrected_tier, refuted_subclaims, added_mechanisms, fix_constraints, unreachable, findings.';
  }
  return head + 'ASSIGNMENT ' + t.pass_id + ' — BLIND THIRD PASS.\n' + out
    + 'Pass type: blind hunter (target withheld). You are NOT told what is claimed.\n\n'
    + 'Read end to end:\n' + t.files + '\n\n'
    + 'Neutral question: ' + t.question + '\n\n'
    + 'Null result is acceptable and expected — do not manufacture findings. State the reachability kind of every finding. If you run a live probe, bound it with `timeout` and kill anything you start.\n\n'
    + 'Return the StructuredOutput envelope: pass_id, report_path, verdict, corrected_tier, refuted_subclaims, added_mechanisms, fix_constraints, unreachable, findings = inventory [{id,tier,title}].';
}
phase('Residual');
const results = await parallel(TASKS.map(function (t) {
  return function () { return agent(promptFor(t), { label: 'resid:' + t.pass_id, phase: 'Residual', agentType: 'swarm-verifier', schema: SCHEMA }); };
}));
const ok = results.filter(Boolean);
log('residual wave: ' + ok.length + '/' + TASKS.length + ' returned');
return { dispatched: TASKS.length, returned: ok.length, envelopes: ok };
'''
body = body.replace("__PREAMBLE__", json.dumps(preamble)).replace("__TASKS__", json.dumps(missing))
OUT.write_text(body)
print(f"wrote {OUT} ({len(body)} bytes)")
print(f"residual tasks: {len(missing)} -> {', '.join(t['pass_id'] for t in missing)}")
