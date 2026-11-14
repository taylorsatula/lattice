#!/usr/bin/env python3
"""Build verify_verdicts.json for lattice-c1 from the verify workflow journal.

The verify workflow's journal records each agent's returned envelope as a JSON string in `text`.
Primed pass ids are `v-<finding-id>` (e.g. `v-hunt-a1#1`); blind pass ids are `blind-<area>`.

Output: scratch/lattice-c1/verify_verdicts.json
  { "primed": { <finding-id>: {verdict, corrected_tier, refuted_subclaims, added_mechanisms,
                                fix_constraints, report_path} },
    "blind":  [ {pass_id, report_path, verdict, corrected_tier, ..., findings:[...]} ] }

Run:  .venv/bin/python .pi/workflows/gen_verify_verdicts.py [runId]
"""
from __future__ import annotations

import glob
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNIDS = sys.argv[1:] if len(sys.argv) > 1 else ["wf_850a5c320756", "wf_0919fef46fb8"]

matches = []
for rid in RUNIDS:
    g = (
        "/var/folders/*/*/T/pi-subagents-*/*/*/tasks/"
        f"{rid}.workflow.jsonl"
    )
    hits = glob.glob(g)
    if not hits:
        sys.exit(f"no journal found for {rid} at {g}")
    matches.extend(hits)
print("journals:", *matches, sep="\n  ")

recs = []
for journal in matches:
    recs.extend(json.loads(l) for l in open(journal) if l.strip())
primed: dict[str, dict] = {}
blind: list[dict] = []
for r in recs:
    try:
        env = json.loads(r["text"])
    except Exception as e:  # noqa: BLE001
        print("WARN unparsable record", r.get("index"), e)
        continue
    pid = env.get("pass_id", "")
    entry = {
        "verdict": env.get("verdict"),
        "corrected_tier": env.get("corrected_tier"),
        "refuted_subclaims": env.get("refuted_subclaims", ""),
        "added_mechanisms": env.get("added_mechanisms", ""),
        "fix_constraints": env.get("fix_constraints", ""),
        "unreachable": env.get("unreachable", ""),
        "report_path": env.get("report_path", ""),
    }
    if pid.startswith("v-"):
        primed[pid[2:]] = entry
    elif pid.startswith("blind-"):
        entry["pass_id"] = pid
        entry["findings"] = env.get("findings") or []
        blind.append(entry)
    else:
        print("WARN unknown pass id", pid)

out = {"primed": primed, "blind": blind}
dest = ROOT / "scratch" / "lattice-c1" / "verify_verdicts.json"
dest.write_text(json.dumps(out, indent=2))
import collections

vc = collections.Counter(v["verdict"] for v in primed.values())
tc = collections.Counter(v["corrected_tier"] for v in primed.values())
blind_new = sum(len(b["findings"]) for b in blind)
print(f"wrote {dest}")
print(f"primed verdicts: {len(primed)} | {dict(vc)}")
print(f"corrected tiers: {dict(tc)}")
print(f"blind passes: {len(blind)} | new findings from blind: {blind_new}")
