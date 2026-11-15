# Documentation Guide for Agents

**These are the v1-era documents. They are historical reference, not normative.**
The normative documents for the current implementation are at the repository
root: `V2_DESIGN.md` (design rationale and threat model), `V2_SPEC.md` (wire
format and protocol rules), and `V2_PLAN.md` (implementation plan and phase
gates). Where a v1 document here and a V2 document disagree, the V2 document
wins. Do not "fix" these files to match the v2 implementation; they describe
the retired Python build and are kept for archaeology only.

## What is here

| Document | What it was | Status |
|----------|-------------|--------|
| `PROTOCOL.md` | v1 wire protocol, schemas, routes, error format | Superseded by `V2_SPEC.md` |
| `THREAT_MODEL.md` | v1 threat model | Superseded by `V2_DESIGN.md` |
| `ADDRESSING.md` | v1 addressing and contact cards | Historical; v2 has no names on the wire (identifiers only) |
| `KEY_MANAGEMENT.md` | v1 key lifecycle | Historical; v2 rotation is pre-committed (`V2_SPEC.md`) |
| `MIGRATIONS.md` | v1 storage migration policy | Historical; v2 storage is redb, no migrations yet |
| `OPERATIONS.md` | v1 deployment (systemd, Nginx) | Historical; see `deploy/` and `README.md` for the v2 unit |
| `INTEGRATION.md` | v1 webhook contract | Historical |
| `ARCHITECTURE.md` | v1 architecture overview | Historical |
| `LATTICE_SYSTEMD.md` | v1 systemd notes | Historical; see `deploy/latticed.service` |
| `LOOSE_ENDS.md` | v1 open items | Historical |
| `adr/` | v1 architecture decision records | Historical; v2 decisions live in `V2_DESIGN.md` |

## Rules

- Read these only to understand v1 behavior or to answer "why was X removed?"
  (then check `V1_DESIGN_INVENTORY.md` and `git log` under `old/`).
- Do not cite these documents as authority for v2 behavior. Cite the V2
  documents instead.
- Do not edit these files to match v2; they are a frozen record.
