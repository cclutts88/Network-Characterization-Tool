# NCT foundation development

Read and follow `docs/NCT_PROJECT_OPERATING_RULES.md` for the user's project
authorization, reviewer responsibilities, quality-gate states and escalation rules.

Maintain a dedicated, independent, read-only reviewer subagent at meaningful gates.
The primary agent implements; the reviewer checks evidence and can halt affected
downstream work. Review against ROADMAP.md, its deviation log, stable main and
established evidence/provenance semantics. Resolve findings and obtain re-review
before marking the affected roadmap item complete.

Implement → Test → Review → Update Roadmap → Commit → Notify → Continue.
Preserve main and production data. No silent deletion or automatic compaction.
Keep ordinary development on foundation/evidence-engine-v2. Clearly distinguish
development verification from Range or mission acceptance.
