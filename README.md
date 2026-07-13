# Agentic SOC Assistant — v2 Implementation Phase

This is the code skeleton implementing **Build Prompt v2 (Corrected)**, resolving the
contradictions found in v1 and executing the reviewed implementation plan. It's a
working, runnable prototype with mocked/seeded data — not a production build.

## Status at a glance

| Area | Status |
|---|---|
| Local/API privacy guard (`config/provider.py`) | ✅ implemented + verified (blocks violation, passes valid config) |
| 6 agent models named in `config/models.yaml` | ✅ done |
| Corrected schemas (`confidence`, `authorized_activity_p`) | ✅ done |
| Corrected LangGraph topology | ✅ implemented + smoke-tested end-to-end |
| Post-Triage routing + severity override | ✅ implemented, **partially tested** (see "Known gaps" below) |
| 4 RAG stores, each with a working query tool | ✅ done (seed/mock data) |
| `createTicket` auto-allow split | ✅ implemented, always audit-logged |
| Automated tests (schema validation, graph topology) | ⬜ **not yet written** — was next on the plan |
| Real ATT&CK STIX / APTnotes / ThreatFox ingestion | ⬜ seed data only, ingestion pipeline not built |
| Real local vLLM / Grok API calls | ⬜ agents run rule-based logic, not actual LLM calls yet |
| HITL FastAPI endpoints | ⬜ not started |

## Why this exists

Three review rounds surfaced real contradictions between the original architecture,
the v1 build prompt, and the implementation plan generated from it — most seriously,
v1 defaulted local-only agents (Log Investigator, ATT&CK Mapper, Reasoning &
Synthesis) to API hosting, silently reversing the project's core data-privacy
constraint. This phase implements the corrected version and proves each fix actually
works in code, not just on paper.

## Repo structure

```
agentic-soc/
  config/
    models.yaml       # model + provider per agent role
    provider.py        # structural guard: refuses local-only role -> API
                        # unless ablation_all_api.enabled: true
  schemas/
    alert.py            # NormalizedAlert
    agent_io.py          # TriageOutput (+confidence, authorized_activity_p),
                          # LogInvestigatorOutput, CTIEnrichmentOutput, ATTCKMapperOutput
    synthesis.py          # SynthesisInput/Output + confidence-escalation policy as code
  agents/
    triage.py              # queries getOrgContext (Store 4) for FP history
    log_investigator.py     # queries getOrgContext (Store 4) for Sigma rules
    cti_enrichment.py        # queries lookupIOC (Store 3), applies exclusivity discount
    attck_mapper.py           # consumes Triage + Log Investigator + CTI Enrichment
    synthesis.py                # reads full shared state, applies escalation policy
    report_generator.py          # runs strictly last; sequential
  orchestrator/
    graph.py                      # LangGraph StateGraph, corrected topology + routing
  mcp_tools/
    read_only/tools.py             # mocked read-only tools (SIEM, process tree, etc.)
    rag/
      store_attck.py                # Store 1 — MITRE ATT&CK (seed data)
      store_cti_reports.py           # Store 2 — CTI reports (seed data)
      store_ioc.py                    # Store 3 — IOC key-value lookup (seed data)
      store_org_kb.py                  # Store 4 — Sigma rules + FP history (seed data)
    write/api.py                       # approval-gated write tools + createTicket split
```

## Pipeline topology (implemented)

```
Triage (always runs first, unconditional)
  -> route_after_triage (post-Triage routing decision)
  -> [Log Investigator || CTI Enrichment]   (parallel, conditionally activated)
-> ATT&CK Mapper        (consumes Triage + Log Investigator + CTI Enrichment)
-> Reasoning & Synthesis (waits for ALL upstream agents, reads full shared state)
-> Report Generator      (runs LAST, always sequential)
```

**Routing logic, as resolved in review:**
- Fast-path (`severity >= 9.0` and `confidence >= 0.90`) is a **side-channel
  notification only** — it never changes routing by itself.
- Identity-only, low-`fp_probability`, no-endpoint-indicator alerts normally skip
  Log Investigator (CTI Enrichment runs alone).
- **Override:** `severity >= 9.0` always forces Log Investigator to run, regardless of
  the skip condition — high severity is itself a signal Triage's skip heuristic may be
  wrong. This override and the fast-path notification are independent of each other.

## Running it

```bash
cd agentic-soc
pip install pydantic pyyaml langgraph --break-system-packages   # or use a venv

# Sanity-check the privacy guard against config/models.yaml
PYTHONPATH=. python3 config/provider.py

# Run one alert through the full graph end-to-end
PYTHONPATH=. python3 orchestrator/graph.py
```

Both have been run and verified during this build:
- `config/provider.py` — confirmed it raises `PrivacyConstraintViolation` when a
  local-only role is pointed at `grok_api` without the ablation flag, and resolves
  correctly when the config is valid.
- `orchestrator/graph.py` — a `brute_force` EDR alert (severity 8.5) was run through
  the full 6-node graph and produced a complete report with a `hitl_approve`
  escalation decision.

## Known gaps — what to do next

1. **Write and run the automated tests from the implementation plan** — schema
   validation tests (`confidence`/`authorized_activity_p` required, fast-path
   condition rejects payloads without `confidence`) and graph-topology tests
   (`attck_mapper` only runs after both `log_investigator` and `cti_enrichment`
   complete). These were scoped in the plan's Verification section but not yet
   written in this phase.
2. **Exercise the routing edge cases explicitly.** The smoke test only covers one
   "both branches run" case. Still needs: an identity-only/low-severity alert
   (confirms the skip actually skips Log Investigator) and an identity-only/high-severity
   alert (confirms the `severity >= 9.0` override forces it to run anyway).
3. **Replace seed data with real ingestion**: ATT&CK STIX bundles (Store 1), APTnotes
   corpus (Store 2), a live IOC feed like ThreatFox/URLhaus behind a real key-value
   store (Store 3, currently a Python dict).
4. **Wire actual model calls.** Every agent currently runs deterministic/rule-based
   logic standing in for the LLM call — `config/provider.py` resolves the right
   model+endpoint per role, but nothing calls it yet. This was intentionally scoped
   as "fully implement the graph logic and schemas, mock the model calls" for this
   phase.
5. **HITL FastAPI backend** (Section 9 of the build prompt) — not started.
6. Confirm the `createTicket` auto-allow policy sign-off (flagged in review, not
   re-confirmed here) before this goes past prototype stage.
