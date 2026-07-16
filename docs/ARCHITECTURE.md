# Architecture

This document records the target architecture for the Agentic SOC Assistant
and how it maps onto the current code layout. The full evaluation,
bug list, demo roadmap, research improvements, and benchmarking protocol
live in [`report.tex`](./report.tex) / `report.pdf` in this same folder —
this file is the short, living reference; the report is the long-form,
point-in-time writeup for the internship deliverable.

## Pipeline

```
Alert ingestion layer (SIEM, EDR, Firewall, Cloud, Email, Identity)
        |
        v
Orchestrator agent  (LangGraph StateGraph; task routing, priority scoring, failure recovery)
        |
        +----------------+----------------+------------------+
        v                v                v                  v
   Triage agent     Log investigator   CTI enrichment    ATT&CK mapper
  (severity, FP)   (event correlation, (IOC lookup,      (TTP tagging,
                     timeline build)     RAG retrieval)    tactic chain)
        |                |                |                  |
        +----------------+----------------+------------------+
                          v
                Reasoning & synthesis
         (attack chain assembly, confidence scoring,
          escalation policy enforced as code)
                          |
                          v
                  Report generator
           (XAI narrative, evidence chain)
- - - - - - - - - Human-in-the-loop boundary - - - - - - - - -
                          v
              HITL validation interface
     (approve / modify / reject / escalate; the ONLY code
      path allowed to populate `approved_by`)
                          |
        +-----------------+-----------------+
        v                 v                  v
  Incident report   ATT&CK mapping    Remediation proposals
                                     (executed only via MCP
                                      write tools, gated on
                                      `approved_by`)
        |
        v
  Analyst feedback loop -> RAG knowledge base updates
```

## Model allocation

| Agent role         | Primary model                  | Rationale                                    |
|---------------------|---------------------------------|-----------------------------------------------|
| Orchestrator / synthesis | Llama 3.3-70B              | Reasoning-heavy reconciliation across parallel agent outputs |
| Triage              | Foundation-sec-8B-Instruct       | Fast, security-domain-tuned classification |
| Log investigator    | Foundation-sec-8B-Reasoning      | Multi-step correlation over raw log events |
| CTI enrichment      | Llama 3.3-70B + RAG (Tseng pattern) | Retrieval-grounded reasoning over CTI reports |
| ATT&CK mapper       | Foundation-sec-8B-Reasoning      | Structured technique/tactic classification |
| Report generator    | Mistral Small                    | Lightweight, templated natural-language output |

Configured in [`soc-assistant/config/models.yaml`](../soc-assistant/config/models.yaml),
with a documented per-role fallback to a hosted Grok model when the
Foundation-sec / Llama / Mistral checkpoints are not yet self-hosted behind
an OpenAI-compatible endpoint. A per-role ablation set
(`ablation_candidates` in the same file, driven by
[`soc-assistant/eval/ablation.py`](../soc-assistant/eval/ablation.py)) tracks
Foundation-sec-8B-Reasoning vs Llama 3.3-70B vs GLM-4.5-Air as candidates
for each role.

## Safety boundary

Enforced structurally, not just in prompts, at
[`soc-assistant/mcp_tools/write/api.py`](../soc-assistant/mcp_tools/write/api.py):
every write tool (`isolateHost`, `disableUserAccount`, `blockIPFirewall`,
`createTicket`) requires a populated `approved_by` field, which only
[`soc-assistant/hitl/api.py`](../soc-assistant/hitl/api.py)'s decision
endpoint is permitted to set.

See `report.tex` for the full architecture evaluation, known bugs, the
step-by-step path to a running demo, proposed research improvements with
references, and the benchmarking protocol.
