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
      path allowed to populate `approved_by`. FastAPI app
      also serves the analyst dashboard at GET /ui, with
      `/` redirecting there -- no separate frontend server.)
                          |
        +-----------------+-----------------+
        v                 v                  v
  Incident report   ATT&CK mapping    Remediation proposals
                                     (executed only via MCP
                                      write tools, gated on
                                      `approved_by`)
        |
        v
  Analyst feedback loop  (hitl/api.py POST /decision, action=modify|reject)
        |
        +----------------------------+----------------------------------+
        v                                                                v
  RAG knowledge base updates                                DPO preference-pair capture
  (review/feedback/rag_update.py;                           (review/feedback/preference_pairs.py;
   appends to data/feedback_log.jsonl;                        one (prompt, chosen, rejected) pair
   document-corpus refresh is a                                per corrected agent role, written to
   documented future step, not yet                             data/dpo_pairs/<role>.jsonl)
   live re-embedding into Chroma)                                       |
                                                                          v
                                                            training/dpo_train.py (offline, scheduled)
                                                            per-role DPOTrainer once a role has
                                                            >= min_pairs_per_role (config/dpo.yaml);
                                                            promotion into config/models.yaml is
                                                            gated on held-out reward-margin improvement
```

### Agents call a real LLM

Every agent node ([agents/*.py](../soc-assistant/agents/)) calls the
model configured for its role via
[`config/provider.py`](../soc-assistant/config/provider.py)`.get_provider(role)`
-- `triage`, `log_investigator`, `reasoning_synthesis`, and
`report_generator` send a role-specific system prompt plus pre-fetched
MCP-tool context and parse a structured JSON completion back into that
role's output schema (`schemas/agent_io.py` / `models/synthesis.py`).
`get_provider()` health-checks the role's primary endpoint, falls back to
its `fallback` block on failure, and enforces a privacy guard:
`log_investigator` and `reasoning_synthesis` refuse to fall back to a
non-local provider (see `PrivacyConstraintViolation`) since they handle
raw internal log data.

Set `SOC_ASSISTANT_MOCK_LLM=1` to skip the network entirely and get a
deterministic per-role completion instead -- used by the test suite / CI
/ offline demos, the same convention as `SOC_ASSISTANT_MOCK_EMBEDDINGS`.

### RAG knowledge base <-> agent connections

`cti_enrichment` and `attck_mapper` additionally pre-fetch deterministic
context from the RAG knowledge base via the MCP tool surface in
[`soc-assistant/mcp_tools/rag/api.py`](../soc-assistant/mcp_tools/rag/api.py)
and feed it into their LLM prompt. If the model's parsed response omits a
field (including under `SOC_ASSISTANT_MOCK_LLM=1`), the RAG/MCP-derived
value is used directly instead -- via `parsed.get(...) or <fallback>` --
so these two agents always return something useful even with no live
model behind them:

- `cti_enrichment` ([agents/cti_enrichment.py](../soc-assistant/agents/cti_enrichment.py))
  looks up `source_ip` / `dest_ip` (and any IPs/hashes found in the raw
  log text) via `lookupIP` / `lookupHash` (read-only MCP tools), discounts
  confidence for infrastructure recorded as `shared` in the IOC store
  ([rag/store_ioc.py](../soc-assistant/rag/store_ioc.py)), and retrieves
  CTI report context via `retrieveCTIContext` (Chroma, falling back to a
  built-in table).
- `attck_mapper` ([agents/attck_mapper.py](../soc-assistant/agents/attck_mapper.py))
  resolves candidate techniques for the alert category via
  `techniquesForCategory`, runs a supplementary semantic search over the
  raw log text against the ATT&CK Chroma store, enriches each candidate
  via `getTechniqueDetail`, and derives `observed_tactics` /
  `kill_chain_position` / `predicted_next` via `buildTacticChain`,
  `killChainPosition`, `predictNextTactics`.
- Both agents deliberately key off `alert_raw` / `alert_category` /
  `triage_output` only -- never `log_output` / the other's output --
  since `log_investigator`, `cti_enrichment`, and `attck_mapper` run in
  the same parallel LangGraph superstep (see `agents/log_investigator.py`
  for why returning a sibling's output there would break the graph).

### Continual improvement: two loops, not one

A `modify`/`reject` HITL decision drives two independent loops that share
a trigger but not a destination:

1. **RAG corpus refresh** (`review/feedback/rag_update.py`) -- cheap,
   near-real-time, append-only. Currently logs corrections to
   `data/feedback_log.jsonl`; live re-embedding into the Chroma stores is
   documented as a future step, not yet implemented.
2. **DPO preference-pair capture** (`review/feedback/preference_pairs.py`)
   -- for each agent role whose output slot actually changed between the
   pre- and post-decision state, records a `(prompt, chosen, rejected)`
   triple to `data/dpo_pairs/<role>.jsonl`. A bare `reject` with no
   replacement value produces no pair (there's no "chosen" completion to
   record). `training/dpo_train.py` consumes these offline, on a
   schedule -- never from the live request path -- to DPO fine-tune a
   role's base checkpoint (per-role config in `config/dpo.yaml`), and
   only promotes (writes back into `config/models.yaml`) a checkpoint
   whose held-out implicit reward margin clears the configured gate.

The two loops are separate because they target different things: RAG
retrieval is a document corpus, unaffected by model weights; DPO changes
a role's model weights and needs a training pipeline + eval gate that a
cheap JSONL append does not.

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
an OpenAI-compatible endpoint.

**Current deployment collapses the above to a single self-hosted Ollama
model (`gpt-oss:20b`) for every role** -- running 4+ distinct checkpoints
hit GPU OOM in practice (see `deploy/setup_vllm_server.sh` for the
alternative per-role vLLM path, kept for when that's viable again).
Splitting roles back out to distinct models is just pointing each role's
`endpoint` / `model_id` in `models.yaml` at a different server; no code
assumes they're the same model.

A per-role ablation set (`ablation_candidates` in the same file, driven by
[`soc-assistant/eval/ablation.py`](../soc-assistant/eval/ablation.py)) tracks
Foundation-sec-8B-Reasoning vs Llama 3.3-70B vs GLM-4.5-Air as candidates
for each role.

Training-time config for the DPO continual-improvement loop (base
checkpoint per role, pair thresholds, promotion gate) is kept separate,
in [`soc-assistant/config/dpo.yaml`](../soc-assistant/config/dpo.yaml) --
`models.yaml` stays purely about serving (which endpoint answers for a
role right now); a promoted DPO checkpoint is recorded there as
`dpo_checkpoint` but pointing the live endpoint at it is a separate,
explicit ops step (see "Continual improvement" above).

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
