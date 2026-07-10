# Agentic SOC Assistant

An intelligent, multi-agent Security Operations Center (SOC) assistant built with **LangGraph** and the **Model Context Protocol (MCP)**. It automates security alert triage, log investigation, CTI enrichment, MITRE ATT&CK technique mapping, and incident report generation, incorporating a strict Human-in-the-Loop (HITL) boundary for any real-world remediation.

## Design Philosophy

**Human-in-the-loop augmentation, not autonomy.** 
Agents collect evidence, correlate logs, enrich with CTI, map to MITRE ATT&CK, and draft reports. **No agent may take an action that changes the real environment.** All remediation actions require explicit analyst approval, enforced structurally at the MCP tool layer.

## Architecture & Workflows

The assistant orchestrates multiple specialized agent nodes using a LangGraph `StateGraph`:
1. **Triage Agent**: Classifies incident severity, category, and false-positive probability.
2. **Log Investigator**: Queries SIEM systems for correlated logs and builds timelines.
3. **CTI Enrichment**: Enriches investigation with IP reputation data and open-source intelligence.
4. **ATT&CK Mapper**: Maps attacker behaviors to MITRE ATT&CK techniques via hybrid vector search (RAG).
5. **Reasoning Synthesis**: Reconciles contradictory signals and aggregates analysis from parallel investigator agents.
6. **Report Generator**: Formats investigation findings into structured reports.

### Advanced Orchestrator Capabilities
- **Conditional Routing**: Identity-only alerts skip log investigation; endpoint telemetry alerts trigger parallel log and CTI enrichment branches.
- **Failure Recovery**: Agent nodes are wrapped with automatic retries to ensure pipeline stability.
- **Fast-path Mode**: Critical severity (>= 9.0) and high-confidence (>= 0.90) alerts trigger immediate preliminary side-channel notifications.
- **Budget Enforcement**: MCP tool calls are capped per agent role to prevent runaway LLM execution.

---

## Directory Structure

```text
SOC_Assistant/
├── datasets_/              # [Ignored] External datasets
├── soc-assistant/          # Core Python application
│   ├── agents/             # Agent node implementations (triage, log_investigator, etc.)
│   ├── config/             # YAML configurations (models, tool_budgets, thresholds)
│   ├── eval/               # Evaluation hooks for override rate tracking
│   ├── hitl/               # Human-in-the-loop FastAPI backend endpoints
│   ├── mcp_tools/          # MCP safety boundary (read_only, rag, write with approval gates)
│   ├── models/             # Pydantic models for agent outputs
│   ├── orchestrator/       # LangGraph StateGraph definitions
│   ├── rag/                # 4-Store RAG Knowledge Base (ATT&CK, CTI, IOCs, Org KB)
│   ├── review/             # Feedback loop for analyst corrections
│   ├── schemas/            # Pydantic schemas (NormalizedAlert, agent I/O)
│   ├── state/              # Graph state schema (SOCInvestigationState)
│   └── requirements.txt    # Application dependencies
├── .gitignore              # Project-wide Git ignore rules
└── README.md               # Main project documentation
```

---

## Getting Started

### 1. Prerequisites
- Python 3.11+
- API-hosted LLMs. The project configuration defaults to `grok-4-fast` (per `config/models.yaml`), but can easily be pointed to an OpenAI-compatible vLLM endpoint hosting Foundation-sec-8B.

### 2. Setup & Installation
1. Clone the repository and navigate to the project directory:
   ```bash
   cd SOC_Assistant
   ```
2. Set up a virtual environment:
   ```bash
   python -m venv .venv
   # On Windows use: .venv\Scripts\activate
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r soc-assistant/requirements.txt
   ```

### 3. Configuration
Adjust the YAML configurations in `soc-assistant/config/` to set your model providers, endpoints, tool budgets, and fast-path escalation thresholds.

### 4. Running the Application
The primary entry points are the LangGraph orchestrator (`soc-assistant/orchestrator/graph.py`) and the FastAPI HITL backend (`soc-assistant/hitl/api.py`).
