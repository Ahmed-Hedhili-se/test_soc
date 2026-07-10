<<<<<<< HEAD
# SOC Assistant

SOC Assistant is an intelligent, agentic Security Operations Center (SOC) assistant built with LangGraph and LangChain. It automates security alert triage, log investigation, CTI enrichment, MITRE ATT&CK technique mapping, and incident report generation, incorporating a Human-in-the-Loop (HITL) interface for final verification.

## Architecture & Workflows

The assistant orchestrates multiple specialized agent nodes using a LangGraph workflow:
1. **Triage Agent**: Classifies incident severity, category, and false-positive probability using localized LLMs.
2. **Log Investigator**: Queries SIEM systems for correlated logs.
3. **CTI Enrichment**: Enriches investigation with IP reputation data and open-source intelligence.
4. **ATT&CK Mapper**: Maps attacker behaviors to MITRE ATT&CK techniques via vector search (RAG).
5. **Reasoning Synthesis**: Aggregates analysis from parallel investigator agents.
6. **Report Generator**: Formats investigation findings into structural reports.
7. **HITL Interface**: Prompts analysts for feedback and approvals, persisting states to SQLite.

---

## Directory Structure

```text
SOC_Assistant/
├── datasets_/              # [Ignored] Datasets used for testing and training
│   └── data/               # Git submodule/repository containing CSV/JSON data
├── soc-assistant/          # Core Python application
│   ├── agents/             # Agent node implementations (triage, orchestrator)
│   ├── data/               # App database and dynamic logs/alerts
│   │   ├── alerts/         # Stored alerts (gitkeep tracked)
│   │   └── logs/           # Stored session logs (gitkeep tracked)
│   ├── evaluation/         # Quality and response accuracy evaluation metrics
│   ├── hitl/               # Human-in-the-loop interactive interface
│   ├── rag/                # RAG module for MITRE ATT&CK indexing and retrieval
│   ├── state/              # Graph state schemas
│   ├── tools/              # Custom tools (asset inventories, AbuseIPDB/VT APIs, SIEM)
│   └── requirements.txt    # Application dependencies
├── .gitignore              # Project-wide Git ignore rules
└── README.md               # Main project documentation
```

---

## Getting Started

### 1. Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com/) running locally.

### 2. Setup & Installation
1. Clone the repository and navigate to the project directory:
   ```bash
   cd SOC_Assistant
   ```
2. Set up a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r soc-assistant/requirements.txt
   ```

### 3. LLM Configuration
The triage agent is configured to use the `foundation-sec-8b-instruct` model via Ollama. Please make sure the model is pulled and running in your local Ollama environment:
```bash
ollama pull foundation-sec-8b-instruct
```

### 4. Indexing MITRE ATT&CK Dataset
To feed the RAG system with MITRE ATT&CK techniques, run the indexing module:
```python
from rag.indexer import index_attck
index_attck()
```
This fetches the latest Enterprise ATT&CK patterns from MITRE's repository and indexes them into the vector store.
=======
# Agent_SOC_Assistant-
>>>>>>> 569b20b5ece0856f6d3edde5dee8d671b8c71f88
