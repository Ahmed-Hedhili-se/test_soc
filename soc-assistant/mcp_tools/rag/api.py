"""
mcp_tools/rag/api.py

RAG retrieval tools backed by Chroma vector stores.
Falls back to a built-in lookup table when the stores are not yet indexed
or unavailable (offline, no embedding backend, etc).
"""
from __future__ import annotations

from typing import Optional

# Built-in fallback: category / keyword -> technique mapping
_CATEGORY_TO_TECHNIQUES: dict[str, list[dict]] = {
    "impossible_travel": [
        {"id": "T1078",     "name": "Valid Accounts",             "tactic": "initial-access",    "confidence": 0.90},
        {"id": "T1078.004", "name": "Valid Accounts: Cloud",      "tactic": "defense-evasion",   "confidence": 0.75},
        {"id": "T1110",     "name": "Brute Force",                "tactic": "credential-access", "confidence": 0.55},
    ],
    "malware": [
        {"id": "T1566.001", "name": "Phishing: Spear",            "tactic": "initial-access",    "confidence": 0.85},
        {"id": "T1059.001", "name": "PowerShell",                 "tactic": "execution",         "confidence": 0.90},
        {"id": "T1055",     "name": "Process Injection",          "tactic": "defense-evasion",   "confidence": 0.70},
        {"id": "T1547.001", "name": "Registry Run Keys",          "tactic": "persistence",       "confidence": 0.65},
    ],
    "lateral_movement": [
        {"id": "T1550.002", "name": "Pass the Hash",              "tactic": "lateral-movement",  "confidence": 0.88},
        {"id": "T1021.002", "name": "SMB/Windows Admin Shares",   "tactic": "lateral-movement",  "confidence": 0.80},
        {"id": "T1003.001", "name": "LSASS Memory",               "tactic": "credential-access", "confidence": 0.75},
    ],
    "data_exfiltration": [
        {"id": "T1567.002", "name": "Exfiltration to Cloud",      "tactic": "exfiltration",      "confidence": 0.85},
        {"id": "T1048",     "name": "Exfiltration Over Alt Proto", "tactic": "exfiltration",      "confidence": 0.70},
        {"id": "T1041",     "name": "Exfiltration Over C2",       "tactic": "exfiltration",      "confidence": 0.60},
    ],
    "privilege_escalation": [
        {"id": "T1068",     "name": "Exploitation for Privilege", "tactic": "privilege-escalation", "confidence": 0.80},
        {"id": "T1134",     "name": "Access Token Manipulation",  "tactic": "privilege-escalation", "confidence": 0.70},
    ],
}

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "exfiltration", "impact",
]


def retrieveCTIContext(category: Optional[str], keywords: Optional[list[str]] = None) -> list[dict]:
    """
    Retrieve CTI report summaries relevant to *category*.
    First tries Chroma (via the lazy get_cti_store() getter -- see
    rag/store_cti_reports.py); falls back to the built-in table if the
    store isn't available or returns nothing.
    """
    try:
        from rag.store_cti_reports import get_cti_store
        cti_store = get_cti_store()
        query = f"{category or ''} {' '.join(keywords or [])}".strip()
        if query:
            docs = cti_store.similarity_search(query, k=3)
            if docs:
                return [{"content": d.page_content, "metadata": d.metadata} for d in docs]
    except Exception:
        pass

    # Fallback
    techniques = _CATEGORY_TO_TECHNIQUES.get(category or "", [])
    return [{
        "content": f"Known {category} techniques: {', '.join(t['id'] for t in techniques)}",
        "metadata": {"source": "builtin_fallback", "category": category},
    }]


def getTechniqueDetail(technique_id: str) -> dict:
    """
    Return detail for a MITRE ATT&CK technique.
    First tries the ATT&CK Chroma store (via get_attck_store()); falls
    back to the built-in table.
    """
    try:
        from rag.store_attck import get_attck_store
        attck_store = get_attck_store()
        docs = attck_store.similarity_search(technique_id, k=1)
        if docs:
            return {"id": technique_id, "content": docs[0].page_content,
                    "metadata": docs[0].metadata}
    except Exception:
        pass

    # Flat search across all categories
    for techniques in _CATEGORY_TO_TECHNIQUES.values():
        for t in techniques:
            if t["id"] == technique_id:
                return {
                    "id": technique_id,
                    "name": t["name"],
                    "tactic": t["tactic"],
                    "content": f"{technique_id} -- {t['name']} (tactic: {t['tactic']})",
                    "metadata": {"source": "builtin_fallback"},
                }
    return {"id": technique_id, "content": "Unknown technique", "metadata": {}}


def buildTacticChain(technique_ids: list[str]) -> list[str]:
    """
    Given a list of technique IDs, return the ordered tactic chain
    (sorted by standard ATT&CK tactic order).
    """
    tactic_set: set[str] = set()
    for cat_techniques in _CATEGORY_TO_TECHNIQUES.values():
        for t in cat_techniques:
            if t["id"] in technique_ids:
                tactic_set.add(t["tactic"])

    return [tac for tac in _TACTIC_ORDER if tac in tactic_set]
