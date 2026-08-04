"""
config/provider.py

LLM provider resolution per agent role, reading config/models.yaml.

Each role maps to a primary `openai_compatible` (self-hosted) endpoint and
an optional `fallback` block (typically a hosted Grok model) -- see the
header comment in config/models.yaml for the two deployment paths this
supports.

Privacy guard: log_investigator and reasoning_synthesis handle raw
internal log data and must never be routed to a non-local provider, even
via fallback -- if their local endpoint is unreachable, get_provider()
raises PrivacyConstraintViolation rather than silently falling back to a
hosted API.

Set SOC_ASSISTANT_MOCK_LLM=1 to skip the network entirely and get a
deterministic, empty-but-valid completion per role -- used by the test
suite / CI / offline demos, the same convention as
SOC_ASSISTANT_MOCK_EMBEDDINGS in rag/store_attck.py. Agents are written to
fall back to their own RAG/MCP-tool-derived defaults whenever the parsed
LLM response is empty (via `parsed.get(...) or <fallback>`), so mock mode
still exercises real agent logic end to end -- just without a real model's
judgment layered on top.
"""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import requests
import yaml
from requests.exceptions import RequestException


class PrivacyConstraintViolation(Exception):
    """Raised when a privacy-sensitive agent role would be routed to a non-local provider."""


_LOCAL_ONLY_ROLES = {"log_investigator", "reasoning_synthesis"}

_MOCK_RESPONSES: dict[str, str] = {
    "triage":              '{"severity": 5.0, "fp_probability": 0.5, "authorized_activity": false}',
    "log_investigator":    '{"events": [], "entities": {"ips": [], "users": [], "processes": []}, "timeline": [], "anomalies": []}',
    "cti_enrichment":      '{"indicators": [], "cti_confidence": 0.0, "threat_summary": ""}',
    "attck_mapper":        '{"technique_ids": [], "kill_chain_position": 0, "observed_tactics": [], "predicted_next": []}',
    "reasoning_synthesis": '{"verdict": "needs_investigation", "confidence": 0.5, "narrative": "", "remediation_required": false, "missing_evidence": []}',
    "report_generator":    '{"executive_summary": "", "evidence_chain": {}, "attck_technique_cards": [], "remediation_proposals": []}',
}


class _MockChatModel:
    """Deterministic stand-in for ChatOpenAI -- see module docstring."""

    def __init__(self, role: str):
        self._role = role

    def invoke(self, messages) -> SimpleNamespace:
        return SimpleNamespace(content=_MOCK_RESPONSES.get(self._role, "{}"))


def load_models_config(path: Optional[Path] = None) -> dict:
    config_path = path or Path(__file__).parent / "models.yaml"
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def _health_check(endpoint: str) -> None:
    response = requests.get(f"{endpoint}/models", timeout=5)
    response.raise_for_status()


def _build_client(provider_name: str, endpoint: str, model_id: str):
    from langchain_openai import ChatOpenAI

    api_key = os.environ.get("GROK_API_KEY", "") if provider_name == "grok" else "not-needed"
    return ChatOpenAI(model=model_id, api_key=api_key, base_url=endpoint, max_retries=3)


def get_provider(role: str):
    """
    Resolve the chat model for *role* per config/models.yaml: health-check
    the primary endpoint, fall back to the role's `fallback` block if the
    primary is unreachable, and enforce the local-only privacy guard for
    log_investigator / reasoning_synthesis regardless of which block ends
    up being selected.
    """
    if os.environ.get("SOC_ASSISTANT_MOCK_LLM") == "1":
        return _MockChatModel(role)

    config = load_models_config()
    if role not in config:
        raise ValueError(f"No configuration found for agent role: {role}")
    role_cfg = config[role]

    provider_name = role_cfg["provider"]
    endpoint      = role_cfg["endpoint"]
    model_id      = role_cfg["model_id"]

    try:
        _health_check(endpoint)
    except RequestException as e:
        fallback = role_cfg.get("fallback")
        if not fallback:
            raise RuntimeError(f"Startup health check failed for role '{role}' at {endpoint}: {e}")
        provider_name, endpoint, model_id = fallback["provider"], fallback["endpoint"], fallback["model_id"]

    if role in _LOCAL_ONLY_ROLES and provider_name != "openai_compatible":
        raise PrivacyConstraintViolation(
            f"Agent '{role}' must use a local (openai_compatible) provider due to privacy "
            f"constraints -- refusing to route to '{provider_name}'."
        )

    return _build_client(provider_name, endpoint, model_id)
