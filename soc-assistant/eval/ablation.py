"""
Per-role model ablation harness.

Referenced by the architecture diagram's legend:
    "Ablation study: Foundation-sec-8B-Reasoning vs Llama 3.3-70B vs GLM-4.5-Air per agent role"

This does NOT change config/models.yaml. Instead, for a fixed evaluation set
of NormalizedAlert fixtures (see data/alerts/), it re-runs a single agent
role with each candidate model from `ablation_candidates` in models.yaml,
holding every other agent's model fixed, and records the metrics needed to
compare candidates for that role (see docs/ARCHITECTURE.md, section 4, for
the full metric list: triage accuracy, ATT&CK technique F1, calibration
error, latency, and cost).

This is intentionally a thin harness — it does not implement the metric
calculations itself (those live in their own eval modules once the real
agent logic exists); it only orchestrates "run role X with candidate model Y
against fixture set Z and collect raw outputs for later scoring".
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List
import yaml


@dataclass
class AblationRun:
    agent_role: str
    candidate_model: str
    fixture_id: str
    output: Dict[str, Any] = field(default_factory=dict)
    latency_seconds: float = 0.0
    tool_calls_used: int = 0


def load_ablation_candidates(models_yaml_path: str = "config/models.yaml") -> List[str]:
    with open(models_yaml_path, "r") as f:
        cfg = yaml.safe_load(f)
    return cfg.get("ablation_candidates", [])


def run_role_ablation(
    agent_role: str,
    agent_fn: Callable[[dict, str], dict],
    fixtures: List[dict],
    candidates: List[str] = None,
    models_yaml_path: str = "config/models.yaml",
) -> List[AblationRun]:
    """
    agent_fn: a callable (state, model_id) -> state, i.e. one of the
    agents/*.py entry points adapted to accept an explicit model override
    instead of reading config/models.yaml internally.
    fixtures: list of SOCInvestigationState dicts (or NormalizedAlert dicts,
    depending on the role) to run the ablation over.
    """
    if candidates is None:
        candidates = load_ablation_candidates(models_yaml_path)

    runs: List[AblationRun] = []
    for candidate in candidates:
        for fixture in fixtures:
            output_state = agent_fn(dict(fixture), candidate)
            runs.append(
                AblationRun(
                    agent_role=agent_role,
                    candidate_model=candidate,
                    fixture_id=fixture.get("alert_id", "unknown"),
                    output=output_state,
                )
            )
    return runs
