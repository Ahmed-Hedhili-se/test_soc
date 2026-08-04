"""
training/dpo_train.py

Per-role DPO fine-tuning -- the second branch of the analyst continual-
improvement loop (see docs/ARCHITECTURE.md).

Pipeline:
  1. review.feedback.preference_pairs accumulates (prompt, chosen,
     rejected) triples per role as analysts modify/reject agent outputs
     via the HITL endpoint (hitl/api.py).
  2. Once a role has >= min_pairs_per_role recorded pairs (config/dpo.yaml),
     train_role() below fine-tunes that role's base checkpoint with TRL's
     DPOTrainer.
  3. The new checkpoint is scored on a held-out split by its mean implicit
     reward margin (log p(chosen) - log p(rejected)); it is only promoted
     -- written back into config/models.yaml -- if that margin improves on
     the base checkpoint's by at least min_reward_margin_improvement.

Requires the optional torch / transformers / trl / datasets dependencies
(see requirements.txt, "DPO fine-tuning" section). Mirrors the
degrade-gracefully convention used elsewhere in this codebase
(rag/indexer.py, rag/store_attck.py): if those packages, a GPU, or the
base checkpoint aren't available, train_role() returns a DPOTrainResult
explaining why rather than crashing.

This module is invoked manually / on a schedule, never from the live
request path:
    python -m training.dpo_train --role triage
    python -m training.dpo_train              # attempts every role
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

_SOC_ASSISTANT_ROOT = Path(__file__).resolve().parent.parent
if str(_SOC_ASSISTANT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOC_ASSISTANT_ROOT))

from review.feedback.preference_pairs import load_preference_pairs, ROLE_OUTPUT_KEYS  # noqa: E402

_CONFIG_DIR      = _SOC_ASSISTANT_ROOT / "config"
_DEFAULT_MODELS  = _CONFIG_DIR / "models.yaml"
_DEFAULT_DPO_CFG = _CONFIG_DIR / "dpo.yaml"
_PROMOTION_LOG   = _SOC_ASSISTANT_ROOT / "data" / "dpo_promotions.jsonl"

ROLES = sorted(set(ROLE_OUTPUT_KEYS.values()))


def load_dpo_config(path: Path = _DEFAULT_DPO_CFG) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Prompt / completion rendering
# ---------------------------------------------------------------------------

_ROLE_INSTRUCTIONS: dict[str, str] = {
    "triage": (
        "You are the SOC triage agent. Given the alert below, return its "
        "severity, false-positive probability, category and whether the "
        "activity is authorized."
    ),
    "log_investigator": (
        "You are the SOC log investigator agent. Given the alert below, "
        "correlate related events and build a timeline of anomalies."
    ),
    "cti_enrichment": (
        "You are the SOC CTI enrichment agent. Given the alert below, "
        "return IOC reputations and relevant threat-intel context."
    ),
    "attck_mapper": (
        "You are the SOC ATT&CK mapper agent. Given the alert and triage "
        "output below, return the observed MITRE ATT&CK techniques and "
        "tactic chain."
    ),
    "reasoning_synthesis": (
        "You are the SOC reasoning & synthesis agent. Given every "
        "upstream agent's output below, produce a verdict, confidence "
        "score and narrative."
    ),
    "report_generator": (
        "You are the SOC report generator agent. Given the synthesis "
        "output below, produce the formatted incident report."
    ),
}


def render_prompt(role: str, prompt_context: dict) -> str:
    """Render a preference pair's structured prompt_context into the flat
    text prompt the base model would actually have been given."""
    instruction = _ROLE_INSTRUCTIONS.get(role, f"You are the SOC {role} agent.")
    return f"{instruction}\n\nInput:\n{json.dumps(prompt_context, indent=2, default=str)}\n\nOutput:"


def render_completion(output: dict) -> str:
    """Render an agent output dict into the flat text completion a model
    would generate."""
    return json.dumps(output, indent=2, default=str)


# ---------------------------------------------------------------------------
# Dataset assembly
# ---------------------------------------------------------------------------

@dataclass
class RoleDataset:
    role: str
    train: list[dict]
    holdout: list[dict]


def build_role_dataset(role: str, holdout_fraction: float = 0.1) -> Optional[RoleDataset]:
    """
    Load and render all persisted preference pairs for *role* into TRL's
    expected {"prompt", "chosen", "rejected"} text format, split into
    train/holdout. Returns None if no pairs are recorded yet.
    """
    pairs = load_preference_pairs(role)
    if not pairs:
        return None

    examples = [
        {
            "prompt":   render_prompt(role, p["prompt"]),
            "chosen":   render_completion(p["chosen"]),
            "rejected": render_completion(p["rejected"]),
        }
        for p in pairs
    ]

    if len(examples) == 1:
        return RoleDataset(role=role, train=examples, holdout=examples)

    split = max(1, int(len(examples) * (1 - holdout_fraction)))
    split = min(split, len(examples) - 1)  # always leave >=1 example for holdout
    return RoleDataset(role=role, train=examples[:split], holdout=examples[split:])


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

@dataclass
class DPOTrainResult:
    role: str
    checkpoint_path: Optional[str]
    base_reward_margin: float
    trained_reward_margin: float
    promoted: bool
    reason: str


def _mean_reward_margin(model, tokenizer, examples: list[dict], device: str) -> float:
    """
    Mean implicit DPO reward margin -- log p(chosen) - log p(rejected)
    under *model*, summed over completion tokens -- across *examples*.
    Used both to sanity-check a freshly trained checkpoint and as the
    promotion gate.
    """
    import torch

    margins = []
    model.eval()
    with torch.no_grad():
        for ex in examples:
            margin = 0.0
            for key, sign in (("chosen", 1.0), ("rejected", -1.0)):
                full = ex["prompt"] + ex[key]
                prompt_ids = tokenizer(ex["prompt"], return_tensors="pt").input_ids.to(device)
                full_ids   = tokenizer(full, return_tensors="pt").input_ids.to(device)
                completion_len = full_ids.shape[1] - prompt_ids.shape[1]
                if completion_len <= 0:
                    continue
                logits  = model(full_ids).logits[:, :-1, :]
                targets = full_ids[:, 1:]
                logprobs = torch.log_softmax(logits, dim=-1)
                token_logprobs = logprobs.gather(-1, targets.unsqueeze(-1)).squeeze(-1)
                completion_logprob = token_logprobs[:, -completion_len:].sum().item()
                margin += sign * completion_logprob
            margins.append(margin)
    return sum(margins) / len(margins) if margins else 0.0


def train_role(
    role: str,
    dpo_config: Optional[dict] = None,
    models_yaml_path: Path = _DEFAULT_MODELS,
) -> DPOTrainResult:
    """
    Fine-tune *role*'s base checkpoint via DPO on its accumulated
    preference pairs, and promote it into config/models.yaml if it clears
    the eval gate.

    Degrades gracefully -- returns a DPOTrainResult with promoted=False
    and an explanatory `reason` -- when the optional ML dependencies
    aren't installed, there aren't enough pairs yet, the base checkpoint
    can't be loaded, or the held-out reward margin doesn't improve
    enough to promote. Only genuine bugs propagate as exceptions.
    """
    cfg = dpo_config or load_dpo_config()
    min_pairs = cfg.get("min_pairs_per_role", 50)

    dataset = build_role_dataset(role, cfg.get("eval_holdout_fraction", 0.1))
    have = len(dataset.train) if dataset else 0
    if dataset is None or have < min_pairs:
        return DPOTrainResult(
            role, None, 0.0, 0.0, False,
            f"Not enough preference pairs yet ({have}/{min_pairs}); skipping training."
        )

    try:
        import torch
        from datasets import Dataset
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from trl import DPOConfig, DPOTrainer
    except ImportError as e:
        return DPOTrainResult(
            role, None, 0.0, 0.0, False,
            f"DPO training dependencies not installed ({e}); install "
            "torch/transformers/trl/datasets (see requirements.txt) to run this."
        )

    base_checkpoint = cfg["base_checkpoints"][role]
    device = "cuda" if torch.cuda.is_available() else "cpu"

    try:
        tokenizer = AutoTokenizer.from_pretrained(base_checkpoint)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(base_checkpoint).to(device)
    except Exception as e:
        return DPOTrainResult(
            role, None, 0.0, 0.0, False,
            f"Could not load base checkpoint '{base_checkpoint}' ({type(e).__name__}: {e})."
        )

    base_margin = _mean_reward_margin(model, tokenizer, dataset.holdout, device)

    output_dir = (
        Path(cfg.get("checkpoint_output_dir", "./training/checkpoints"))
        / role
        / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    trainer_kwargs = dict(
        model=model,
        args=DPOConfig(
            output_dir=str(output_dir),
            beta=cfg.get("beta", 0.1),
            learning_rate=cfg.get("learning_rate", 5e-6),
            num_train_epochs=cfg.get("num_train_epochs", 1),
            per_device_train_batch_size=cfg.get("per_device_train_batch_size", 2),
            gradient_accumulation_steps=cfg.get("gradient_accumulation_steps", 4),
            max_prompt_length=cfg.get("max_prompt_length", 1024),
            max_length=cfg.get("max_length", 2048),
            report_to=[],
        ),
        train_dataset=Dataset.from_list(dataset.train),
    )
    try:
        trainer = DPOTrainer(**trainer_kwargs, processing_class=tokenizer)
    except TypeError:
        # Older trl versions take `tokenizer=` instead of `processing_class=`.
        trainer = DPOTrainer(**trainer_kwargs, tokenizer=tokenizer)

    trainer.train()
    trainer.save_model(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    trained_margin = _mean_reward_margin(trainer.model, tokenizer, dataset.holdout, device)

    min_improvement = cfg.get("min_reward_margin_improvement", 0.0)
    improvement = trained_margin - base_margin
    promoted = improvement >= min_improvement
    reason = (
        f"Held-out reward margin improved by {improvement:.4f} "
        f"(>= required {min_improvement}); promoted."
        if promoted else
        f"Held-out reward margin only improved by {improvement:.4f} "
        f"(< required {min_improvement}); NOT promoted."
    )

    result = DPOTrainResult(role, str(output_dir), base_margin, trained_margin, promoted, reason)
    _log_promotion_decision(result)
    if promoted:
        promote_checkpoint(role, str(output_dir), models_yaml_path)
    return result


# ---------------------------------------------------------------------------
# Promotion
# ---------------------------------------------------------------------------

def promote_checkpoint(role: str, checkpoint_path: str, models_yaml_path: Path = _DEFAULT_MODELS) -> None:
    """
    Record *checkpoint_path* as the promoted DPO checkpoint for *role* in
    config/models.yaml, under a `dpo_checkpoint` key alongside the
    existing serving `provider` / `endpoint`. Actually pointing the
    serving endpoint at this checkpoint is a separate, explicit ops step
    -- this function only records that promotion happened.
    """
    path = Path(models_yaml_path)
    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    cfg.setdefault(role, {})["dpo_checkpoint"]    = checkpoint_path
    cfg[role]["dpo_promoted_at"] = datetime.now(timezone.utc).isoformat()

    with open(path, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)


def _log_promotion_decision(result: DPOTrainResult) -> None:
    _PROMOTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "role":                  result.role,
        "checkpoint_path":       result.checkpoint_path,
        "base_reward_margin":    result.base_reward_margin,
        "trained_reward_margin": result.trained_reward_margin,
        "promoted":              result.promoted,
        "reason":                result.reason,
        "logged_at":             datetime.now(timezone.utc).isoformat(),
    }
    with open(_PROMOTION_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the DPO fine-tuning loop for one or all agent roles.")
    parser.add_argument("--role", choices=ROLES, default=None,
                         help="Role to train. Omit to attempt every role.")
    args = parser.parse_args()

    for role in ([args.role] if args.role else ROLES):
        result = train_role(role)
        print(f"[{role}] {result.reason}")


if __name__ == "__main__":
    main()
