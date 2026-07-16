#!/usr/bin/env python3
"""
run_pipeline.py

Main demo runner for the Agentic SOC Assistant.

Usage:
    .venv\\Scripts\\python run_pipeline.py
    .venv\\Scripts\\python run_pipeline.py --alert-id ALT-2026-002
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure we run from the soc-assistant directory
os.chdir(Path(__file__).parent)
sys.path.insert(0, str(Path(__file__).parent))

# Enable mock embeddings for running to avoid heavy downloads and network dependencies
os.environ["SOC_ASSISTANT_MOCK_EMBEDDINGS"] = "1"


# -- Console helpers ----------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
MAGENTA= "\033[35m"
BLUE   = "\033[34m"

def _c(color: str, text: str) -> str:
    return f"{color}{text}{RESET}"


def _banner(title: str) -> None:
    width = 70
    print()
    print(_c(BLUE, "=" * width))
    print(_c(BOLD + BLUE, f"  {title}"))
    print(_c(BLUE, "=" * width))


def _section(label: str) -> None:
    print()
    print(_c(CYAN, f"  > {label}"))
    print(_c(CYAN, "  " + "-" * 60))


def _kv(key: str, value, indent: int = 4) -> None:
    pad = " " * indent
    print(f"{pad}{_c(BOLD, key + ':')} {value}")


# -- Core runner ----------------------------------------------------------------

def run_alert(graph, alert: dict, thread_id: str) -> dict:
    """Run a single alert through the full pipeline and return final state."""
    initial_state = {
        "alert_id":           alert["alert_id"],
        "alert_raw":          alert,
        "alert_category":     alert["category"],
        "alert_timestamp":    alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "agents_activated":   [],
        "agents_completed":   [],
        "agents_failed":      [],
        "missing_evidence":   [],
        "audit_log":          [],
        "tool_calls_count":   {},
        "confidence_score":   0.0,
        "escalation_flag":    False,
        "pipeline_start_time": datetime.now(timezone.utc).isoformat(),
    }
    config = {"configurable": {"thread_id": thread_id}}
    return graph.invoke(initial_state, config=config)


def print_results(alert: dict, state: dict) -> None:
    """Pretty-print investigation results."""
    _banner(f"Investigation: {alert['alert_id']}")

    _section("Alert Info")
    _kv("Alert ID",   alert["alert_id"])
    _kv("Category",   alert["category"])
    _kv("Severity",   alert.get("severity"))
    _kv("Source",     alert.get("source"))
    _kv("Raw Log",    alert.get("raw_log", "")[:100] + "...")

    _section("Triage Output")
    triage = state.get("triage_output") or {}
    _kv("Computed Severity",  triage.get("severity"))
    _kv("FP Probability",     f"{triage.get('fp_probability', 0):.0%}")
    _kv("Category",           triage.get("category"))
    _kv("Authorized Activity",triage.get("authorized_activity"))

    if state.get("log_output"):
        log = state["log_output"]
        _section("Log Investigation")
        _kv("Events Found",  len(log.get("events", [])))
        _kv("Anomalies",     len(log.get("anomalies", [])))
        for a in log.get("anomalies", []):
            print(f"      {_c(YELLOW, '[!]')}  {a}")

    if state.get("cti_output"):
        cti = state["cti_output"]
        _section("CTI Enrichment")
        malicious = [
            ind.get("ip") for ind in cti.get("indicators", [])
            if ind.get("reputation") == "malicious"
        ]
        _kv("Indicators Checked", len(cti.get("indicators", [])))
        _kv("Malicious IPs",      malicious or "None")
        _kv("CTI Confidence",     f"{cti.get('cti_confidence', 0):.0%}")

    if state.get("attck_output"):
        attck = state["attck_output"]
        _section("MITRE ATT&CK Mapping")
        _kv("Techniques",        attck.get("technique_ids"))
        _kv("Tactic Chain",      " -> ".join(attck.get("observed_tactics", [])))
        _kv("Predicted Next",    attck.get("predicted_next", [])[:3])

    _section("Synthesis & Verdict")
    synthesis = state.get("synthesis_output") or {}
    verdict   = synthesis.get("verdict", "unknown")
    conf      = state.get("confidence_score", 0)
    verdict_color = (
        RED    if verdict == "actionable"        else
        YELLOW if verdict == "needs_investigation" else
        GREEN  if verdict == "false_positive"      else MAGENTA
    )
    print(f"    {_c(BOLD, 'Verdict:')} {_c(verdict_color, verdict.upper())}",
          f"| {_c(BOLD, 'Confidence:')} {conf:.1%}")
    _kv("Escalation",   _c(RED, "YES - " + synthesis.get("escalation_reason", ""))
                        if state.get("escalation_flag")
                        else _c(GREEN, "No"))

    _section("Incident Report - Remediation Proposals")
    report = state.get("report_output") or {}
    for prop in report.get("remediation_proposals", []):
        approval = _c(RED, "[!] REQUIRES ANALYST APPROVAL") if prop.get("requires_approval") else _c(GREEN, "Auto")
        print(f"    * {_c(BOLD, prop['action']):<30} {approval}")
        print(f"      {prop.get('description', '')[:80]}")

    _section("Pipeline Summary")
    _kv("Agents Completed", state.get("agents_completed", []))
    if state.get("missing_evidence"):
        _kv("Missing Evidence", state["missing_evidence"])


# -- Entry point ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Agentic SOC Assistant Demo Runner")
    parser.add_argument(
        "--alert-id", default=None,
        help="Run a specific alert ID (e.g. ALT-2026-002). Defaults to all sample alerts.",
    )
    args = parser.parse_args()

    print(_c(BOLD + BLUE, "\n" + "=" * 70))
    print(_c(BOLD + BLUE,   "  [SOC] Agentic SOC Assistant - End-to-End Pipeline Demo"))
    print(_c(BOLD + BLUE,   "=" * 70))
    print(_c(CYAN, "  Compiling LangGraph orchestrator..."))

    from orchestrator.graph import build_soc_graph
    graph = build_soc_graph()
    print(_c(GREEN, "  [+] Graph compiled successfully.\n"))

    # Load sample alerts
    alerts_path = Path("data/alerts/sample_alerts.json")
    all_alerts: list[dict] = json.loads(alerts_path.read_text(encoding="utf-8"))

    if args.alert_id:
        alerts = [a for a in all_alerts if a["alert_id"] == args.alert_id]
        if not alerts:
            print(_c(RED, f"Alert '{args.alert_id}' not found in sample_alerts.json."))
            sys.exit(1)
    else:
        alerts = all_alerts

    # Register investigations for HITL API
    try:
        from hitl.api import register_investigation
        hitl_available = True
    except Exception:
        hitl_available = False

    results: list[dict] = []

    for i, alert in enumerate(alerts):
        thread_id = f"demo-{alert['alert_id']}-{i}"
        print(_c(CYAN, f"  [{i+1}/{len(alerts)}] Running {alert['alert_id']} ({alert['category']})..."))
        try:
            state = run_alert(graph, alert, thread_id)
            results.append({"alert": alert, "state": state})
            print_results(alert, state)
            if hitl_available:
                register_investigation(alert["alert_id"], state)
        except Exception as e:
            print(_c(RED, f"  [-] Error running {alert['alert_id']}: {e}"))
            import traceback; traceback.print_exc()

    # Summary table
    _banner("Run Summary")
    print(f"  {'Alert ID':<20} {'Category':<25} {'Verdict':<22} {'Confidence':>10}")
    print(_c(BLUE, "  " + "-" * 65))
    for r in results:
        alert    = r["alert"]
        state    = r["state"]
        synthesis = state.get("synthesis_output") or {}
        verdict  = synthesis.get("verdict", "?")[:20]
        conf     = state.get("confidence_score", 0)
        v_color  = (RED    if verdict.startswith("action") else
                    YELLOW if verdict.startswith("needs")  else
                    GREEN  if verdict.startswith("false")  else MAGENTA)
        print(
            f"  {alert['alert_id']:<20} {alert['category']:<25} "
            f"{_c(v_color, verdict):<30} {conf:>10.1%}"
        )
    print()

    if hitl_available:
        print(_c(GREEN, "  [+] Investigations registered. Start the HITL API server with:"))
        print(_c(CYAN,  "    .venv\\Scripts\\uvicorn hitl.api:app --host 127.0.0.1 --port 8000 --reload"))
        print()


if __name__ == "__main__":
    main()
