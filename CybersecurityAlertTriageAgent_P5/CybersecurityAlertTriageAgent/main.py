
"""Command-line entry point for the Cybersecurity Alert Triage Agent."""

import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from agents.critic import CriticAgent
from agents.investigator import Investigator
from agents.specialist_agent import SpecialistAgent
from agents.threat_intelligence import ThreatIntelligence
from agents.triage_agent import TriageAgent
from a2a.communication import A2ACommunication
from memory.vector_memory import VectorMemory
from orchestration.orchestrator import Orchestrator
from rag.retriever import PlaybookRetriever

PROJECT_DIR = Path(__file__).resolve().parent
ALERTS_FILE = PROJECT_DIR / "data" / "alerts.json"


def build_orchestrator(memory, model=None):
    """Wire all agents and shared components into the pipeline."""
    triage = TriageAgent(
        model=model or os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    )
    investigator = Investigator(
        triage_agent=triage,
        retriever=PlaybookRetriever(),
        threat_intelligence=ThreatIntelligence(),
        memory=memory,
    )
    return Orchestrator(
        investigator=investigator,
        critic=CriticAgent(),
        specialist=SpecialistAgent(),
        communication=A2ACommunication(),
    )


def load_alerts(path=ALERTS_FILE):
    """Load alerts from a JSON file and validate the top-level structure."""
    with open(path, "r", encoding="utf-8") as file:
        alerts = json.load(file)

    if not isinstance(alerts, list):
        raise ValueError("The alerts JSON file must contain a list.")

    return alerts


def validate_alert(alert):
    """Check whether an alert has the minimum required structure."""
    if not isinstance(alert, dict):
        return False

    if not alert.get("alert_id"):
        return False

    return True


def main():
    load_dotenv(PROJECT_DIR / ".env")

    parser = argparse.ArgumentParser(
        description="Run the security alert triage pipeline."
    )
    parser.add_argument(
        "--alert-id",
        help="Process one alert by ID; defaults to the first alert.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process all alerts in data/alerts.json.",
    )
    parser.add_argument(
        "--approve-escalations",
        action="store_true",
        help="Simulate explicit human approval for escalated cases.",
    )
    parser.add_argument(
        "--alerts-file",
        default=str(ALERTS_FILE),
        help="Path to an alerts JSON file.",
    )
    args = parser.parse_args()

    try:
        alerts = load_alerts(args.alerts_file)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(f"Unable to load alerts: {exc}")

    invalid_count = sum(
        not validate_alert(alert) for alert in alerts
    )
    if invalid_count:
        parser.error(
            f"Found {invalid_count} invalid alert(s). "
            "Each alert must be an object with an alert_id."
        )

    if args.alert_id:
        alerts = [
            alert
            for alert in alerts
            if str(alert.get("alert_id")) == args.alert_id
        ]
        if not alerts:
            parser.error(f"No alert found with ID {args.alert_id!r}.")
    elif not args.all:
        alerts = alerts[:1]

    if not os.getenv("GEMINI_API_KEY"):
        parser.error(
            "GEMINI_API_KEY is missing. Add it to your local .env file."
        )

    memory = VectorMemory()
    orchestrator = build_orchestrator(memory)
    outputs = []

    for alert in alerts:
        result = orchestrator.run(
            alert,
            human_approved=args.approve_escalations,
        )
        result["memory"] = {
            "similar_cases_found": len(
                result["investigation"].get("historical_cases", [])
            ),
            "stored_as_resolved": False,
        }

        critic_ok = result.get("critic", {}).get("approved") is True
        approval_ok = (
            result.get("human_approval_status")
            != "pending_human_approval"
        )

        if critic_ok and approval_ok:
            stored = memory.store_resolved(alert, result)
            result["memory"]["stored_as_resolved"] = stored["stored"]

        outputs.append(result)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    print(f"\nProcessed {len(outputs)} alert(s).")


if __name__ == "__main__":
    main()
