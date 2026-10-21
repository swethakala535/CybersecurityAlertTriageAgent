
import json

from agents.investigator import Investigator


def main():
    with open("data/alerts.json", encoding="utf-8") as file:
        alerts = json.load(file)

    # Test the first sample alert.
    alert = alerts[0]

    investigator = Investigator()
    report = investigator.investigate(alert)

    print("INVESTIGATION REPORT")
    print("-" * 50)
    print("Alert ID:", report["alert_id"])
    print("Severity:", report["triage"]["severity"])
    print("Classification:", report["triage"]["classification"])
    print("Playbook:", report["playbook"])
    print("Evidence:", report["evidence"])
    print("Recommended action:", report["recommended_action"])

    print("\nTOOL RESULTS")
    print("-" * 50)

    for tool_name, result in report["tool_results"].items():
        print(f"{tool_name}: {result}")

    print("\nINVESTIGATION STEPS")
    for step in report["investigation_steps"]:
        print(step)

    print("\nHuman review required:", report["requires_human_review"])
    print("Escalation required:", report["escalation_required"])
    print("Ticket created:", report["ticket"] is not None)

    # Validate the investigation report.
    assert report["alert_id"] == alert["alert_id"]

    assert report["triage"]["severity"] in {
        "Low", "Medium", "High", "Critical"
    }

    assert report["triage"]["classification"] in {
        "TRUE POSITIVE", "FALSE POSITIVE", "UNDETERMINED"
    }

    assert report["requires_human_review"] is True
    assert "log_search" in report["tool_results"]
    assert report["ticket"] is None  # Ticket creation is opt-in.

    if alert.get("source_ip") or alert.get("src_ip") or alert.get("ip_address"):
        assert "ip_reputation" in report["tool_results"]

    print("\nIntegrated investigator checks passed!")


if __name__ == "__main__":
    main()
