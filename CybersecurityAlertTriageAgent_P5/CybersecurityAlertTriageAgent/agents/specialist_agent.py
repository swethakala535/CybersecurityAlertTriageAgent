
class SpecialistAgent:
    """Provide a second review of escalated security alerts."""

    def investigate(self, message):
        alert = message.get("alert", {})
        investigation = message.get("investigation", {})
        triage = investigation.get("triage", {})

        if not isinstance(alert, dict):
            alert = {}

        if not isinstance(triage, dict):
            triage = {}

        severity = triage.get("severity", "Unknown")
        evidence = investigation.get("evidence", [])
        issues = message.get("critic_issues", [])

        findings = [
            f"Alert ID: {alert.get('alert_id', 'UNKNOWN')}",
            f"Reported severity: {severity}",
            f"Evidence items available: {len(evidence)}",
        ]

        if issues:
            findings.append(
                "The critic identified issues requiring verification."
            )

        return {
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "specialist_review": True,
            "severity": severity,
            "findings": findings,
            "recommendation": (
                "Verify the evidence and follow the approved "
                "incident-response playbook."
            ),
            "automated_response_performed": False,
        }

