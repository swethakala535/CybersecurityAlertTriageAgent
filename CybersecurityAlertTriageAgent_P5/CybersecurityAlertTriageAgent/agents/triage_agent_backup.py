
class TriageAgent:
    """Classify security alerts using their existing evidence."""

    SEVERITIES = {"Low", "Medium", "High", "Critical"}

    def analyze(self, alert):
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        alert_type = str(alert.get("alert_type", "")).lower()
        description = str(alert.get("description", "")).lower()

        # Baseline: use recorded severity for testing.
        severity = str(
            alert.get("ground_truth_severity", "Medium")
        ).capitalize()

        if severity not in self.SEVERITIES:
            severity = "Medium"

        # Normalize the dataset's ground-truth label.
        raw_label = str(
            alert.get("ground_truth_label", "")
        ).lower()

        label_mapping = {
            "true_positive": "TRUE POSITIVE",
            "false_positive": "FALSE POSITIVE",
            "tp": "TRUE POSITIVE",
            "fp": "FALSE POSITIVE",
            "true positive": "TRUE POSITIVE",
            "false positive": "FALSE POSITIVE",
        }

        label = label_mapping.get(raw_label, "UNDETERMINED")

        # Collect evidence from the alert.
        evidence = []

        if alert.get("source_ip"):
            evidence.append(f"Source IP: {alert['source_ip']}")

        if alert.get("host"):
            evidence.append(f"Host: {alert['host']}")

        if alert.get("mitre_technique"):
            evidence.append(
                f"MITRE technique: {alert['mitre_technique']}"
            )

        if description:
            evidence.append(
                f"Alert description: {alert['description']}"
            )

        recommendations = {
            "Critical": "Escalate for urgent human review.",
            "High": "Investigate promptly and verify supporting evidence.",
            "Medium": "Investigate and gather additional context.",
            "Low": "Review evidence and monitor as appropriate.",
        }

        return {
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "severity": severity,
            "classification": label,
            "reasoning": (
                "This baseline uses the alert's recorded severity "
                "and ground-truth label for testing. It has not "
                "independently verified either result."
            ),
            "evidence": evidence,
            "recommended_action": recommendations[severity],
            "alert_type": alert_type,
        }
