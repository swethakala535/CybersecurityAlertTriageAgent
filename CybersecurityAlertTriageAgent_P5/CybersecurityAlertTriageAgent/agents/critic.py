
class CriticAgent:
    """Check the quality of an alert investigation."""

    VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}

    def review(self, investigation):
        issues = []

        if not isinstance(investigation, dict):
            return {
                "approved": False,
                "issues": ["Investigation must be a dictionary."],
            }

        triage = investigation.get("triage", {})

        if not isinstance(triage, dict):
            triage = {}
            issues.append("Triage result is missing or invalid.")

        severity = triage.get("severity")

        if severity not in self.VALID_SEVERITIES:
            issues.append("Severity is missing or invalid.")

        evidence = investigation.get("evidence", [])

        if not isinstance(evidence, list) or not evidence:
            issues.append("No supporting evidence was provided.")

        if not investigation.get("recommended_action"):
            issues.append("Recommended action is missing.")

        return {
            "approved": len(issues) == 0,
            "issues": issues,
            "severity": severity,
        }
