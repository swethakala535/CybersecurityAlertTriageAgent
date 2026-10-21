
import json
import os

from dotenv import load_dotenv
from google import genai


load_dotenv()


class TriageAgent:
    """Classify security alerts using Gemini and the alert evidence."""

    SEVERITIES = {"Low", "Medium", "High", "Critical"}
    CLASSIFICATIONS = {
        "TRUE POSITIVE",
        "FALSE POSITIVE",
        "UNDETERMINED",
    }

    def __init__(self, client=None, model="gemini-3.5-flash-lite"):
        api_key = os.getenv("GEMINI_API_KEY")

        if client is None:
            if not api_key:
                raise ValueError(
                    "GEMINI_API_KEY was not found. "
                    "Check that it is set in your .env file."
                )
            client = genai.Client(api_key=api_key)

        self.client = client
        self.model = model

    def analyze(self, alert):
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        # Exclude ground-truth fields to avoid leaking answers to Gemini.
        safe_alert = {
            key: value
            for key, value in alert.items()
            if key not in {
                "ground_truth_severity",
                "ground_truth_label",
            }
        }

        prompt = f"""
You are a cybersecurity alert triage analyst.

Analyze the alert using only the evidence provided.
Do not invent facts. If evidence is insufficient, say so.
Do not assume an alert is malicious merely because it exists.

Return ONLY a valid JSON object with these fields:
- severity: exactly Low, Medium, High, or Critical
- classification: exactly TRUE POSITIVE, FALSE POSITIVE, or UNDETERMINED
- reasoning: a concise explanation based on the alert evidence
- evidence: a list of specific evidence items from the alert
- recommended_action: a practical next step

Classification guidance:
- TRUE POSITIVE: evidence supports a real security incident.
- FALSE POSITIVE: available evidence supports a benign explanation.
- UNDETERMINED: evidence is insufficient to decide.

Severity guidance:
- Critical: credible evidence of successful unauthorized access to a sensitive
  system, active ransomware, domain-level compromise, or confirmed severe impact.
- High: strong evidence of a serious threat, but no evidence of critical impact.
- Medium: suspicious activity requiring investigation, with no confirmed severe impact.
- Low: limited-risk activity or a well-supported benign explanation.

Few-shot examples:
Example 1:
Alert evidence: 18 failed SSH logins from an external IP within five minutes,
followed by a successful login from that same IP.
Expected output: severity=Critical, classification=TRUE POSITIVE.
Reason: the successful login after repeated failures supports possible account
compromise; urgent investigation is required.

Example 2:
Alert evidence: Three failed login attempts followed by a documented password
reset, with no suspicious successful login.
Expected output: severity=Low, classification=FALSE POSITIVE.
Reason: the available evidence supports a benign explanation.

Alert data:
{json.dumps(safe_alert, indent=2)}

Return valid JSON only. Do not include Markdown fences.
"""

        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
        )

        try:
            result = json.loads(response.text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(
                "Gemini did not return valid JSON. Try the alert again."
            ) from exc

        severity = result.get("severity")
        classification = result.get("classification")

        if severity not in self.SEVERITIES:
            raise ValueError(
                f"Gemini returned an invalid severity: {severity!r}"
            )

        if classification not in self.CLASSIFICATIONS:
            raise ValueError(
                "Gemini returned an invalid classification: "
                f"{classification!r}"
            )

        evidence = result.get("evidence", [])
        if not isinstance(evidence, list):
            evidence = []

        recommendations = {
            "Critical": "Escalate for urgent human review.",
            "High": "Investigate promptly and verify supporting evidence.",
            "Medium": "Investigate and gather additional context.",
            "Low": "Review evidence and monitor as appropriate.",
        }

        return {
            "alert_id": alert.get("alert_id", "UNKNOWN"),
            "severity": severity,
            "classification": classification,
            "reasoning": str(result.get("reasoning", "")),
            "evidence": evidence,
            "recommended_action": str(
                result.get(
                    "recommended_action",
                    recommendations[severity],
                )
            ),
            "alert_type": str(alert.get("alert_type", "")).lower(),
        }
