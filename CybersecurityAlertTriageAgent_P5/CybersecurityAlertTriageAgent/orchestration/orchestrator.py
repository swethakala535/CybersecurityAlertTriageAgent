
from agents.investigator import Investigator
from agents.critic import CriticAgent
from agents.specialist_agent import SpecialistAgent
from a2a.communication import A2ACommunication


class Orchestrator:
    """Coordinate investigation, critique, escalation and approval."""

    def __init__(
        self,
        investigator=None,
        critic=None,
        specialist=None,
        communication=None,
    ):
        self.investigator = investigator or Investigator()
        self.critic = critic or CriticAgent()
        self.specialist = specialist or SpecialistAgent()
        self.communication = communication or A2ACommunication()

    def run(self, alert, human_approved=False):
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        # 1. Investigate the alert.
        investigation = self.investigator.investigate(alert)

        if not isinstance(investigation, dict):
            raise ValueError("Investigator must return a dictionary.")

        # 2. Review investigation quality.
        critic_result = self.critic.review(investigation)

        if not isinstance(critic_result, dict):
            critic_result = {
                "approved": False,
                "issues": ["Critic returned an invalid result."],
            }

        critic_approved = critic_result.get("approved") is True
        critic_issues = critic_result.get("issues", [])

        if not isinstance(critic_issues, list):
            critic_issues = ["Critic issues are missing or invalid."]

        # 3. Read severity safely.
        triage = investigation.get("triage", {})
        if not isinstance(triage, dict):
            triage = {}

        severity = triage.get("severity", "Unknown")

        # 4. Decide whether specialist review is required.
        escalation_reasons = []

        if severity in {"High", "Critical"}:
            escalation_reasons.append(
                f"Alert severity is {severity}."
            )

        if not critic_approved:
            escalation_reasons.append(
                "Critic did not approve the investigation."
            )

        escalation_required = bool(escalation_reasons)
        specialist_result = None

        # 5. Send the A2A handoff.
        if escalation_required:
            message = {
                "alert": alert,
                "investigation": investigation,
                "critic_issues": critic_issues,
                "escalation_reasons": escalation_reasons,
            }

            specialist_result = self.communication.send(
                self.specialist,
                message,
            )

        # 6. Apply the human-approval gate.
        if escalation_required:
            approval_status = (
                "approved"
                if human_approved
                else "pending_human_approval"
            )
        else:
            approval_status = "not_required_for_escalation"

        return {
            "alert_id": investigation.get(
                "alert_id",
                alert.get("alert_id", "UNKNOWN"),
            ),
            "investigation": investigation,
            "critic": critic_result,
            "escalation_required": escalation_required,
            "escalation_reasons": escalation_reasons,
            "specialist_result": specialist_result,
            "human_approval_status": approval_status,
            "response_authorized": (
                escalation_required and human_approved
            ),
        }
