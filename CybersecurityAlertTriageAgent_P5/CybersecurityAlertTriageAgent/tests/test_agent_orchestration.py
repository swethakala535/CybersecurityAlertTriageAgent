
import unittest

from agents.critic import CriticAgent
from agents.specialist_agent import SpecialistAgent
from a2a.communication import A2ACommunication


class TestAgentOrchestration(unittest.TestCase):

    def test_critic_detects_missing_evidence(self):
        critic = CriticAgent()

        result = critic.review({
            "triage": {"severity": "High"},
            "evidence": [],
            "recommended_action": "Investigate",
        })

        self.assertFalse(result["approved"])
        self.assertTrue(result["issues"])

    def test_specialist_reviews_alert(self):
        specialist = SpecialistAgent()

        result = specialist.investigate({
            "alert": {"alert_id": "TEST-1"},
            "investigation": {
                "triage": {"severity": "Critical"},
                "evidence": ["Repeated failed logins"],
            },
        })

        self.assertTrue(result["specialist_review"])
        self.assertEqual(result["severity"], "Critical")
        self.assertFalse(
            result["automated_response_performed"]
        )

    def test_a2a_handoff(self):
        specialist = SpecialistAgent()
        communication = A2ACommunication()

        result = communication.send(
            specialist,
            {
                "alert": {"alert_id": "TEST-2"},
                "investigation": {
                    "triage": {"severity": "High"},
                    "evidence": ["Suspicious login"],
                },
            },
        )

        self.assertEqual(
            result["receiver"],
            "specialist_agent",
        )
        self.assertTrue(
            result["message"]["specialist_review"]
        )

    def test_real_investigator_workflow(self):
        from orchestration.orchestrator import Orchestrator

        orchestrator = Orchestrator()

        alert = {
            "alert_id": "REAL-TEST-001",
            "description": (
                "Multiple failed login attempts followed by "
                "a successful login from an unfamiliar IP address."
            ),
            "source_ip": "203.0.113.25",
            "event_type": "suspicious_login",
        }

        result = orchestrator.run(alert)

        self.assertIn("investigation", result)
        self.assertIn("critic", result)
        self.assertIn("escalation_required", result)
        self.assertIn("human_approval_status", result)

        print("\nReal workflow result:")
        print("Alert ID:", result["alert_id"])
        print(
            "Severity:",
            result["investigation"]["triage"].get("severity"),
        )
        print(
            "Escalation required:",
            result["escalation_required"],
        )
        print(
            "Human approval:",
            result["human_approval_status"],
        )

    def test_critical_alert_requires_human_approval(self):
        from orchestration.orchestrator import Orchestrator

        class FakeInvestigator:
            def investigate(self, alert):
                return {
                    "alert_id": alert["alert_id"],
                    "triage": {"severity": "Critical"},
                    "evidence": ["Suspicious login activity"],
                    "recommended_action": "Investigate the alert",
                }

        orchestrator = Orchestrator(
            investigator=FakeInvestigator()
        )

        result = orchestrator.run({
            "alert_id": "TEST-CRITICAL-1"
        })

        self.assertTrue(result["escalation_required"])
        self.assertEqual(
            result["human_approval_status"],
            "pending_human_approval",
        )
        self.assertFalse(result["response_authorized"])
        self.assertIsNotNone(result["specialist_result"])

    def test_critic_rejection_triggers_escalation(self):
        from orchestration.orchestrator import Orchestrator

        class FakeInvestigator:
            def investigate(self, alert):
                return {
                    "alert_id": alert["alert_id"],
                    "triage": {"severity": "Low"},
                    "evidence": [
                        "Insufficient supporting evidence"
                    ],
                    "recommended_action": "Review the alert",
                }

        class RejectingCritic:
            def review(self, investigation):
                return {
                    "approved": False,
                    "issues": ["Evidence is insufficient."],
                }

        orchestrator = Orchestrator(
            investigator=FakeInvestigator(),
            critic=RejectingCritic(),
        )

        result = orchestrator.run({
            "alert_id": "TEST-CRITIC-1"
        })

        self.assertTrue(result["escalation_required"])
        self.assertIn(
            "Critic did not approve the investigation.",
            result["escalation_reasons"],
        )
        self.assertEqual(
            result["human_approval_status"],
            "pending_human_approval",
        )
        self.assertIsNotNone(result["specialist_result"])


if __name__ == "__main__":
    unittest.main()
