import unittest

from agents.critic import CriticAgent
from agents.specialist_agent import SpecialistAgent
from a2a.communication import A2ACommunication
from orchestration.orchestrator import Orchestrator
from memory.vector_memory import VectorMemory


class FakeInvestigator:
    def __init__(self, severity="Low", evidence=None):
        self.severity = severity
        self.evidence = evidence if evidence is not None else ["Mock log evidence"]

    def investigate(self, alert):
        return {
            "alert_id": alert.get("alert_id", "TEST-1"),
            "triage": {
                "severity": self.severity,
                "classification": "UNDETERMINED",
            },
            "evidence": self.evidence,
            "recommended_action": "Review supporting logs",
            "historical_cases": [],
        }


class FakeEmbeddingModel:
    def encode(self, texts):
        return [[float(len(text)), 1.0] for text in texts]


class FakeCollection:
    def __init__(self):
        self.records = {}

    def count(self):
        return len(self.records)

    def upsert(self, ids, documents, metadatas, embeddings):
        for alert_id, document, metadata, embedding in zip(ids, documents, metadatas, embeddings):
            self.records[alert_id] = (document, metadata, embedding)

    def query(self, query_embeddings, n_results, include):
        records = list(self.records.items())[:n_results]
        return {
            "ids": [[item[0] for item in records]],
            "documents": [[item[1][0] for item in records]],
            "metadatas": [[item[1][1] for item in records]],
            "distances": [[0.1 for item in records]],
        }


class FakeVectorClient:
    def __init__(self):
        self.collection = FakeCollection()

    def get_or_create_collection(self, name, metadata):
        return self.collection


class TestAgents(unittest.TestCase):
    def test_vector_memory_stores_and_retrieves_resolved_case(self):
        client = FakeVectorClient()
        memory = VectorMemory(model=FakeEmbeddingModel(), client=client)
        memory.store_resolved(
            {"alert_id": "MEM-1", "alert_type": "brute_force", "description": "Repeated failed logins"},
            {"alert_id": "MEM-1", "investigation": {"triage": {"severity": "High", "classification": "TRUE POSITIVE"}, "recommended_action": "Reset credentials and investigate"}},
        )
        matches = memory.search_similar({"alert_id": "MEM-2", "alert_type": "brute_force", "description": "Repeated failed logins"})
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["alert_id"], "MEM-1")
        self.assertEqual(matches[0]["severity"], "High")

    def test_critic_approves_complete_investigation(self):
        result = CriticAgent().review({
            "triage": {"severity": "Medium"},
            "evidence": ["Several failed logins"],
            "recommended_action": "Review account activity",
        })
        self.assertTrue(result["approved"])

    def test_critic_rejects_missing_evidence(self):
        result = CriticAgent().review({
            "triage": {"severity": "High"},
            "evidence": [],
            "recommended_action": "Investigate",
        })
        self.assertFalse(result["approved"])
        self.assertIn("No supporting evidence was provided.", result["issues"])

    def test_specialist_does_not_perform_automated_response(self):
        result = SpecialistAgent().investigate({
            "alert": {"alert_id": "TEST-2"},
            "investigation": {
                "triage": {"severity": "Critical"},
                "evidence": ["Suspicious login"],
            },
        })
        self.assertEqual(result["severity"], "Critical")
        self.assertFalse(result["automated_response_performed"])

    def test_a2a_handoff(self):
        result = A2ACommunication().send(SpecialistAgent(), {
            "alert": {"alert_id": "TEST-3"},
            "investigation": {"triage": {"severity": "High"}, "evidence": []},
        })
        self.assertEqual(result["receiver"], "specialist_agent")

    def test_high_severity_requires_human_approval(self):
        orchestrator = Orchestrator(investigator=FakeInvestigator("High"))
        result = orchestrator.run({"alert_id": "TEST-4"})
        self.assertTrue(result["escalation_required"])
        self.assertEqual(result["human_approval_status"], "pending_human_approval")
        self.assertFalse(result["response_authorized"])
        self.assertIsNotNone(result["specialist_result"])

    def test_low_severity_does_not_escalate_when_critic_approves(self):
        orchestrator = Orchestrator(investigator=FakeInvestigator("Low"))
        result = orchestrator.run({"alert_id": "TEST-5"})
        self.assertFalse(result["escalation_required"])
        self.assertTrue(result["critic"]["approved"])

    def test_human_approval_authorizes_escalated_case(self):
        orchestrator = Orchestrator(investigator=FakeInvestigator("Critical"))
        result = orchestrator.run({"alert_id": "TEST-6"}, human_approved=True)
        self.assertEqual(result["human_approval_status"], "approved")
        self.assertTrue(result["response_authorized"])


if __name__ == "__main__":
    unittest.main()
