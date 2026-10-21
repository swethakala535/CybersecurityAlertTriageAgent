"""Persistent vector memory for previously resolved security alerts."""

import json
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_DIR = PROJECT_DIR / "chroma_db"
DEFAULT_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_COLLECTION_NAME = "resolved_security_alerts"


class VectorMemory:
    """Store resolved cases and retrieve semantically similar incidents."""

    def __init__(self, db_dir=None, model_name=DEFAULT_MODEL_NAME,
                 collection_name=DEFAULT_COLLECTION_NAME, model=None, client=None):
        if model is None:
            from sentence_transformers import SentenceTransformer
            model = SentenceTransformer(model_name)
        if client is None:
            import chromadb
            client = chromadb.PersistentClient(path=str(db_dir or DEFAULT_DB_DIR))
        self.model = model
        self.client = client
        self.collection = self.client.get_or_create_collection(
            name=collection_name, metadata={"hnsw:space": "cosine"}
        )

    @staticmethod
    def _alert_text(alert):
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")
        fields = ("alert_type", "description", "source", "source_ip", "host",
                  "mitre_technique", "event_type")
        return " ".join(str(alert.get(key, "")) for key in fields).strip()

    def store_resolved(self, alert, result, resolution=None):
        """Persist a completed case. Call only after a verified resolution."""
        if not isinstance(alert, dict) or not isinstance(result, dict):
            raise ValueError("alert and result must be dictionaries.")
        investigation = result.get("investigation", result)
        triage = investigation.get("triage", {})
        if not isinstance(triage, dict):
            triage = {}
        alert_id = str(alert.get("alert_id") or result.get("alert_id") or "").strip()
        if not alert_id:
            raise ValueError("A resolved alert must have an alert_id.")
        document = self._alert_text(alert) or json.dumps(alert, sort_keys=True)
        metadata = {
            "alert_id": alert_id,
            "severity": str(triage.get("severity", "Unknown")),
            "classification": str(triage.get("classification", "UNDETERMINED")),
            "resolution": str(resolution or investigation.get(
                "recommended_action", "Reviewed and resolved"))[:1000],
        }
        encoded = self.model.encode([document])
        embedding = encoded.tolist()[0] if hasattr(encoded, "tolist") else encoded[0]
        self.collection.upsert(ids=[alert_id], documents=[document],
                               metadatas=[metadata], embeddings=[embedding])
        return {"stored": True, "alert_id": alert_id}

    def search_similar(self, alert, top_k=3):
        """Return relevant prior cases without treating them as ground truth."""
        if top_k < 1:
            return []
        query = self._alert_text(alert)
        count = self.collection.count()
        if not query or count == 0:
            return []
        encoded = self.model.encode([query])
        embedding = encoded.tolist() if hasattr(encoded, "tolist") else encoded
        results = self.collection.query(
            query_embeddings=embedding, n_results=min(top_k, count),
            include=["documents", "metadatas", "distances"])
        ids = results.get("ids", [[]])[0]
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
        current_id = str(alert.get("alert_id", ""))
        matches = []
        for case_id, document, metadata, distance in zip(ids, docs, metas, distances):
            if case_id == current_id:
                continue
            metadata = metadata or {}
            matches.append({
                "alert_id": metadata.get("alert_id", case_id),
                "severity": metadata.get("severity", "Unknown"),
                "classification": metadata.get("classification", "UNDETERMINED"),
                "resolution": metadata.get("resolution", ""),
                "description": document,
                "distance": float(distance),
            })
        return matches
