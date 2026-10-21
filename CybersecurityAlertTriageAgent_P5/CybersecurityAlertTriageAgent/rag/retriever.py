
import json
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

#path and model

PROJECT_DIR = Path(__file__).resolve().parent.parent
PLAYBOOKS_FILE = PROJECT_DIR / "data" / "playbooks.json"
DB_DIR = PROJECT_DIR / "chroma_db"
#embedding model 
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
COLLECTION_NAME = "security_playbooks"

#retrival class
class PlaybookRetriever:
    def __init__(self):
        """Load playbooks, initialize the model, and index playbooks."""

        if not PLAYBOOKS_FILE.exists():
            raise FileNotFoundError(
                f"Could not find playbooks file: {PLAYBOOKS_FILE}"
            )

        with open(PLAYBOOKS_FILE, "r", encoding="utf-8") as file:
            self.playbooks = json.load(file)

        if not isinstance(self.playbooks, list):
            raise ValueError(
                "playbooks.json must contain a JSON list of playbooks."
            )

        if not self.playbooks:
            raise ValueError("No playbooks were found in playbooks.json.")

        print("Loading sentence-transformer model...")
        self.model = SentenceTransformer(MODEL_NAME)

        self.client = chromadb.PersistentClient(path=str(DB_DIR))

        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME
        )

        self._index_playbooks()

   #converting playbook into searchable text 

    @staticmethod
    def _playbook_to_text(playbook):
        """Convert a detailed playbook into searchable text."""

        parts = [
            playbook.get("title", ""),
            playbook.get("alert_type", ""),
            playbook.get("overview", ""),
        ]

        # MITRE techniques and indicators
        for field in ("mitre_techniques", "indicators"):
            value = playbook.get(field, [])

            if isinstance(value, list):
                parts.extend(str(item) for item in value)
            elif value:
                parts.append(str(value))

        # investigation steps.
        steps = playbook.get("steps", [])

        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    parts.append(str(step.get("action", "")))
                    parts.append(str(step.get("tool", "")))
                else:
                    parts.append(str(step))

        # if other guidance is prensent then put this 
        for field in (
            "severity",
            "severity_guidance",
            "false_positive_checks",
            "containment_recommendations",
            "approval_requirements",
            "escalation_criteria",
            "references",
        ):
            value = playbook.get(field, "")

            if isinstance(value, list):
                parts.extend(str(item) for item in value)
            elif value:
                parts.append(str(value))

        return " ".join(
            str(part) for part in parts if part
        )

    # now converting the alerts to searchable text 
    @staticmethod
    def _alert_to_text(alert):
        """Convert an alert dictionary or string into searchable text."""

        if not isinstance(alert, dict):
            return str(alert)

        fields = (
            "alert_type",
            "description",
            "source",
            "source_ip",
            "host",
            "mitre_technique",
            "alert_id",
            "timestamp",
        )

        parts = [str(alert.get(field, "")) for field in fields]

        return " ".join(part for part in parts if part)

    # create/updatinh the stored playbook embeddings

    def _index_playbooks(self):
        """Create or update stored playbook embeddings."""

        ids = []
        documents = []
        metadatas = []

        for index, playbook in enumerate(self.playbooks):
            playbook_id = str(
                playbook.get("playbook_id", f"playbook-{index}")
            )

            title = str(
                playbook.get("title", "Untitled playbook")
            )

            alert_type = str(
                playbook.get("alert_type", "general_triage")
            )

            document = self._playbook_to_text(playbook)

            if not document.strip():
                continue

            ids.append(playbook_id)
            documents.append(document)

            metadatas.append({
                "alert_type": alert_type,
                "title": title,
            })

        if not ids:
            raise ValueError(
                "No searchable playbook content was found."
            )

        # Remove stale records so the collection reflects the JSON file.
        existing = self.collection.get()

        if existing["ids"]:
            self.collection.delete(ids=existing["ids"])

        print(f"Creating embeddings for {len(documents)} playbooks...")

        embeddings = self.model.encode(
            documents,
            show_progress_bar=False,
        ).tolist()

        self.collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=embeddings,
        )

        print("Playbooks indexed successfully.")

    # now searching for relevant playbooks for alerts

    def search(self, alert, top_k=3):
        """
        Find relevant playbooks for an alert.

        Args:
            alert: An alert dictionary or a text string.
            top_k: Maximum number of results to return.

        Returns:
            A list of matching playbooks and similarity distances.
        """

        if top_k < 1:
            return []

        alert_text = self._alert_to_text(alert).strip()

        if not alert_text:
            return []

        collection_count = self.collection.count()

        if collection_count == 0:
            return []

        query_embedding = self.model.encode(
            [alert_text]
        ).tolist()

        # First try an exact alert-type match.
        alert_type = (
            str(alert.get("alert_type", ""))
            if isinstance(alert, dict)
            else ""
        )

        results = None

        if alert_type:
            results = self.collection.query(
                query_embeddings=query_embedding,
                n_results=min(top_k, collection_count),
                where={"alert_type": alert_type},
                include=["documents", "metadatas", "distances"],
            )

        # If there are no exact-type results, search all playbooks.
        if (
            not results
            or not results.get("ids")
            or not results["ids"][0]
        ):
            results = self.collection.query(
                query_embeddings=query_embedding,
                n_results=min(top_k, collection_count),
                include=["documents", "metadatas", "distances"],
            )

        matches = []

        if not results or not results.get("ids"):
            return matches

        for index, playbook_id in enumerate(results["ids"][0]):
            metadata = results["metadatas"][0][index]

            matches.append({
                "playbook_id": playbook_id,
                "title": metadata.get("title", "Untitled playbook"),
                "alert_type": metadata.get("alert_type", ""),
                "distance": float(
                    results["distances"][0][index]
                ),
                "document": results["documents"][0][index],
            })

        return matches


#test and retrieve

if __name__ == "__main__":
    retriever = PlaybookRetriever()

    test_alert = {
        "alert_id": "TEST-001",
        "alert_type": "brute_force",
        "description": (
            "Many failed SSH login attempts followed by "
            "a successful login from the same IP address."
        ),
        "source_ip": "192.0.2.50",
        "host": "server-01",
        "mitre_technique": "T1110",
    }

    results = retriever.search(test_alert, top_k=3)

    print("\nRetrieved playbooks:")

    if not results:
        print("No matching playbooks found.")
    else:
        for result in results:
            print(
                f"\n- {result['playbook_id']}: "
                f"{result['title']}"
            )
            print(f"  Alert type: {result['alert_type']}")
            print(f"  Distance: {result['distance']:.4f}")
