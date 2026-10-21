
import json
from pathlib import Path

from rag.retriever import PlaybookRetriever


PROJECT_DIR = Path(__file__).resolve().parent
ALERTS_FILE = PROJECT_DIR / "data" / "alerts.json"


def main():
    with open(ALERTS_FILE, "r", encoding="utf-8") as file:
        alerts = json.load(file)

    retriever = PlaybookRetriever()

    print(f"\nTesting retrieval on {len(alerts)} alerts\n")

    for alert in alerts:
        results = retriever.search(alert, top_k=1)

        alert_id = alert.get("alert_id", "Unknown")
        alert_type = alert.get("alert_type", "Unknown")

        if results:
            best = results[0]
            print(
                f"{alert_id} | {alert_type} | "
                f"{best['playbook_id']} - {best['title']} | "
                f"distance={best['distance']:.4f}"
            )
        else:
            print(f"{alert_id} | {alert_type} | No result found")


if __name__ == "__main__":
    main()
