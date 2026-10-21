
import json
import time
from agents.triage_agent import TriageAgent
import os

with open("data/alerts.json", encoding="utf-8") as file:
    alerts = json.load(file)

agent = TriageAgent()
results = []
errors = []

for alert in alerts[:1]:
    try:
        result = agent.analyze(alert)
        results.append(result)

        print(
            alert["alert_id"],
            "|",
            result["severity"],
            "|",
            result["classification"],
        )

    except Exception as error:
        errors.append((alert["alert_id"], str(error)))
        print(alert["alert_id"], "| ERROR:", error)
    time.sleep(5)

print("\nTotal alerts:", len(alerts))
print("Successful:", len(results))
print("Errors:", len(errors))

if errors:
    print("\nError details:")
    for alert_id, message in errors:
        print(alert_id, "-", message)


# Merge new predictions with previously saved results.
results_path = "data/triage_results.json"
os.makedirs("data", exist_ok=True)

existing_results = []

if os.path.exists(results_path):
    with open(results_path, "r", encoding="utf-8") as file:
        try:
            existing_results = json.load(file)
        except json.JSONDecodeError:
            existing_results = []

# Keep one result per alert ID; new predictions replace older ones.
results_by_id = {
    item["alert_id"]: item
    for item in existing_results
    if "alert_id" in item
}

for result in results:
    results_by_id[result["alert_id"]] = result

saved_results = list(results_by_id.values())

with open(results_path, "w", encoding="utf-8") as file:
    json.dump(saved_results, file, indent=2)

print("New predictions:", len(results))
print("Total saved predictions:", len(saved_results))
print("Results file:", results_path)
