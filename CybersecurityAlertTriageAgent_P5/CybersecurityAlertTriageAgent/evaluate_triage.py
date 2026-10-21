
import json

with open("data/alerts.json", encoding="utf-8") as file:
    alerts = json.load(file)

with open("data/triage_results.json", encoding="utf-8") as file:
    predictions = json.load(file)

# Match predictions to alerts by ID.
alerts_by_id = {alert["alert_id"]: alert for alert in alerts}

severity_correct = 0
classification_correct = 0

print("TRIAGE EVALUATION")
print("-" * 60)

for prediction in predictions:
    alert_id = prediction["alert_id"]
    expected = alerts_by_id.get(alert_id)

    if expected is None:
        print(f"{alert_id}: No matching alert found")
        continue

    expected_severity = expected["ground_truth_severity"].capitalize()
    expected_label = expected["ground_truth_label"].upper().replace("_", " ")

    predicted_severity = prediction["severity"]
    predicted_label = prediction["classification"]

    severity_match = predicted_severity == expected_severity
    classification_match = predicted_label == expected_label

    severity_correct += severity_match
    classification_correct += classification_match

    print(f"\nAlert: {alert_id}")
    print(f"Severity: expected={expected_severity}, predicted={predicted_severity}, correct={severity_match}")
    print(f"Classification: expected={expected_label}, predicted={predicted_label}, correct={classification_match}")

total = len(predictions)

print("\n" + "-" * 60)
print("Predictions evaluated:", total)

if total:
    print(f"Severity accuracy: {severity_correct}/{total} ({severity_correct / total * 100:.1f}%)")
    print(f"Classification accuracy: {classification_correct}/{total} ({classification_correct / total * 100:.1f}%)")
else:
    print("No predictions available to evaluate.")
