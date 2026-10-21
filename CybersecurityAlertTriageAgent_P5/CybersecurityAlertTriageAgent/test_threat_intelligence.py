
from agents.threat_intelligence import ThreatIntelligence


def main():
    tools = ThreatIntelligence()

    print("=" * 50)
    print("TEST 1: IP REPUTATION LOOKUP")
    print("=" * 50)

    reputation = tools.lookup_ip_reputation("198.51.100.24")
    print(reputation)

    assert reputation["success"] is True
    assert reputation["reputation"] == "malicious"
    assert reputation["risk_score"] == 95
    print("IP reputation test passed!")

    print("\n" + "=" * 50)
    print("TEST 2: SECURITY LOG SEARCH")
    print("=" * 50)

    logs = tools.search_logs(alert_id="ALT-001")
    print(logs)

    assert logs["success"] is True
    assert logs["count"] == 2
    assert all(
        item["alert_id"] == "ALT-001"
        for item in logs["results"]
    )
    print("Security log search test passed!")

    print("\n" + "=" * 50)
    print("TEST 3: MOCK TICKET CREATION")
    print("=" * 50)

    ticket_result = tools.create_ticket(
        alert_id="ALT-001",
        title="Possible brute-force compromise",
        description=(
            "Repeated failed SSH logins followed by a successful login. "
            "Human review is required."
        ),
        severity="Critical",
    )
    print(ticket_result)

    assert ticket_result["success"] is True
    assert ticket_result["ticket"]["alert_id"] == "ALT-001"
    assert ticket_result["ticket"]["severity"] == "Critical"
    assert ticket_result["ticket"]["status"] == "OPEN"
    assert len(tools.tickets) == 1
    print("Mock ticket creation test passed!")

    print("\nAll P3 tool tests passed!")


if __name__ == "__main__":
    main()
