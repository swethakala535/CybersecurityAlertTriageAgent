
from datetime import datetime, timezone
from uuid import uuid4


class ThreatIntelligence:
    """Provide deterministic mock security investigation tools."""

    def __init__(self):
        # Mock IP reputation database for the college project.
        self.ip_reputation = {
            "198.51.100.24": {
                "reputation": "malicious",
                "risk_score": 95,
                "description": "Mock brute-force source IP",
            },
            "203.0.113.50": {
                "reputation": "suspicious",
                "risk_score": 65,
                "description": "Mock suspicious outbound traffic",
            },
            "192.0.2.10": {
                "reputation": "clean",
                "risk_score": 5,
                "description": "Mock known benign IP",
            },
        }

        # Mock security events for testing.
        self.security_logs = [
            {
                "event_id": "LOG-001",
                "alert_id": "ALT-001",
                "event_type": "failed_login",
                "source_ip": "198.51.100.24",
                "host": "server-app-01",
                "message": "Repeated failed SSH logins",
            },
            {
                "event_id": "LOG-002",
                "alert_id": "ALT-001",
                "event_type": "successful_login",
                "source_ip": "198.51.100.24",
                "host": "server-app-01",
                "message": "Successful login after repeated failures",
            },
            {
                "event_id": "LOG-003",
                "alert_id": "ALT-004",
                "event_type": "network_connection",
                "source_ip": "203.0.113.50",
                "host": "workstation-02",
                "message": "Unusual outbound connection",
            },
        ]

        # Mock ticket storage. Tickets exist only while this object lives.
        self.tickets = []

    def lookup_ip_reputation(self, ip_address):
        """Look up an IP in the local mock reputation database."""
        if not isinstance(ip_address, str) or not ip_address.strip():
            return {
                "success": False,
                "error": "A valid, non-empty IP address is required.",
            }

        ip_address = ip_address.strip()
        result = self.ip_reputation.get(ip_address)

        if result is None:
            return {
                "success": True,
                "ip_address": ip_address,
                "reputation": "unknown",
                "risk_score": None,
                "description": "IP not found in the mock database.",
                "source": "mock_database",
            }

        return {
            "success": True,
            "ip_address": ip_address,
            **result,
            "source": "mock_database",
        }

    def search_logs(self, query=None, alert_id=None, source_ip=None, host=None):
        """Search mock security logs using any supplied filters."""
        if query is not None and not isinstance(query, str):
            return {"success": False, "error": "query must be a string."}

        if alert_id is not None and not isinstance(alert_id, str):
            return {"success": False, "error": "alert_id must be a string."}

        if source_ip is not None and not isinstance(source_ip, str):
            return {"success": False, "error": "source_ip must be a string."}

        if host is not None and not isinstance(host, str):
            return {"success": False, "error": "host must be a string."}

        matches = []

        for log in self.security_logs:
            if alert_id and log["alert_id"].lower() != alert_id.lower():
                continue

            if source_ip and log["source_ip"] != source_ip:
                continue

            if host and log["host"].lower() != host.lower():
                continue

            if query:
                searchable_text = " ".join(str(value) for value in log.values())
                if query.lower() not in searchable_text.lower():
                    continue

            matches.append(log.copy())

        return {
            "success": True,
            "query": query,
            "count": len(matches),
            "results": matches,
            "source": "mock_security_logs",
        }

    def create_ticket(
        self,
        alert_id,
        title,
        description,
        severity="Medium",
    ):
        """Create a mock investigation ticket without external side effects."""
        valid_severities = {"Low", "Medium", "High", "Critical"}

        if not isinstance(alert_id, str) or not alert_id.strip():
            return {
                "success": False,
                "error": "alert_id is required.",
            }

        if not isinstance(title, str) or not title.strip():
            return {
                "success": False,
                "error": "title is required.",
            }

        if not isinstance(description, str) or not description.strip():
            return {
                "success": False,
                "error": "description is required.",
            }

        if severity not in valid_severities:
            return {
                "success": False,
                "error": (
                    "severity must be Low, Medium, High, or Critical."
                ),
            }

        ticket = {
            "ticket_id": f"TKT-{uuid4().hex[:8].upper()}",
            "alert_id": alert_id.strip(),
            "title": title.strip(),
            "description": description.strip(),
            "severity": severity,
            "status": "OPEN",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source": "mock_ticket_system",
        }

        self.tickets.append(ticket)

        return {
            "success": True,
            "ticket": ticket.copy(),
            "message": "Mock investigation ticket created.",
        }
