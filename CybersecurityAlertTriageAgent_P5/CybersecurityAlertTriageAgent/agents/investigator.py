
from agents.triage_agent import TriageAgent
from rag.retriever import PlaybookRetriever
from agents.threat_intelligence import ThreatIntelligence


class Investigator:
    """Coordinate triage, playbook retrieval, and mock security tools."""

    def __init__(
        self,
        triage_agent=None,
        retriever=None,
        threat_intelligence=None,
        memory=None,
    ):
        self.triage_agent = triage_agent or TriageAgent()
        self.retriever = retriever or PlaybookRetriever()
        self.threat_intelligence = (
            threat_intelligence or ThreatIntelligence()
        )
        self.memory = memory

    def investigate(self, alert, create_ticket=False):
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        # Retrieve similar resolved cases as optional context.
        alert_for_analysis = dict(alert)
        historical_cases = []
        if self.memory is not None:
            historical_cases = self.memory.search_similar(alert, top_k=3)
            if historical_cases:
                alert_for_analysis["historical_context"] = [
                    {key: case.get(key, "") for key in
                     ("alert_id", "severity", "classification", "resolution")}
                    for case in historical_cases
                ]

        # 1. Analyze the alert. Historical cases are context, not ground truth.
        triage_result = self.triage_agent.analyze(alert_for_analysis)
        severity = triage_result["severity"]

        investigation_steps = []
        tool_results = {}

        # 2. Retrieve the most relevant playbook.
        playbooks = self.retriever.search(alert, top_k=1)
        selected_playbook = playbooks[0] if playbooks else None

        playbook_summary = None

        if selected_playbook:
            playbook_summary = {
                "playbook_id": selected_playbook["playbook_id"],
                "title": selected_playbook["title"],
                "alert_type": selected_playbook["alert_type"],
                "distance": selected_playbook["distance"],
            }

            investigation_steps.append({
                "step": "retrieve_playbook",
                "status": "success",
                "details": (
                    "Retrieved playbook: "
                    + selected_playbook["title"]
                ),
            })
        else:
            investigation_steps.append({
                "step": "retrieve_playbook",
                "status": "not_found",
                "details": "No relevant playbook was retrieved.",
            })

        # 3. Look up an IP address if the alert provides one.
        ip_address = (
            alert.get("source_ip")
            or alert.get("src_ip")
            or alert.get("ip_address")
        )

        if ip_address:
            reputation = (
                self.threat_intelligence.lookup_ip_reputation(
                    ip_address
                )
            )
            tool_results["ip_reputation"] = reputation

            investigation_steps.append({
                "step": "lookup_ip_reputation",
                "status": (
                    "success"
                    if reputation.get("success")
                    else "error"
                ),
                "details": (
                    f"IP reputation lookup completed for {ip_address}."
                ),
            })
        else:
            investigation_steps.append({
                "step": "lookup_ip_reputation",
                "status": "skipped",
                "details": "No source IP was provided in the alert.",
            })

        # 4. Search logs associated with this alert.
        alert_id = alert.get("alert_id")
        log_result = self.threat_intelligence.search_logs(
            alert_id=alert_id
        )
        tool_results["log_search"] = log_result

        investigation_steps.append({
            "step": "search_logs",
            "status": (
                "success" if log_result.get("success") else "error"
            ),
            "details": (
                f"Log search returned {log_result.get('count', 0)} "
                "matching events."
            ),
        })

        # 5. Decide whether urgent human review is required.
        escalation_required = severity in {"High", "Critical"}

        investigation_steps.append({
            "step": "escalation_check",
            "status": (
                "escalation_required"
                if escalation_required
                else "standard_review"
            ),
            "details": (
                f"{severity} severity alert requires "
                f"{'urgent' if escalation_required else 'standard'} "
                "human review."
            ),
        })

        # 6. Prepare or create a mock ticket.
        ticket_result = None

        if escalation_required:
            if create_ticket:
                ticket_result = self.threat_intelligence.create_ticket(
                    alert_id=triage_result["alert_id"],
                    title=f"{severity} security alert investigation",
                    description=(
                        triage_result.get("reasoning", "")
                        or "Security alert requires investigation."
                    ),
                    severity=severity,
                )

                tool_results["ticket"] = ticket_result

                investigation_steps.append({
                    "step": "create_ticket",
                    "status": (
                        "success"
                        if ticket_result.get("success")
                        else "error"
                    ),
                    "details": (
                        "Mock ticket creation was requested."
                    ),
                })
            else:
                investigation_steps.append({
                    "step": "create_ticket",
                    "status": "approval_required",
                    "details": (
                        "A mock ticket is recommended, but creation "
                        "was not authorized. Call investigate(alert, "
                        "create_ticket=True) to create it."
                    ),
                })

        # 7. Build the investigation report.
        return {
            "alert_id": triage_result["alert_id"],
            "triage": triage_result,
            "playbook": playbook_summary,
            "historical_cases": historical_cases,
            "evidence": triage_result.get("evidence", []),
            "recommended_action": triage_result.get(
                "recommended_action", ""
            ),
            "tool_results": tool_results,
            "ticket": ticket_result,
            "investigation_steps": investigation_steps,
            "investigation_status": (
                "playbook_found"
                if playbook_summary
                else "no_playbook_found"
            ),
            "escalation_required": escalation_required,
            "requires_human_review": True,
        }
