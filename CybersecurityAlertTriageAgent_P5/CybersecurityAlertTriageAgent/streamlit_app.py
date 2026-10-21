from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv

# This UI is designed to sit in the root of the existing Cybersecurity Alert
# Triage Agent project, beside main.py, agents/, orchestration/, data/, etc.
PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")

st.set_page_config(
    page_title="Sentinel | Alert Triage",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Styling ----------
st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
      html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
      .stApp { background: #0a1020; color: #e8eefb; }
      [data-testid="stSidebar"] { background: #0d1729; border-right: 1px solid #1d2a41; }
      [data-testid="stHeader"] { background: rgba(10,16,32,.85); }
      .hero {
        padding: 1.35rem 1.5rem; border: 1px solid #243653; border-radius: 18px;
        background: linear-gradient(120deg, #111f37 0%, #101a2e 60%, #152b3a 100%);
        margin-bottom: 1.1rem;
      }
      .eyebrow { color: #73e0c0; font-size: .72rem; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
      .hero h1 { color: #f4f7ff; margin: .3rem 0 .45rem; font-size: 2rem; letter-spacing: -.04em; }
      .muted { color: #91a2bd; }
      .metric {
        border: 1px solid #243653; border-radius: 14px; padding: 1rem 1.1rem;
        background: #101a2d; min-height: 108px;
      }
      .metric-label { color: #91a2bd; font-size: .76rem; text-transform: uppercase; letter-spacing: .09em; }
      .metric-value { color: #f5f7ff; font-size: 1.55rem; font-weight: 800; margin-top: .25rem; }
      .pill { display: inline-block; border-radius: 999px; padding: .22rem .65rem; font-size: .72rem; font-weight: 800; letter-spacing: .04em; }
      .pill-critical { background: #4b1d2a; color: #ff9eaa; border: 1px solid #8c3448; }
      .pill-high { background: #4a2a19; color: #ffc18b; border: 1px solid #92582c; }
      .pill-medium { background: #443a18; color: #f5d978; border: 1px solid #8c792d; }
      .pill-low { background: #163b34; color: #82e7c6; border: 1px solid #2c7665; }
      .section-title { font-size: 1.05rem; font-weight: 800; color: #edf3ff; margin: .5rem 0 .8rem; }
      .panel { background: #101a2d; border: 1px solid #243653; border-radius: 14px; padding: 1rem 1.1rem; }
      div[data-testid="stMetric"] { background: #101a2d; border: 1px solid #243653; padding: 1rem; border-radius: 14px; }
      div[data-testid="stMetricLabel"] { color: #91a2bd; }
      div[data-testid="stMetricValue"] { color: #f4f7ff; }
      .mono { font-family: 'DM Mono', monospace; }
      .stButton > button[kind="primary"] { background: #63e2bf; color: #07151b; border: 0; font-weight: 800; border-radius: 10px; min-height: 2.7rem; }
      .stButton > button[kind="secondary"] { border: 1px solid #304462; border-radius: 10px; color: #e8eefb; background: #142139; }
      div[data-testid="stExpander"] { border: 1px solid #243653; border-radius: 12px; }
      .small-note { font-size: .82rem; color: #91a2bd; }
    </style>
    """,
    unsafe_allow_html=True,
)

SEVERITY_COLORS = {
    "critical": "pill-critical",
    "high": "pill-high",
    "medium": "pill-medium",
    "low": "pill-low",
}


def safe_text(value: Any, fallback: str = "Not available") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def load_alerts(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("data/alerts.json must contain a JSON list.")
    return data


def pick(mapping: Any, *keys: str, default=None):
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        value = mapping.get(key)
        if value is not None and value != "":
            return value
    return default


def render_severity(value: Any) -> None:
    severity = safe_text(value, "Unknown").lower()
    cls = SEVERITY_COLORS.get(severity, "pill-medium")
    st.markdown(
        f'<span class="pill {cls}">{severity.upper()}</span>',
        unsafe_allow_html=True,
    )


def get_nested_result(result: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    investigation = result.get("investigation", {})
    critic = result.get("critic", {})
    if not isinstance(investigation, dict):
        investigation = {}
    if not isinstance(critic, dict):
        critic = {}
    return investigation, critic


def main() -> None:
    alerts_path = PROJECT_DIR / "data" / "alerts.json"

    with st.sidebar:
        st.markdown("## 🛡️ SENTINEL")
        st.caption("CYBERSECURITY OPERATIONS")
        st.markdown("---")
        st.markdown("### Workspace")
        st.markdown("**Alert triage**")
        st.markdown('<span class="small-note">AI-assisted investigation with human oversight</span>', unsafe_allow_html=True)
        st.markdown("---")
        st.markdown("### Pipeline")
        for label in ["01  Triage", "02  Investigation", "03  Critic review", "04  Human approval", "05  Case memory"]:
            st.markdown(f"🟢  {label}")
        st.markdown("---")
        st.caption("Local project dashboard")
        st.caption("Results depend on your configured agents and data.")

    st.markdown(
        """
        <div class="hero">
          <div class="eyebrow">Security intelligence / Operations console</div>
          <h1>Alert Triage Center</h1>
          <div class="muted">Turn noisy security alerts into structured investigations, recommended actions, and reviewable decisions.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not os.getenv("GEMINI_API_KEY"):
        st.warning("GEMINI_API_KEY was not found. Add it to your local .env file before running an investigation. Do not paste API keys into this dashboard or share them publicly.")

    try:
        alerts = load_alerts(alerts_path)
    except Exception as exc:
        st.error(f"Could not read {alerts_path}: {exc}")
        st.info("Confirm that the project's data/alerts.json file exists and contains a JSON list.")
        return

    if not alerts:
        st.error("No alerts found.")
        st.info(f"Expected an alerts file at: {alerts_path}")
        return

    # Overview metrics
    critical_count = sum(
        1 for alert in alerts
        if str(pick(alert, "severity", "ground_truth_severity", default="")).lower() == "critical"
    )
    high_count = sum(
        1 for alert in alerts
        if str(pick(alert, "severity", "ground_truth_severity", default="")).lower() == "high"
    )
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Alerts loaded", len(alerts))
    with c2:
        st.metric("Critical in source data", critical_count)
    with c3:
        st.metric("High in source data", high_count)
    with c4:
        st.metric("Review policy", "Human-in-loop")

    st.markdown('<div class="section-title">Investigate an alert</div>', unsafe_allow_html=True)

    alert_labels = []
    alert_by_label = {}
    for index, alert in enumerate(alerts):
        alert_id = safe_text(pick(alert, "alert_id", default=f"Alert {index + 1}"))
        alert_type = safe_text(pick(alert, "alert_type", "type", default="Unknown type"))
        label = f"{alert_id}  ·  {alert_type}"
        if label in alert_by_label:
            label = f"{label} ({index + 1})"
        alert_labels.append(label)
        alert_by_label[label] = alert

    left, right = st.columns([1.2, 0.8], gap="large")
    with left:
        selected_label = st.selectbox("Select alert", alert_labels)
        selected_alert = alert_by_label[selected_label]
        st.markdown("#### Alert details")
        details_left, details_right = st.columns(2)
        with details_left:
            st.caption("Alert ID")
            st.markdown(f"`{safe_text(pick(selected_alert, 'alert_id'))}`")
            st.caption("Alert type")
            st.write(safe_text(pick(selected_alert, "alert_type", "type")))
            st.caption("Source IP")
            st.code(safe_text(pick(selected_alert, "source_ip", "src_ip", "ip_address")), language=None)
        with details_right:
            st.caption("Timestamp")
            st.write(safe_text(pick(selected_alert, "timestamp", "time", "event_time")))
            st.caption("Asset / user")
            st.write(safe_text(pick(selected_alert, "asset", "hostname", "user", "username")))
            st.caption("Raw source severity")
            render_severity(pick(selected_alert, "severity", "ground_truth_severity", default="Unknown"))
        with st.expander("View full alert payload"):
            st.json(selected_alert)

    with right:
        st.markdown("#### Run controls")
        approve = st.checkbox(
            "Simulate explicit human approval for escalations",
            value=False,
            help="Leave unchecked to preserve the pending human-approval state for escalated cases.",
        )
        st.markdown(
            '<div class="panel"><b>Safety gate</b><br><span class="small-note">Escalated cases should remain pending until a human explicitly approves them. This control passes the approval flag to the existing orchestrator.</span></div>',
            unsafe_allow_html=True,
        )
        run_clicked = st.button("▶  Run triage pipeline", type="primary", use_container_width=True)
        clear_clicked = st.button("Clear displayed result", use_container_width=True)

    if clear_clicked:
        st.session_state.pop("triage_result", None)
        st.session_state.pop("triage_alert_id", None)
        st.rerun()

    if run_clicked:
        if not os.getenv("GEMINI_API_KEY"):
            st.error("Missing GEMINI_API_KEY. Configure it in your project's .env file, then restart Streamlit.")
        else:
            try:
                with st.spinner("Running triage, investigation, critic review, and memory workflow…"):
                    # Imports are delayed so the UI can still explain setup errors cleanly.
                    from main import build_orchestrator
                    from memory.vector_memory import VectorMemory

                    memory = VectorMemory()
                    orchestrator = build_orchestrator(memory)
                    result = orchestrator.run(selected_alert, human_approved=approve)
                    if isinstance(result, dict):
                        result.setdefault("memory", {})
                        result["memory"].setdefault(
                            "similar_cases_found",
                            len((result.get("investigation") or {}).get("historical_cases", []))
                            if isinstance(result.get("investigation"), dict) else 0,
                        )
                        result["memory"].setdefault("stored_as_resolved", False)
                    st.session_state["triage_result"] = result
                    st.session_state["triage_alert_id"] = safe_text(pick(selected_alert, "alert_id"))
            except Exception as exc:
                st.error(f"The pipeline could not complete: {exc}")
                st.exception(exc)

    result = st.session_state.get("triage_result")
    if result is None:
        st.markdown("---")
        st.markdown(
            '<div class="panel"><b>Ready for analysis</b><br><span class="small-note">Choose an alert and run the pipeline to see severity, classification, evidence, investigation steps, critic feedback, escalation status, and memory information here.</span></div>',
            unsafe_allow_html=True,
        )
        return

    if not isinstance(result, dict):
        st.error("The pipeline returned a result in an unexpected format.")
        st.write(result)
        return

    investigation, critic = get_nested_result(result)
    triage = investigation.get("triage", {}) if isinstance(investigation.get("triage"), dict) else {}
    severity = pick(triage, "severity", default=pick(result, "severity", default="Unknown"))
    classification = pick(triage, "classification", default=pick(result, "classification", default="Undetermined"))
    recommended_action = pick(investigation, "recommended_action", default=pick(result, "recommended_action", default="No recommendation returned"))
    critic_approved = pick(critic, "approved", default=None)
    human_status = pick(result, "human_approval_status", default="Not reported")
    requires_review = pick(investigation, "requires_human_review", default=None)
    escalation = pick(investigation, "escalation_required", default=None)

    st.markdown("---")
    st.markdown('<div class="section-title">Triage result</div>', unsafe_allow_html=True)
    r1, r2, r3, r4 = st.columns(4)
    with r1:
        st.markdown('<div class="metric"><div class="metric-label">Predicted severity</div><div style="margin-top:.45rem">', unsafe_allow_html=True)
        render_severity(severity)
        st.markdown("</div></div>", unsafe_allow_html=True)
    with r2:
        st.markdown(f'<div class="metric"><div class="metric-label">Classification</div><div class="metric-value" style="font-size:1.05rem">{safe_text(classification)}</div></div>', unsafe_allow_html=True)
    with r3:
        critic_label = "Approved" if critic_approved is True else ("Needs review" if critic_approved is False else "Not reported")
        st.markdown(f'<div class="metric"><div class="metric-label">Critic review</div><div class="metric-value" style="font-size:1.15rem">{critic_label}</div></div>', unsafe_allow_html=True)
    with r4:
        status_label = safe_text(human_status)
        st.markdown(f'<div class="metric"><div class="metric-label">Human approval</div><div class="metric-value" style="font-size:.95rem">{status_label}</div></div>', unsafe_allow_html=True)

    st.markdown("#### Recommended action")
    st.markdown(f'<div class="panel">{safe_text(recommended_action)}</div>', unsafe_allow_html=True)

    tabs = st.tabs(["Investigation", "Evidence & tools", "Review & memory", "Raw output"])
    with tabs[0]:
        st.markdown("#### Investigation steps")
        steps = pick(investigation, "investigation_steps", default=[])
        if isinstance(steps, list) and steps:
            for index, step in enumerate(steps, start=1):
                st.markdown(f"**{index}.** {step}")
        else:
            st.info("No investigation steps were returned.")
        st.markdown("#### Playbook")
        st.write(safe_text(pick(investigation, "playbook")))
        st.markdown("#### Ticket")
        ticket = pick(investigation, "ticket", default=None)
        if ticket:
            st.json(ticket)
        else:
            st.caption("No ticket was created or returned.")

    with tabs[1]:
        st.markdown("#### Evidence")
        evidence = pick(investigation, "evidence", default=None)
        if evidence:
            if isinstance(evidence, (dict, list)):
                st.json(evidence)
            else:
                st.write(evidence)
        else:
            st.info("No evidence field was returned.")
        st.markdown("#### Tool results")
        tool_results = pick(investigation, "tool_results", default={})
        if isinstance(tool_results, dict) and tool_results:
            for tool_name, tool_result in tool_results.items():
                with st.expander(str(tool_name).replace("_", " ").title()):
                    if isinstance(tool_result, (dict, list)):
                        st.json(tool_result)
                    else:
                        st.write(tool_result)
        else:
            st.info("No tool results were returned.")

    with tabs[2]:
        a, b, c = st.columns(3)
        with a:
            st.metric("Human review required", safe_text(requires_review, "Unknown"))
        with b:
            st.metric("Escalation required", safe_text(escalation, "Unknown"))
        memory_info = result.get("memory", {})
        if not isinstance(memory_info, dict):
            memory_info = {}
        with c:
            st.metric("Similar cases found", safe_text(memory_info.get("similar_cases_found"), "0"))
        st.markdown("#### Critic feedback")
        feedback = pick(critic, "feedback", "reason", "comments", "message", default=None)
        st.write(safe_text(feedback, "No critic feedback field was returned."))
        st.markdown("#### Memory status")
        st.write("Stored as resolved:", safe_text(memory_info.get("stored_as_resolved"), "Not reported"))
        st.caption("The UI reports the memory status returned by the project. It does not independently verify persistence.")

    with tabs[3]:
        st.json(result)

    st.caption(f"Displayed result for alert {st.session_state.get('triage_alert_id', 'unknown')}. Verify critical decisions against your team's response procedures.")


if __name__ == "__main__":
    main()
