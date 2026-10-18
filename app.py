from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import os

import streamlit as st

from sentinel.correlation import correlate_incidents, dependency_edges
from sentinel.detection import enrich_with_findings
from sentinel.evidence import generate_demo_events
from sentinel.investigation import investigate
from sentinel.storage import SentinelStore

st.set_page_config(page_title="IBM Z Sentinel", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top:1.4rem;max-width:1480px}
.hero {padding:1.3rem 1.6rem;border-radius:14px;background:linear-gradient(120deg,#101c33,#173d64);color:white;margin-bottom:1rem}
.hero h1 {margin:0;font-size:2rem}.hero p {margin:.35rem 0 0;color:#d7e6f7}
.synthetic {border:1px solid #d8a537;background:#fff7df;color:#684b00;padding:.65rem .9rem;border-radius:8px;font-weight:600;margin:.6rem 0 1rem}
</style>
<div class="hero"><h1>IBM Z Sentinel</h1><p>Unified Mainframe Intelligence &amp; Protection Platform · Datathon 2026</p></div>
<div class="synthetic">SYNTHETIC DEMO MODE · Generated records only. No live z/OS, RACF or SMF connection. No system actions are executed.</div>
""", unsafe_allow_html=True)


database_path = os.getenv("SENTINEL_DB_PATH", "data/sentinel.db")
store = SentinelStore(database_path)


def refresh_demo(seed_value: int, window_value: int) -> None:
    demo_events = enrich_with_findings(generate_demo_events(seed_value))
    demo_incidents = correlate_incidents(demo_events, window_minutes=window_value)
    store.save_demo_snapshot(seed_value, window_value, demo_events, demo_incidents)


with st.sidebar:
    st.header("Synthetic demo controls")
    seed = st.number_input("Dataset seed", min_value=0, max_value=999999, value=42, step=1)
    window = st.slider("Correlation window (minutes)", 15, 240, 90, 15)
    if st.button("Load / refresh seeded demo", type="primary", use_container_width=True):
        refresh_demo(int(seed), int(window))
        st.session_state.pop("pending_decision", None)
        st.session_state["demo_refresh_message"] = "Seeded demo snapshot refreshed. Existing approval decisions were retained."
        st.rerun()
    use_granite = st.toggle("Try local Granite model", value=False,
                            help="Optional Ollama-compatible local endpoint. The deterministic investigation works without it.")
    st.caption(f"SQLite history: `{database_path}`")
    st.caption("Risk values are demonstrator heuristics, not calibrated production detection.")

if st.session_state.pop("demo_refresh_message", None):
    st.success("Seeded demo snapshot refreshed. Existing approval decisions were retained.")

# First launch creates one demo snapshot. Later refreshes are explicit and upsert stable IDs.
if not store.has_incidents():
    refresh_demo(int(seed), int(window))

incidents = store.list_incidents()
counts = store.counts()
high_risk_count = sum(incident.risk.score >= 55 for incident in incidents)

metric1, metric2, metric3, metric4 = st.columns(4)
metric1.metric("Stored evidence events", counts["evidence_events"])
metric2.metric("Incident history", counts["incidents"])
metric3.metric("High / critical cases", high_risk_count)
metric4.metric("Approval decisions", counts["approval_history"])

if not incidents:
    st.info("No cross-signal incidents are stored. Use Load / refresh seeded demo to create a synthetic incident history.")
else:
    labels = {case.incident_id: f"{case.incident_id}  |  {case.business_criticality.upper()} BUSINESS · {case.risk.band.upper()} {case.risk.score}/100  |  {', '.join(case.actors) or 'SYSTEM'}"
              for case in incidents}
    incident_id = st.selectbox("Incident history", list(labels), format_func=lambda key: labels[key])
    incident = next(case for case in incidents if case.incident_id == incident_id)
    selected_recommendations = store.list_recommendations(incident_id)
    source_counts = Counter(event.source_type for event in incident.evidence)
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    severity = max((event.severity for event in incident.evidence), key=lambda value: severity_order.get(value, 0), default="info")

    detail1, detail2, detail3, detail4 = st.columns(4)
    detail1.metric("Event severity", severity.upper())
    detail2.metric("Risk score", f"{incident.risk.score}/100")
    detail3.metric("Business criticality", incident.business_criticality.upper())
    detail4.metric("Correlated events", len(incident.evidence))

    overview, evidence_panel = st.columns([1.15, .85], gap="large")
    with overview:
        st.subheader("Incident overview")
        st.markdown(f"### {incident.incident_id}")
        if incident.business_process:
            st.markdown(f"**Business process:** {incident.business_process}")
        st.caption(f"Actors: {', '.join(incident.actors) or 'Not attributed'} · Resources: {', '.join(incident.resources)}")
        st.progress(incident.risk.score / 100, text=f"Explainable risk · {incident.risk.band.upper()}")
        for reason in incident.risk.reasons:
            st.write(f"• {reason}")
    with evidence_panel:
        st.subheader("Evidence sources")
        for source, amount in source_counts.most_common():
            st.write(f"**{source}** · {amount}")
        st.markdown("**Correlated evidence IDs**")
        st.code("\n".join(event.evidence_id for event in incident.evidence), language=None)

    st.subheader("Program and data dependencies")
    event_by_id = {event.evidence_id: event for event in incident.evidence}
    edges = dependency_edges(incident)
    if edges:
        for edge in edges:
            source = event_by_id[edge.source_evidence_id]
            target = event_by_id[edge.target_evidence_id]
            st.write(f"`{source.event_type}` {edge.source_evidence_id} → `{target.event_type}` {edge.target_evidence_id} · {edge.relationship}")
    else:
        st.caption("No explicit evidence dependency edges were recorded for this incident.")

    st.subheader("Investigation explanation")
    report = investigate(incident, use_granite=use_granite)
    st.caption(f"{report['provider']} · {report['note']}")
    for claim in report["claims"]:
        with st.container(border=True):
            st.write(claim["conclusion"])
            st.caption("Evidence references: " + ", ".join(claim["evidence_ids"]))

    st.subheader("Event timeline")
    for event in sorted(incident.evidence, key=lambda item: item.occurred_at, reverse=True):
        timestamp = datetime.fromisoformat(event.occurred_at).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        with st.expander(f"{timestamp} · {event.event_type} · {event.severity.upper()} · {event.evidence_id}"):
            st.write(event.summary)
            st.caption(f"Source: {event.source_type} · Actor: {event.actor} · Target: {event.target} · Outcome: {event.outcome} · Synthetic: {event.synthetic}")
            if event.attributes:
                st.json(event.attributes, expanded=False)

    st.subheader("Remediation recommendations")
    st.caption("Every recommendation starts pending. Approve or reject records a human decision only; Sentinel never executes an operating-system, z/OS, access-control, or data action.")
    for recommendation in selected_recommendations:
        with st.container(border=True):
            label = " · DISRUPTIVE ACTION REVIEW" if recommendation.destructive else ""
            st.markdown(f"**{recommendation.title}**{label}")
            st.write(recommendation.rationale)
            st.caption(f"Approval: {recommendation.approval_status} · Execution: {recommendation.execution_status} · Evidence: {', '.join(recommendation.evidence_ids)}")
            decision_cols = st.columns(2)
            if decision_cols[0].button("Request approval", key=f"approve:{incident_id}:{recommendation.action_id}"):
                st.session_state["pending_decision"] = (incident_id, recommendation.action_id, "Approved")
            if decision_cols[1].button("Request rejection", key=f"reject:{incident_id}:{recommendation.action_id}"):
                st.session_state["pending_decision"] = (incident_id, recommendation.action_id, "Rejected")
            pending = st.session_state.get("pending_decision")
            if pending == (incident_id, recommendation.action_id, "Approved") or pending == (incident_id, recommendation.action_id, "Rejected"):
                decision = pending[2]
                st.warning(f"Confirm recording **{decision}** for this recommendation. This will not execute it.")
                approver = st.text_input("Approver name or operator ID", key=f"approver:{incident_id}:{recommendation.action_id}")
                confirmed = st.checkbox(f"I confirm the {decision.lower()} decision", key=f"confirm:{decision}:{incident_id}:{recommendation.action_id}")
                if st.button("Confirm decision", key=f"confirm-button:{decision}:{incident_id}:{recommendation.action_id}",
                             disabled=not (approver.strip() and confirmed), type="primary"):
                    store.record_decision(incident_id, recommendation.action_id, decision,
                                          approver, confirmed=True)
                    st.session_state.pop("pending_decision", None)
                    st.rerun()

    with st.expander("Approval audit history", expanded=False):
        audit = store.list_approval_history(incident_id)
        if audit:
            for decision_row in audit:
                st.write(f"{decision_row['decided_at']} · {decision_row['decision']} · {decision_row['action_id']} · approver {decision_row['approver']}")
        else:
            st.caption("No human approval decisions have been recorded for this incident.")

with st.expander("Persistent store summary"):
    st.write(counts)
    st.caption("Refreshing with the same seed updates stable event and incident IDs; it does not duplicate records or reset approval decisions.")

st.caption("IBM Z Sentinel · Synthetic evidence only · SQLite local history · Human decisions are recorded, never executed")
