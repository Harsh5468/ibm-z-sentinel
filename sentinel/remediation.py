"""Human approval state for suggested remediations; no action execution exists."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .correlation import Incident


@dataclass(frozen=True)
class Recommendation:
    action_id: str
    title: str
    rationale: str
    evidence_ids: tuple[str, ...]
    approval_status: str = "Pending approval"
    destructive: bool = False
    execution_status: str = "Not executed"


def recommend_remediations(incident: Incident) -> list[Recommendation]:
    events = incident.evidence
    recommendations: list[Recommendation] = []
    def add(action_id: str, title: str, rationale: str, event_types: set[str], destructive: bool = False) -> None:
        refs = tuple(item.evidence_id for item in events if item.event_type in event_types)
        if refs:
            recommendations.append(Recommendation(action_id, title, rationale, refs,
                                                  destructive=destructive))
    add("review-access", "Review involved identity access and recent authorization changes",
        "Validate the request and maintenance record with an authorized operator before changing access.",
        {"AUTH_FAILURE_BURST", "PRIVILEGE_CHANGE", "RESTRICTED_READ"})
    add("review-program-change", "Verify the payroll program change against its approved release record",
        "Compare the change reference and load-module baseline with the release owner before any rollback or replacement.",
        {"PROGRAM_CHANGE"})
    add("review-sensitive-access", "Review the flagged restricted-dataset access with the data owner",
        "Check the baseline comparison and preserve the access evidence; this recommendation does not change permissions.",
        {"SUSPICIOUS_SENSITIVE_ACCESS"})
    add("hold-export", "Request a human review of the export job",
        "Confirm job ownership and business need; any hold or cancellation requires explicit operator approval.",
        {"UNSCHEDULED_JOB"}, destructive=True)
    add("hold-payroll-output", "Request a human hold on downstream use of the incomplete payroll output",
        "Reconcile record counts and control totals with the batch owner before any downstream business use. Sentinel will not hold or alter data.",
        {"BATCH_INTEGRITY_MISMATCH"}, destructive=True)
    if incident.business_process == "Payment settlement":
        add("hold-payment-settlement", "Request human review before downstream payment settlement",
            "Ask the settlement owner to hold processing of the linked output until the 100,000 expected versus 99,000 processed records are reconciled. Sentinel records this recommendation only and will not pause or alter settlement processing.",
            {"BATCH_INTEGRITY_MISMATCH", "OUTPUT_DATASET_WRITTEN",
             "SETTLEMENT_CONSUMER_QUEUED"}, destructive=True)
    add("verify-dataset", "Verify the dataset against a trusted backup or baseline",
        "Preserve the current evidence and have the data owner validate the integrity alert.",
        {"CHECKSUM_MISMATCH"})
    return recommendations


def set_approval(recommendations: Iterable[Recommendation], action_id: str, decision: str,
                 *, confirmed: bool = False) -> list[Recommendation]:
    """Return updated recommendation state after explicit human confirmation.

    This records a decision only. It intentionally has no action execution path.
    """
    if not confirmed:
        raise PermissionError("A human must explicitly confirm the approval decision")
    if decision not in {"Approved", "Rejected", "Pending approval"}:
        raise ValueError("decision must be Approved, Rejected, or Pending approval")
    items = list(recommendations)
    if not any(item.action_id == action_id for item in items):
        raise KeyError(f"Unknown recommendation: {action_id}")
    return [Recommendation(item.action_id, item.title, item.rationale, item.evidence_ids,
                           decision if item.action_id == action_id else item.approval_status,
                           item.destructive, "Not executed") for item in items]
