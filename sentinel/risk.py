"""Transparent risk scoring for normalized synthetic evidence."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable
from .evidence import Evidence

SEVERITY_POINTS = {"info": 5, "low": 10, "medium": 20, "high": 30, "critical": 40}
SIGNAL_POINTS = {
    "AUTH_FAILURE_BURST": (20, "Repeated authentication failures"),
    "PRIVILEGE_CHANGE": (25, "Privilege or security configuration changed"),
    "PROGRAM_CHANGE": (22, "Program changed outside the approved baseline"),
    "SUSPICIOUS_SENSITIVE_ACCESS": (25, "Sensitive access differs from its approved baseline"),
    "UNSCHEDULED_JOB": (18, "Unscheduled batch job activity"),
    "BATCH_INTEGRITY_MISMATCH": (30, "Batch returned success with incomplete business data"),
    "CHECKSUM_MISMATCH": (25, "Data integrity baseline mismatch"),
    "RESTRICTED_READ": (18, "Successful access to restricted data"),
}

@dataclass(frozen=True)
class RiskAssessment:
    score: int
    band: str
    reasons: tuple[str, ...]

def score_evidence(evidence: Iterable[Evidence]) -> RiskAssessment:
    """Score one correlated actor story; explain each additive contribution."""
    items = list(evidence)
    if not items:
        return RiskAssessment(0, "low", ("No evidence in this incident",))
    points = 0
    reasons: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item.event_type not in seen and item.event_type in SIGNAL_POINTS:
            bonus, reason = SIGNAL_POINTS[item.event_type]
            points += bonus
            reasons.append(f"+{bonus}: {reason} ({item.event_type})")
            seen.add(item.event_type)
    types = {item.event_type for item in items}
    if {"PRIVILEGE_CHANGE", "UNSCHEDULED_JOB", "CHECKSUM_MISMATCH"}.issubset(types):
        points += 15
        reasons.append("+15: Correlated privilege, batch-job and integrity signals")
    if {"PROGRAM_CHANGE", "SUSPICIOUS_SENSITIVE_ACCESS", "BATCH_INTEGRITY_MISMATCH"}.issubset(types):
        points += 20
        reasons.append("+20: Program change, anomalous sensitive access and incomplete batch form a business-impact chain")
    severity_total = sum(SEVERITY_POINTS.get(x.severity, 10) for x in items)
    score = min(100, severity_total + points)
    band = "critical" if score >= 80 else "high" if score >= 55 else "medium" if score >= 30 else "low"
    reasons.insert(0, f"Severity contribution: {severity_total} points across {len(items)} events")
    return RiskAssessment(score, band, tuple(reasons))

def group_by_actor(evidence: Iterable[Evidence]) -> dict[str, list[Evidence]]:
    groups: dict[str, list[Evidence]] = defaultdict(list)
    for item in evidence:
        groups[item.actor].append(item)
    return dict(groups)
