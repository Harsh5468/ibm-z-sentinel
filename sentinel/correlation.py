"""Time-bounded cross-signal incident correlation for normalized evidence."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from typing import Iterable

from .evidence import Evidence
from .risk import RiskAssessment, score_evidence

SIGNAL_TYPES = {"AUTH_FAILURE_BURST", "PRIVILEGE_CHANGE", "PROGRAM_CHANGE",
                "SUSPICIOUS_SENSITIVE_ACCESS", "UNSCHEDULED_JOB", "BATCH_JOB_COMPLETE",
                "BATCH_INTEGRITY_MISMATCH", "CHECKSUM_MISMATCH", "RESTRICTED_READ",
                "SETTLEMENT_CONSUMER_QUEUED"}


@dataclass(frozen=True)
class Incident:
    incident_id: str
    evidence: tuple[Evidence, ...]
    actors: tuple[str, ...]
    resources: tuple[str, ...]
    risk: RiskAssessment
    business_criticality: str = "unclassified"
    business_process: str = ""


@dataclass(frozen=True)
class DependencyEdge:
    source_evidence_id: str
    target_evidence_id: str
    relationship: str


def _time(item: Evidence) -> datetime:
    parsed = datetime.fromisoformat(item.occurred_at.replace("Z", "+00:00"))
    return parsed


def _identities(item: Evidence) -> set[str]:
    """Return only actor/resource entities; arbitrary shared metadata is not a link."""
    ids = {f"actor:{item.actor.casefold()}"} if item.actor and item.actor.upper() != "SYSTEM" else set()
    if item.target:
        ids.add(f"resource:{item.target.casefold()}")
    return ids


_ACTOR_SIGNAL_PAIRS = {
    frozenset(("AUTH_FAILURE_BURST", "PRIVILEGE_CHANGE")),
    frozenset(("PRIVILEGE_CHANGE", "UNSCHEDULED_JOB")),
    frozenset(("UNSCHEDULED_JOB", "RESTRICTED_READ")),
    frozenset(("RESTRICTED_READ", "SENSITIVE_DATA_ACCESS")),
    frozenset(("PRIVILEGE_CHANGE", "PROGRAM_CHANGE")),
    frozenset(("PROGRAM_CHANGE", "SENSITIVE_DATA_ACCESS")),
    frozenset(("PROGRAM_CHANGE", "BATCH_JOB_COMPLETE")),
    frozenset(("SENSITIVE_DATA_ACCESS", "BATCH_JOB_COMPLETE")),
    frozenset(("UNSCHEDULED_JOB", "BATCH_JOB_COMPLETE")),
}
_RESOURCE_SIGNAL_PAIRS = {
    frozenset(("RESTRICTED_READ", "CHECKSUM_MISMATCH")),
}


def _explicit_links(item: Evidence) -> list[tuple[str, str, str]]:
    attrs = item.attributes
    links: list[tuple[str, str, str]] = []
    for key, relationship in (
        ("program_evidence_id", "program dependency"),
        ("downstream_job_evidence_id", "program to batch job"),
        ("downstream_dataset_evidence_id", "program to output dataset"),
        ("downstream_settlement_evidence_id", "output dataset to settlement consumer"),
        ("output_dataset_evidence_id", "batch job to output dataset"),
        ("source_job_evidence_id", "batch job produced dataset"),
        ("source_dataset_evidence_id", "output dataset consumed by settlement"),
        ("batch_evidence_id", "batch integrity finding"),
        ("baseline_evidence_id", "access baseline finding"),
    ):
        value = attrs.get(key)
        if value:
            source_id = str(value)
            if key in {"downstream_job_evidence_id", "downstream_dataset_evidence_id",
                       "downstream_settlement_evidence_id", "output_dataset_evidence_id"}:
                links.append((item.evidence_id, source_id, relationship))
            else:
                links.append((source_id, item.evidence_id, relationship))
    for key, relationship in (("source_access_evidence_ids", "access feeds batch job"),
                              ("source_evidence_ids", "source evidence supports detector finding")):
        for value in attrs.get(key, []) or []:
            links.append((str(value), item.evidence_id, relationship))
    return links


def dependency_edges(incident: Incident) -> list[DependencyEdge]:
    """Return explicit evidence-to-evidence dependency links present in an incident."""
    evidence_ids = {item.evidence_id for item in incident.evidence}
    edges = {
        DependencyEdge(source, target, relation)
        for item in incident.evidence
        for source, target, relation in _explicit_links(item)
        if source in evidence_ids and target in evidence_ids
    }
    return sorted(edges, key=lambda edge: (edge.source_evidence_id, edge.target_evidence_id, edge.relationship))


def correlate_incidents(evidence: Iterable[Evidence], window_minutes: int = 90) -> list[Incident]:
    """Build connected incident components when events share entities in a time window.

    Correlation prioritizes explicit evidence-ID dependencies. Actor and resource matches are
    allowed only for a small set of meaningful cross-signal pairs. Fallback unions retain
    component-level business-process and workflow scopes, including across unscoped events,
    so a shared intermediary cannot bridge separately scoped incidents. Arbitrary common
    metadata and routine-only components do not join incidents.
    """
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")
    items = sorted(evidence, key=_time)
    parent = list(range(len(items)))
    scope_keys = ("business_process", "workflow_id")
    component_scopes: list[dict[str, set[str]]] = []
    for item in items:
        component_scopes.append({
            key: ({value} if (value := str(item.attributes.get(key, "")).strip().casefold()) else set())
            for key in scope_keys
        })

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int, *, fallback: bool = False) -> bool:
        a, b = find(left), find(right)
        if a != b:
            if fallback and any(
                len(component_scopes[a][key] | component_scopes[b][key]) > 1
                for key in scope_keys
            ):
                return False
            parent[b] = a
            for key in scope_keys:
                component_scopes[a][key].update(component_scopes[b][key])
            return True
        return True

    window = timedelta(minutes=window_minutes)
    by_id = {item.evidence_id: index for index, item in enumerate(items)}
    for index, item in enumerate(items):
        for source_id, target_id, _relationship in _explicit_links(item):
            left, right = by_id.get(source_id), by_id.get(target_id)
            if left is not None and right is not None and abs(_time(items[right]) - _time(items[left])) <= window:
                union(left, right)

    entity_index: dict[str, list[int]] = {}
    for index, item in enumerate(items):
        for entity in _identities(item):
            entity_index.setdefault(entity, []).append(index)
    for indices in entity_index.values():
        for offset, left in enumerate(indices):
            for right in indices[offset + 1:]:
                if _time(items[right]) - _time(items[left]) > window:
                    break
                first, second = items[left], items[right]
                event_pair = frozenset((first.event_type, second.event_type))
                same_actor = first.actor.upper() != "SYSTEM" and first.actor.casefold() == second.actor.casefold()
                if same_actor and event_pair in _ACTOR_SIGNAL_PAIRS:
                    union(left, right, fallback=True)
                elif (first.target.casefold() == second.target.casefold()
                      and event_pair in _RESOURCE_SIGNAL_PAIRS):
                    union(left, right, fallback=True)

    components: dict[int, list[Evidence]] = {}
    for index, item in enumerate(items):
        components.setdefault(find(index), []).append(item)
    incidents: list[Incident] = []
    for component in components.values():
        if len(component) < 2 or not any(item.event_type in SIGNAL_TYPES for item in component):
            continue
        ids = sorted(item.evidence_id for item in component)
        actors = tuple(sorted({item.actor for item in component if item.actor.upper() != "SYSTEM"}))
        resources = tuple(sorted({item.target for item in component}))
        criticality_order = {"unclassified": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        criticality = max((str(item.attributes.get("business_criticality", "unclassified")).lower()
                           for item in component), key=lambda value: criticality_order.get(value, 0), default="unclassified")
        process = next((str(item.attributes["business_process"]) for item in component
                        if item.attributes.get("business_process")), "")
        incidents.append(Incident(
            incident_id="INC-" + hashlib.sha256("|".join(ids).encode()).hexdigest()[:10].upper(),
            evidence=tuple(sorted(component, key=_time)), actors=actors,
            resources=resources, risk=score_evidence(component),
            business_criticality=criticality, business_process=process,
        ))
    criticality_order = {"unclassified": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return sorted(incidents, key=lambda case: (-case.risk.score,
                                                -criticality_order.get(case.business_criticality, 0),
                                                case.incident_id))
