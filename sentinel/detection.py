"""Deterministic access-baseline and batch-integrity detectors for synthetic evidence."""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import math
from typing import Iterable

from .evidence import Evidence


def _event_from(source: Evidence, evidence_id: str, event_type: str, summary: str,
                severity: str, target: str, attributes: dict[str, object]) -> Evidence:
    return Evidence(
        evidence_id=evidence_id, occurred_at=source.occurred_at,
        source_type="Sentinel synthetic detector", event_type=event_type,
        actor="SENTINEL", target=target, outcome="finding", severity=severity,
        summary=summary, attributes=attributes, synthetic=True,
    )


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect_suspicious_access(evidence: Iterable[Evidence], window_minutes: int = 15) -> list[Evidence]:
    """Compare sensitive reads with synthetic approved-actor and frequency baselines.

    A source access record is not pre-labeled anomalous. The detector derives findings when
    its actor is outside the approved baseline or when its read count exceeds the baseline.
    """
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")
    items = list(evidence)
    baselines = {item.target.casefold(): item for item in items if item.event_type == "ACCESS_BASELINE"}
    reads_by_key: dict[tuple[str, str], list[Evidence]] = {}
    for item in items:
        if item.event_type == "SENSITIVE_DATA_ACCESS" and item.attributes.get("sensitivity") == "restricted":
            reads_by_key.setdefault((item.target.casefold(), item.actor.casefold()), []).append(item)

    findings: list[Evidence] = []
    window = timedelta(minutes=window_minutes)
    for (resource_key, actor_key), reads in reads_by_key.items():
        reads.sort(key=lambda item: item.occurred_at)
        baseline = baselines.get(resource_key)
        approved = {str(actor).casefold() for actor in (baseline.attributes.get("approved_actors", []) if baseline else [])}
        baseline_limit = int(baseline.attributes.get("max_reads_per_15m", 1)) if baseline else 0
        max_reads = math.ceil(baseline_limit * window_minutes / 15) if baseline else 0
        reasons: set[str] = set()
        anomalous: set[str] = set()
        if baseline is None:
            reasons.add("no_approved_baseline_available")
            anomalous.update(item.evidence_id for item in reads)
        elif actor_key not in approved:
            reasons.add("actor_not_in_approved_baseline")
            anomalous.update(item.evidence_id for item in reads)
        if baseline:
            for item in reads:
                cluster = [other for other in reads
                           if abs((_parse_time(other.occurred_at) - _parse_time(item.occurred_at))) <= window]
                if len(cluster) > max_reads:
                    reasons.add("read_frequency_exceeds_baseline")
                    anomalous.update(other.evidence_id for other in cluster)
        if not anomalous:
            continue
        source_ids = sorted(anomalous)
        if baseline:
            source_ids.append(baseline.evidence_id)
        latest = max((item for item in reads if item.evidence_id in anomalous), key=lambda item: item.occurred_at)
        stable = "|".join(sorted(source_ids)) + "|" + "|".join(sorted(reasons))
        finding_id = "det-access-" + hashlib.sha256(stable.encode()).hexdigest()[:12]
        reason_text = " and ".join(sorted(reasons))
        findings.append(_event_from(
            latest, finding_id, "SUSPICIOUS_SENSITIVE_ACCESS",
            f"Sensitive dataset access by {latest.actor} violated baseline: {reason_text}.", "high", latest.target,
            {"source_evidence_ids": source_ids, "access_evidence_ids": sorted(anomalous),
             "baseline_evidence_id": baseline.evidence_id if baseline else None,
             "detector_reasons": sorted(reasons), "business_criticality": latest.attributes.get("business_criticality", "unclassified"),
             "business_process": latest.attributes.get("business_process", "")}))
    return findings


def detect_incomplete_batches(evidence: Iterable[Evidence]) -> list[Evidence]:
    """Find record or control-total shortfalls even when batch return code is zero."""
    findings: list[Evidence] = []
    for item in evidence:
        if item.event_type != "BATCH_JOB_COMPLETE":
            continue
        attrs = item.attributes
        try:
            expected = int(attrs["expected_records"])
            processed = int(attrs["processed_records"])
            return_code = int(attrs["return_code"])
        except (KeyError, TypeError, ValueError):
            continue
        expected_total = attrs.get("expected_control_total")
        processed_total = attrs.get("processed_control_total")
        count_mismatch = processed != expected
        record_discrepancy = abs(expected - processed)
        total_mismatch = expected_total is not None and processed_total is not None and float(expected_total) != float(processed_total)
        if not (count_mismatch or total_mismatch):
            continue
        details = []
        if count_mismatch:
            difference_label = "shortfall" if processed < expected else "excess"
            details.append(f"processed {processed:,} of {expected:,} expected records "
                           f"({record_discrepancy:,} record {difference_label})")
        if total_mismatch:
            details.append(f"control total {processed_total} differs from expected {expected_total}")
        finding_id = "det-batch-" + hashlib.sha256(item.evidence_id.encode()).hexdigest()[:12]
        findings.append(_event_from(
            item, finding_id, "BATCH_INTEGRITY_MISMATCH",
            f"Job {attrs.get('job_id', item.target)} ended RC={return_code} but " + "; ".join(details) + ".",
            "critical", str(attrs.get("output_dataset", item.target)),
            {"source_evidence_ids": [item.evidence_id], "batch_evidence_id": item.evidence_id,
             "return_code": return_code, "expected_records": expected, "processed_records": processed,
             "record_discrepancy": record_discrepancy,
             "expected_control_total": expected_total, "processed_control_total": processed_total,
             "program_evidence_id": attrs.get("program_evidence_id"),
             "source_access_evidence_ids": attrs.get("source_access_evidence_ids", []),
             "output_dataset_evidence_id": attrs.get("output_dataset_evidence_id"),
             "business_criticality": attrs.get("business_criticality", "unclassified"),
             "business_process": attrs.get("business_process", "")}))
    return findings


def enrich_with_findings(evidence: Iterable[Evidence]) -> list[Evidence]:
    """Append detector findings to source evidence for correlation, storage, and display."""
    source = list(evidence)
    findings = detect_suspicious_access(source) + detect_incomplete_batches(source)
    return sorted(source + findings, key=lambda item: item.occurred_at)
