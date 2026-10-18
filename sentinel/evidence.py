"""Synthetic source events normalized to a shared evidence schema."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import random
from typing import Any
import uuid

@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    occurred_at: str
    source_type: str
    event_type: str
    actor: str
    target: str
    outcome: str
    severity: str
    summary: str
    attributes: dict[str, Any]
    synthetic: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

def normalize_event(raw: dict[str, Any]) -> Evidence:
    """Map a source-shaped event into the common evidence schema."""
    required = ("timestamp", "source", "event", "actor", "target", "outcome", "severity", "summary")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError(f"Missing event fields: {', '.join(missing)}")
    try:
        dt = datetime.fromisoformat(str(raw["timestamp"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be an ISO-8601 datetime") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return Evidence(
        evidence_id=str(raw.get("id") or f"ev-{uuid.uuid4().hex[:10]}"),
        occurred_at=dt.astimezone(timezone.utc).isoformat(),
        source_type=str(raw["source"]), event_type=str(raw["event"]),
        actor=str(raw["actor"]), target=str(raw["target"]),
        outcome=str(raw["outcome"]), severity=str(raw["severity"]).lower(),
        summary=str(raw["summary"]), attributes=dict(raw.get("attributes") or {}),
        synthetic=True,
    )

def generate_demo_events(seed: int = 42, now: datetime | None = None) -> list[Evidence]:
    """Generate repeatable synthetic events, including a correlated threat story."""
    rng = random.Random(seed)
    base = now or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    base = base.astimezone(timezone.utc)
    raw: list[dict[str, Any]] = []
    def add(minutes_ago: int, source: str, event: str, actor: str, target: str,
            outcome: str, severity: str, summary: str, **attrs: Any) -> None:
        raw.append({"id": f"demo-{seed}-{len(raw) + 1:03d}",
                    "timestamp": (base - timedelta(minutes=minutes_ago)).isoformat(),
                    "source": source, "event": event, "actor": actor,
                    "target": target, "outcome": outcome, "severity": severity,
                    "summary": summary, "attributes": attrs})
    actors = ["BATCH01", "OPSUSER", "DBA07", "PAYROLL", "SYSOP2"]
    for i in range(14):
        actor = rng.choice(actors)
        add(rng.randint(5, 360), rng.choice(["SMF-style security", "config audit", "batch scheduler", "data integrity"]),
            rng.choice(["JOB_COMPLETE", "DATASET_READ", "CONFIG_CHECK", "AUTH_SUCCESS"]),
            actor, rng.choice(["PAYROLL.PRD", "SYS1.PARMLIB", "CUSTOMER.MASTER", "NIGHTLY.BATCH"]),
            "success", "low", "Routine synthetic operational activity", job_id=f"JOB{rng.randint(100,999)}")
    workflow_id = f"PAYROLL-CLOSE-{seed:04d}"
    baseline_id = f"demo-{seed}-{len(raw) + 1:03d}"
    add(120, "synthetic access baseline", "ACCESS_BASELINE", "SYSTEM", "PAYROLL.INPUT", "active", "info",
        "Synthetic baseline for the restricted payroll input dataset",
        baseline_version="PAYROLL-ACCESS-BASELINE-v1", sensitivity="restricted",
        approved_actors=["PAYROLLB"], max_reads_per_15m=1,
        workflow_id=workflow_id, business_process="Payroll close")
    add(70, "SMF-style security", "SENSITIVE_DATA_ACCESS", "PAYROLLB", "PAYROLL.INPUT", "success", "low",
        "Approved payroll service account read the restricted input dataset",
        sensitivity="restricted", records=10000, baseline_id=baseline_id,
        workflow_id=workflow_id, business_process="Payroll close")
    add(38, "SMF-style security", "AUTH_FAILURE_BURST", "OPSUSER", "PAYROLL.PRD", "denied", "high",
        "Repeated failed access to a restricted payroll dataset", failures=7, source_ip="192.0.2.44",
        workflow_id=workflow_id, business_process="Payroll close")
    add(31, "config audit", "PRIVILEGE_CHANGE", "OPSUSER", "SYS1.PARMLIB", "changed", "critical",
        "Elevated access profile changed outside the maintenance window", change="SPECIAL=YES", change_ticket=None,
        workflow_id=workflow_id, business_process="Payroll close")
    add(24, "batch scheduler", "UNSCHEDULED_JOB", "OPSUSER", "PAYROLL.EXPORT", "started", "high",
        "Unscheduled export job launched by the same actor", job_id="JOB884", records=18420,
        workflow_id=workflow_id, business_process="Payroll close")
    add(18, "data integrity", "CHECKSUM_MISMATCH", "SYSTEM", "PAYROLL.PRD", "alert", "critical",
        "Dataset checksum differs from the prior verified baseline", expected="7a31…", observed="c90f…",
        workflow_id=workflow_id, business_process="Payroll close")
    add(12, "SMF-style security", "RESTRICTED_READ", "OPSUSER", "PAYROLL.PRD", "success", "high",
        "Restricted dataset read after privilege change", records=18420,
        workflow_id=workflow_id, business_process="Payroll close")
    program_id = f"demo-{seed}-{len(raw) + 1:03d}"
    access_one_id = f"demo-{seed}-{len(raw) + 2:03d}"
    access_two_id = f"demo-{seed}-{len(raw) + 3:03d}"
    job_evidence_id = f"demo-{seed}-{len(raw) + 4:03d}"
    output_evidence_id = f"demo-{seed}-{len(raw) + 5:03d}"
    job_id = f"JOB-PCLOSE-{seed:04d}"
    output_dataset = "PAYROLL.CLOSE.OUT"
    add(48, "z/OS program change audit", "PROGRAM_CHANGE", "OPSUSER", "PAYROLL.CLOSE",
        "changed", "high", "Synthetic payroll close load-module changed outside the approved baseline",
        program_name="PAYROLL.CLOSE", change_reference=f"CHG-SYN-{seed:04d}-17",
        approval_status="unapproved", baseline_status="not_in_approved_baseline",
        workflow_id=workflow_id, downstream_job_evidence_id=job_evidence_id,
        downstream_dataset_evidence_id=output_evidence_id,
        business_criticality="critical", business_process="Payroll close")
    add(42, "SMF-style security", "SENSITIVE_DATA_ACCESS", "OPSUSER", "PAYROLL.INPUT", "success", "medium",
        "Operator account read the restricted payroll input dataset",
        sensitivity="restricted", records=10000, baseline_id=baseline_id,
        program_evidence_id=program_id, workflow_id=workflow_id,
        business_criticality="critical", business_process="Payroll close")
    add(41, "SMF-style security", "SENSITIVE_DATA_ACCESS", "OPSUSER", "PAYROLL.INPUT", "success", "medium",
        "Second restricted payroll input read within the monitoring interval",
        sensitivity="restricted", records=10000, baseline_id=baseline_id,
        program_evidence_id=program_id, workflow_id=workflow_id,
        business_criticality="critical", business_process="Payroll close")
    add(22, "z/OS batch scheduler", "BATCH_JOB_COMPLETE", "OPSUSER", job_id, "completed", "medium",
        "Payroll close job ended with RC=0; job and control totals captured",
        job_id=job_id, return_code=0, expected_records=10000, processed_records=6400,
        expected_control_total=1250000.00, processed_control_total=800000.00,
        program_name="PAYROLL.CLOSE", program_evidence_id=program_id,
        source_access_evidence_ids=[access_one_id, access_two_id],
        output_dataset=output_dataset, output_dataset_evidence_id=output_evidence_id,
        workflow_id=workflow_id, business_criticality="critical", business_process="Payroll close")
    add(21, "z/OS dataset catalog", "OUTPUT_DATASET_WRITTEN", job_id, output_dataset, "written", "low",
        "Payroll close job wrote its synthetic output dataset",
        job_id=job_id, source_job_evidence_id=job_evidence_id,
        program_evidence_id=program_id, workflow_id=workflow_id,
        expected_records=10000, processed_records=6400,
        business_criticality="critical", business_process="Payroll close")

    # Separate synthetic payment-settlement chain used by the finalized demo.
    payment_workflow = f"PAYMENT-SETTLEMENT-{seed:04d}"
    payment_baseline_id = f"demo-{seed}-{len(raw) + 1:03d}"
    add(90, "synthetic access baseline", "ACCESS_BASELINE", "SYSTEM", "PAYMENTS.PENDING", "active", "info",
        "Synthetic approved-actor baseline for the pending payment dataset",
        baseline_version="PAYMENTS-ACCESS-BASELINE-v1", sensitivity="restricted",
        approved_actors=["PAYMENTSVC"], max_reads_per_15m=1,
        workflow_id=payment_workflow, business_criticality="critical",
        business_process="Payment settlement")
    add(80, "SMF-style security", "SENSITIVE_DATA_ACCESS", "PAYMENTSVC", "PAYMENTS.PENDING",
        "success", "low", "Approved payment service account read the restricted payment input dataset",
        sensitivity="restricted", records=100000, baseline_id=payment_baseline_id,
        workflow_id=payment_workflow, business_criticality="critical",
        business_process="Payment settlement")
    payment_program_id = f"demo-{seed}-{len(raw) + 1:03d}"
    payment_access_id = f"demo-{seed}-{len(raw) + 2:03d}"
    payment_job_evidence_id = f"demo-{seed}-{len(raw) + 3:03d}"
    payment_output_id = f"demo-{seed}-{len(raw) + 4:03d}"
    settlement_evidence_id = f"demo-{seed}-{len(raw) + 5:03d}"
    payment_job_id = f"JOB-PAYSETTLE-{seed:04d}"
    payment_output_dataset = "PAYMENTS.SETTLEMENT.OUT"
    settlement_consumer = "SETTLEMENT.CLEARING.CONSUMER"
    add(65, "z/OS program change audit", "PROGRAM_CHANGE", "RELEASEOPS", "PAYMENT.POST.CBL",
        "changed", "critical", "Synthetic payment-processing COBOL program changed outside the approved release baseline",
        program_name="PAYMENT.POST.CBL", language="COBOL",
        change_reference=f"CHG-SYN-PAY-{seed:04d}-09", approval_status="unapproved",
        baseline_status="not_in_approved_baseline", input_dataset="PAYMENTS.PENDING",
        output_dataset=payment_output_dataset, workflow_id=payment_workflow,
        downstream_job_evidence_id=payment_job_evidence_id,
        business_criticality="critical", business_process="Payment settlement")
    add(58, "SMF-style security", "SENSITIVE_DATA_ACCESS", "OPSUSER", "PAYMENTS.PENDING",
        "success", "high", "Operator identity outside the approved baseline read the restricted payment input dataset",
        sensitivity="restricted", records=100000, baseline_id=payment_baseline_id,
        program_evidence_id=payment_program_id, workflow_id=payment_workflow,
        business_criticality="critical", business_process="Payment settlement")
    add(25, "z/OS batch scheduler", "BATCH_JOB_COMPLETE", "PAYBATCH", payment_job_id,
        "completed", "high", "Payment settlement batch ended with RC=0; expected and processed record totals were captured",
        job_id=payment_job_id, return_code=0, expected_records=100000, processed_records=99000,
        expected_control_total=52600000.00, processed_control_total=52074000.00,
        program_name="PAYMENT.POST.CBL", program_evidence_id=payment_program_id,
        source_access_evidence_ids=[payment_access_id],
        output_dataset=payment_output_dataset, output_dataset_evidence_id=payment_output_id,
        workflow_id=payment_workflow, business_criticality="critical",
        business_process="Payment settlement")
    add(24, "z/OS dataset catalog", "OUTPUT_DATASET_WRITTEN", payment_job_id,
        payment_output_dataset, "written", "medium",
        "Payment batch wrote its output dataset for the downstream settlement consumer",
        job_id=payment_job_id, source_job_evidence_id=payment_job_evidence_id,
        program_evidence_id=payment_program_id,
        downstream_settlement_evidence_id=settlement_evidence_id,
        expected_records=100000, processed_records=99000,
        business_criticality="critical", business_process="Payment settlement")
    add(20, "synthetic settlement monitor", "SETTLEMENT_CONSUMER_QUEUED", settlement_consumer,
        payment_output_dataset, "queued", "high",
        "Synthetic downstream settlement consumer queued the payment output dataset",
        consumer=settlement_consumer, source_dataset_evidence_id=payment_output_id,
        source_job_evidence_id=payment_job_evidence_id,
        workflow_id=payment_workflow, business_criticality="critical",
        business_process="Payment settlement")
    return sorted([normalize_event(item) for item in raw], key=lambda e: e.occurred_at)
