import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from sentinel.correlation import correlate_incidents, dependency_edges
from sentinel.detection import (detect_incomplete_batches, detect_suspicious_access,
                                enrich_with_findings)
from sentinel.evidence import generate_demo_events, normalize_event
from sentinel.investigation import deterministic_investigation
from sentinel.storage import SentinelStore
from web_app import render_dashboard


class SyntheticPaymentScenarioTests(unittest.TestCase):
    def setUp(self):
        self.seed = 2026
        self.now = datetime(2026, 10, 17, tzinfo=timezone.utc)
        self.source = generate_demo_events(seed=self.seed, now=self.now)
        self.evidence = enrich_with_findings(self.source)
        self.incidents = correlate_incidents(self.evidence, window_minutes=90)
        self.incident = next(case for case in self.incidents
                             if case.business_process == "Payment settlement")
        self.by_id = {event.evidence_id: event for event in self.incident.evidence}

    def test_rc_zero_batch_derives_exact_1000_record_shortfall(self):
        job = next(event for event in self.source if event.event_type == "BATCH_JOB_COMPLETE"
                   and event.attributes.get("business_process") == "Payment settlement")
        self.assertEqual(job.attributes["return_code"], 0)
        self.assertEqual(job.attributes["expected_records"], 100000)
        self.assertEqual(job.attributes["processed_records"], 99000)

        findings = detect_incomplete_batches([job])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].attributes["record_discrepancy"], 1000)
        self.assertIn("1,000 record shortfall", findings[0].summary)
        self.assertEqual(findings[0].attributes["return_code"], 0)

    def test_complete_batch_is_not_flagged(self):
        job = next(event for event in self.source if event.event_type == "BATCH_JOB_COMPLETE"
                   and event.attributes.get("business_process") == "Payment settlement")
        complete = replace(job, attributes={**job.attributes,
                                            "expected_records": 99000,
                                            "processed_records": 99000,
                                            "expected_control_total": 52074000.0,
                                            "processed_control_total": 52074000.0})
        self.assertEqual(detect_incomplete_batches([complete]), [])

    def test_payment_access_detector_keeps_approved_actor_normal_and_flags_operator(self):
        findings = [item for item in detect_suspicious_access(self.source)
                    if item.attributes.get("business_process") == "Payment settlement"]
        self.assertEqual(len(findings), 1)
        self.assertIn("OPSUSER", findings[0].summary)
        self.assertNotIn("PAYMENTSVC", findings[0].summary)
        self.assertIn("actor_not_in_approved_baseline", findings[0].attributes["detector_reasons"])

    def test_payment_dependencies_correlate_program_access_job_dataset_and_settlement(self):
        events = self.incident.evidence
        program = next(item for item in events if item.event_type == "PROGRAM_CHANGE"
                       and item.attributes.get("business_process") == "Payment settlement")
        access = next(item for item in events if item.event_type == "SENSITIVE_DATA_ACCESS"
                      and item.target == "PAYMENTS.PENDING" and item.actor == "OPSUSER")
        batch = next(item for item in events if item.event_type == "BATCH_JOB_COMPLETE"
                     and item.attributes.get("business_process") == "Payment settlement")
        dataset = next(item for item in events if item.event_type == "OUTPUT_DATASET_WRITTEN"
                       and item.target == "PAYMENTS.SETTLEMENT.OUT")
        settlement = next(item for item in events if item.event_type == "SETTLEMENT_CONSUMER_QUEUED")

        edges = {(edge.source_evidence_id, edge.target_evidence_id)
                 for edge in dependency_edges(self.incident)}
        for source, target in ((program, access), (access, batch), (program, batch),
                               (batch, dataset), (dataset, settlement)):
            self.assertIn((source.evidence_id, target.evidence_id), edges)
        incident_types = {item.event_type for item in events}
        self.assertTrue({"SUSPICIOUS_SENSITIVE_ACCESS", "BATCH_INTEGRITY_MISMATCH",
                         "SETTLEMENT_CONSUMER_QUEUED"}.issubset(incident_types))
        self.assertEqual(self.incident.business_criticality, "critical")
        self.assertFalse(any(item.event_type == "CHECKSUM_MISMATCH" for item in events))

    def test_payment_and_payroll_workflows_are_not_merged_by_shared_operator(self):
        payroll = next(case for case in self.incidents if case.business_process == "Payroll close")
        bridge = next(item for item in self.evidence
                      if item.event_type == "RESTRICTED_READ" and item.actor == "OPSUSER"
                      and item.target == "PAYROLL.PRD")
        payment_access = next(item for item in self.source
                              if item.event_type == "SENSITIVE_DATA_ACCESS"
                              and item.actor == "OPSUSER" and item.target == "PAYMENTS.PENDING")
        payroll_access = next(item for item in self.source
                              if item.event_type == "SENSITIVE_DATA_ACCESS"
                              and item.actor == "OPSUSER" and item.target == "PAYROLL.INPUT")
        # Legacy payroll signals are now explicitly scoped, so actor coincidence
        # cannot attach this payroll evidence to the payment incident.
        self.assertEqual(bridge.attributes["business_process"], "Payroll close")
        self.assertEqual(bridge.attributes["workflow_id"], f"PAYROLL-CLOSE-{self.seed:04d}")
        self.assertEqual(bridge.actor, payment_access.actor)
        self.assertEqual(bridge.actor, payroll_access.actor)
        self.assertEqual({bridge.event_type, payment_access.event_type},
                         {"RESTRICTED_READ", "SENSITIVE_DATA_ACCESS"})
        self.assertEqual({bridge.event_type, payroll_access.event_type},
                         {"RESTRICTED_READ", "SENSITIVE_DATA_ACCESS"})
        self.assertLessEqual(
            abs((datetime.fromisoformat(bridge.occurred_at)
                 - datetime.fromisoformat(payment_access.occurred_at)).total_seconds()),
            90 * 60,
        )
        payment_ids = {item.evidence_id for item in self.incident.evidence}
        payroll_ids = {item.evidence_id for item in payroll.evidence}
        self.assertTrue(payment_ids)
        self.assertTrue(payroll_ids)
        self.assertTrue(payment_ids.isdisjoint(payroll_ids))
        self.assertIn(bridge.evidence_id, payroll_ids)
        self.assertNotIn(bridge.evidence_id, payment_ids)

    def test_unscoped_intermediary_cannot_merge_conflicting_scoped_components(self):
        common = {"timestamp": "2026-10-17T00:00:00+00:00", "actor": "SHAREDOP",
                  "outcome": "observed", "severity": "high"}
        events = [
            normalize_event({**common, "id": "payroll-program", "source": "change",
                             "event": "PROGRAM_CHANGE", "target": "PAYROLL.POST",
                             "summary": "Payroll change", "attributes": {
                                 "business_process": "Payroll close", "workflow_id": "PAYROLL-WF"}}),
            normalize_event({**common, "id": "payroll-access", "source": "security",
                             "event": "SENSITIVE_DATA_ACCESS", "target": "PAYROLL.INPUT",
                             "summary": "Payroll read", "attributes": {
                                 "business_process": "Payroll close", "workflow_id": "PAYROLL-WF"}}),
            normalize_event({**common, "id": "payment-program", "source": "change",
                             "event": "PROGRAM_CHANGE", "target": "PAYMENT.POST",
                             "summary": "Payment change", "attributes": {
                                 "business_process": "Payment settlement", "workflow_id": "PAYMENT-WF"}}),
            normalize_event({**common, "id": "payment-access", "source": "security",
                             "event": "SENSITIVE_DATA_ACCESS", "target": "PAYMENTS.PENDING",
                             "summary": "Payment read", "attributes": {
                                 "business_process": "Payment settlement", "workflow_id": "PAYMENT-WF"}}),
            normalize_event({**common, "id": "unscoped-intermediary", "source": "security",
                             "event": "RESTRICTED_READ", "target": "UNSCOPED.RESOURCE",
                             "summary": "Unscoped intermediary"}),
        ]

        incidents = correlate_incidents(events, window_minutes=90)
        self.assertEqual(len(incidents), 2)
        grouped = {incident.business_process: {item.evidence_id for item in incident.evidence}
                   for incident in incidents}
        self.assertEqual(set(grouped), {"Payroll close", "Payment settlement"})
        self.assertTrue({"payroll-program", "payroll-access"}.issubset(grouped["Payroll close"]))
        self.assertTrue({"payment-program", "payment-access"}.issubset(grouped["Payment settlement"]))
        self.assertFalse(any({"payroll-program", "payment-program"}.issubset(ids)
                             for ids in grouped.values()))

    def test_same_workflow_restricted_read_and_checksum_still_correlate(self):
        source = generate_demo_events(seed=self.seed, now=self.now)
        pair = [item for item in source
                if item.event_type in {"RESTRICTED_READ", "CHECKSUM_MISMATCH"}]
        incidents = correlate_incidents(pair, window_minutes=90)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].business_process, "Payroll close")
        self.assertEqual({item.event_type for item in incidents[0].evidence},
                         {"RESTRICTED_READ", "CHECKSUM_MISMATCH"})

    def test_unrelated_events_with_shared_actor_resource_do_not_correlate(self):
        common = {"timestamp": "2026-10-17T00:00:00+00:00", "actor": "SAMEOP",
                  "target": "PAYMENTS.SETTLEMENT.OUT", "outcome": "observed",
                  "severity": "high", "workflow_id": "SAME-WORKFLOW"}
        program = normalize_event({**common, "id": "unrelated-payment-program", "source": "audit",
                                   "event": "PROGRAM_CHANGE", "summary": "Unrelated program change"})
        integrity = normalize_event({**common, "id": "unrelated-payment-integrity", "source": "integrity",
                                     "event": "CHECKSUM_MISMATCH", "summary": "Unrelated checksum alert"})
        self.assertEqual(correlate_incidents([program, integrity], window_minutes=90), [])

    def test_investigation_cites_incident_evidence_and_limits_causality_and_impact(self):
        claims = deterministic_investigation(self.incident)
        valid_ids = set(self.by_id)
        self.assertTrue(claims)
        for claim in claims:
            self.assertTrue(claim["evidence_ids"])
            self.assertTrue(set(claim["evidence_ids"]).issubset(valid_ids))

        text = " ".join(claim["conclusion"] for claim in claims)
        self.assertIn("Hypothesis for investigation", text)
        self.assertIn("does not prove", text)
        self.assertIn("1,000-record shortfall", text)
        self.assertIn("settlement completeness", text)
        self.assertIn("payment was missed", text)
        cited = {evidence_id for claim in claims for evidence_id in claim["evidence_ids"]}
        for event_type in ("PROGRAM_CHANGE", "SUSPICIOUS_SENSITIVE_ACCESS",
                           "BATCH_INTEGRITY_MISMATCH", "SETTLEMENT_CONSUMER_QUEUED"):
            event = next(item for item in self.incident.evidence if item.event_type == event_type)
            self.assertIn(event.evidence_id, cited)

    def test_dashboard_renders_payment_chain_and_recommendation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SentinelStore(Path(directory) / "payment.db")
            store.save_demo_snapshot(self.seed, 90, self.evidence, self.incidents)
            html = render_dashboard(store, "test-csrf-token", self.incident.incident_id).decode("utf-8")
        self.assertIn("Payment settlement", html)
        self.assertIn("100000", html)
        self.assertIn("99000", html)
        self.assertIn("SETTLEMENT_CONSUMER_QUEUED", html)
        self.assertIn("hold-payment-settlement", html)
        for event in self.incident.evidence:
            self.assertIn(event.evidence_id, html)

    def test_payment_approval_and_rejection_preserve_audit_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SentinelStore(Path(directory) / "payment.db")
            store.save_demo_snapshot(self.seed, 90, self.evidence, self.incidents)
            recommendation = next(item for item in store.list_recommendations(self.incident.incident_id)
                                  if item.action_id == "hold-payment-settlement")
            self.assertTrue(set(recommendation.evidence_ids).intersection(self.by_id))

            with self.assertRaises(PermissionError):
                store.record_decision(self.incident.incident_id, recommendation.action_id,
                                      "Approved", "operator", confirmed=False)
            approved = store.record_decision(self.incident.incident_id, recommendation.action_id,
                                             "Approved", "operator", confirmed=True)
            self.assertEqual(approved.execution_status, "Not executed")

            # Re-upserting the seeded scenario retains the existing audit row.
            store.save_demo_snapshot(self.seed, 90, self.evidence, self.incidents)
            rejected = store.record_decision(self.incident.incident_id, recommendation.action_id,
                                             "Rejected", "reviewer", confirmed=True)
            self.assertEqual(rejected.approval_status, "Rejected")
            self.assertEqual(rejected.execution_status, "Not executed")
            history = store.list_approval_history(self.incident.incident_id)
            self.assertEqual([row["decision"] for row in history], ["Rejected", "Approved"])
            current = next(item for item in store.list_recommendations(self.incident.incident_id)
                           if item.action_id == recommendation.action_id)
            self.assertEqual(current.execution_status, "Not executed")


if __name__ == "__main__":
    unittest.main()
