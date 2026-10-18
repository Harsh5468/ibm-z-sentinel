import unittest
from dataclasses import replace
from datetime import datetime, timezone

from sentinel.correlation import correlate_incidents, dependency_edges
from sentinel.detection import detect_incomplete_batches, detect_suspicious_access, enrich_with_findings
from sentinel.evidence import generate_demo_events, normalize_event
from sentinel.investigation import deterministic_investigation
from sentinel.remediation import recommend_remediations, set_approval


class PaymentSettlementScenarioTests(unittest.TestCase):
    def setUp(self):
        source = generate_demo_events(seed=2026, now=datetime(2026, 10, 17, tzinfo=timezone.utc))
        self.evidence = enrich_with_findings(source)
        self.incidents = correlate_incidents(self.evidence, window_minutes=90)
        self.incident = next(case for case in self.incidents if case.business_process == "Payment settlement")
        self.by_id = {event.evidence_id: event for event in self.incident.evidence}

    def test_complete_synthetic_story_is_business_critical_and_linked(self):
        program = next(event for event in self.incident.evidence if event.event_type == "PROGRAM_CHANGE")
        accesses = [event for event in self.incident.evidence if event.event_type == "SENSITIVE_DATA_ACCESS"
                    and event.actor == "OPSUSER" and event.target == "PAYMENTS.PENDING"]
        batch = next(event for event in self.incident.evidence if event.event_type == "BATCH_JOB_COMPLETE")
        output = next(event for event in self.incident.evidence if event.event_type == "OUTPUT_DATASET_WRITTEN")
        access_alert = next(event for event in self.incident.evidence
                            if event.event_type == "SUSPICIOUS_SENSITIVE_ACCESS")
        batch_alert = next(event for event in self.incident.evidence
                           if event.event_type == "BATCH_INTEGRITY_MISMATCH")

        self.assertTrue(program.evidence_id)
        self.assertEqual(program.attributes["program_name"], "PAYMENT.POST.CBL")
        self.assertEqual(program.attributes["language"], "COBOL")
        self.assertTrue(program.attributes["change_reference"])
        self.assertEqual(program.attributes["approval_status"], "unapproved")
        self.assertEqual(program.attributes["baseline_status"], "not_in_approved_baseline")
        self.assertEqual(len(accesses), 1)
        self.assertEqual(batch.attributes["return_code"], 0)
        self.assertEqual(batch.attributes["expected_records"], 100000)
        self.assertEqual(batch.attributes["processed_records"], 99000)
        self.assertEqual(batch_alert.attributes["record_discrepancy"], 1000)
        self.assertNotEqual(batch.attributes["expected_control_total"], batch.attributes["processed_control_total"])
        self.assertIn(batch.evidence_id, batch_alert.attributes["source_evidence_ids"])
        self.assertEqual(batch_alert.attributes["return_code"], 0)
        self.assertEqual(output.target, "PAYMENTS.SETTLEMENT.OUT")
        self.assertEqual(output.attributes["source_job_evidence_id"], batch.evidence_id)
        settlement = next(event for event in self.incident.evidence
                          if event.event_type == "SETTLEMENT_CONSUMER_QUEUED")
        self.assertEqual(self.incident.business_criticality, "critical")
        self.assertEqual(self.incident.risk.band, "critical")
        self.assertIn(access_alert, self.incident.evidence)
        self.assertEqual(len({event.evidence_id for event in self.incident.evidence}), len(self.incident.evidence))

        edges = dependency_edges(self.incident)
        pairs = {(edge.source_evidence_id, edge.target_evidence_id) for edge in edges}
        self.assertIn((program.evidence_id, batch.evidence_id), pairs)
        self.assertIn((batch.evidence_id, output.evidence_id), pairs)
        self.assertIn((program.evidence_id, accesses[0].evidence_id), pairs)
        self.assertIn((output.evidence_id, settlement.evidence_id), pairs)
        self.assertEqual(self.incident.business_process, "Payment settlement")
        self.assertTrue(all(item.synthetic for item in self.incident.evidence))

    def test_access_detector_distinguishes_baseline_actor_from_unusual_actor(self):
        findings = detect_suspicious_access(generate_demo_events(
            seed=2026, now=datetime(2026, 10, 17, tzinfo=timezone.utc)))
        self.assertTrue(findings)
        findings = [finding for finding in findings
                    if finding.attributes.get("business_process") == "Payment settlement"]
        self.assertEqual(len(findings), 1)
        self.assertTrue(all("OPSUSER" in finding.summary for finding in findings))
        self.assertFalse(any("PAYMENTSVC" in finding.summary for finding in findings))
        self.assertTrue(all(finding.attributes["baseline_evidence_id"] in self.by_id for finding in findings))

    def test_batch_detector_distinguishes_complete_from_incomplete_rc_zero(self):
        job = next(event for event in self.incident.evidence if event.event_type == "BATCH_JOB_COMPLETE"
                   and event.attributes.get("business_process") == "Payment settlement")
        complete = replace(job, attributes={**job.attributes, "expected_records": 99000,
                                            "processed_records": 99000,
                                            "expected_control_total": 52074000.0,
                                            "processed_control_total": 52074000.0})
        self.assertEqual(detect_incomplete_batches([complete]), [])
        findings = detect_incomplete_batches([job])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].attributes["return_code"], 0)
        self.assertEqual(findings[0].attributes["record_discrepancy"], 1000)

    def test_approved_actor_frequency_pattern_is_detected(self):
        source = generate_demo_events(seed=2026, now=datetime(2026, 10, 17, tzinfo=timezone.utc))
        baseline = next(event for event in source if event.event_type == "ACCESS_BASELINE"
                        and event.target == "PAYMENTS.PENDING")
        normal_read = next(event for event in source if event.event_type == "SENSITIVE_DATA_ACCESS"
                           and event.actor == "PAYMENTSVC")
        repeated_read = replace(normal_read, evidence_id="synthetic-frequency-read-2",
                                occurred_at="2026-10-16T22:50:00+00:00")
        normal_read = replace(normal_read, occurred_at="2026-10-16T22:55:00+00:00")
        findings = detect_suspicious_access([baseline, normal_read, repeated_read])
        self.assertEqual(len(findings), 1)
        self.assertIn("read_frequency_exceeds_baseline", findings[0].attributes["detector_reasons"])

    def test_unrelated_events_do_not_correlate_from_shared_actor_or_resource(self):
        at = "2026-10-17T00:00:00+00:00"
        common = {"timestamp": at, "actor": "SAMEUSER", "target": "SAME.DATASET", "outcome": "observed"}
        program = normalize_event({**common, "id": "unrelated-program", "source": "audit",
                                   "event": "PROGRAM_CHANGE", "severity": "high", "summary": "change"})
        checksum = normalize_event({**common, "id": "unrelated-checksum", "source": "integrity",
                                    "event": "CHECKSUM_MISMATCH", "severity": "high", "summary": "mismatch"})
        self.assertEqual(correlate_incidents([program, checksum], window_minutes=90), [])

    def test_deterministic_claims_cite_exact_supporting_event_ids(self):
        claims = deterministic_investigation(self.incident)
        allowed = set(self.by_id)
        self.assertTrue(claims)
        for claim in claims:
            self.assertTrue(claim["evidence_ids"])
            self.assertTrue(set(claim["evidence_ids"]).issubset(allowed))
        program = next(event for event in self.incident.evidence if event.event_type == "PROGRAM_CHANGE")
        anomaly = next(event for event in self.incident.evidence
                       if event.event_type == "SUSPICIOUS_SENSITIVE_ACCESS")
        incomplete = next(event for event in self.incident.evidence
                          if event.event_type == "BATCH_INTEGRITY_MISMATCH")
        cited = {evidence_id for claim in claims for evidence_id in claim["evidence_ids"]}
        self.assertIn(program.evidence_id, cited)
        self.assertIn(anomaly.evidence_id, cited)
        self.assertIn(incomplete.evidence_id, cited)

    def test_scenario_response_is_confirmation_gated_and_non_executing(self):
        recommendation = next(item for item in recommend_remediations(self.incident)
                              if item.action_id == "hold-payment-settlement")
        with self.assertRaises(PermissionError):
            set_approval([recommendation], recommendation.action_id, "Approved")
        approved = set_approval([recommendation], recommendation.action_id, "Approved", confirmed=True)[0]
        self.assertEqual(approved.approval_status, "Approved")
        self.assertEqual(approved.execution_status, "Not executed")
        self.assertTrue(set(approved.evidence_ids).intersection(
            event.evidence_id for event in self.incident.evidence
            if event.event_type == "BATCH_INTEGRITY_MISMATCH"))


if __name__ == "__main__":
    unittest.main()
