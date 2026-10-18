import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from sentinel.correlation import correlate_incidents
from sentinel.evidence import generate_demo_events
from sentinel.investigation import deterministic_investigation, investigate
from sentinel.remediation import recommend_remediations, set_approval


class IncidentWorkflowTests(unittest.TestCase):
    def setUp(self):
        events = generate_demo_events(seed=3, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.incidents = correlate_incidents(events)
        self.legacy_incident = next(case for case in self.incidents
                                    if {"PRIVILEGE_CHANGE", "UNSCHEDULED_JOB", "CHECKSUM_MISMATCH"}.issubset(
                                        {event.event_type for event in case.evidence}))

    def test_cross_signal_events_correlate_by_identity_resource_and_time(self):
        self.assertTrue(self.incidents)
        incident = self.legacy_incident
        kinds = {event.event_type for event in incident.evidence}
        self.assertTrue({"PRIVILEGE_CHANGE", "UNSCHEDULED_JOB", "CHECKSUM_MISMATCH"}.issubset(kinds))
        self.assertIn("OPSUSER", incident.actors)
        self.assertIn("PAYROLL.PRD", incident.resources)

    def test_correlation_respects_time_window_and_empty_input(self):
        self.assertEqual(correlate_incidents([], 90), [])
        events = [event for event in self.legacy_incident.evidence
                  if event.event_type in {"AUTH_FAILURE_BURST", "PRIVILEGE_CHANGE",
                                          "UNSCHEDULED_JOB", "CHECKSUM_MISMATCH", "RESTRICTED_READ"}]
        self.assertEqual(correlate_incidents(events, 1), [])
        with self.assertRaises(ValueError):
            correlate_incidents(events, 0)

    def test_each_conclusion_cites_ids_from_its_incident(self):
        incident = self.legacy_incident
        valid_ids = {event.evidence_id for event in incident.evidence}
        claims = deterministic_investigation(incident)
        self.assertTrue(claims)
        for claim in claims:
            self.assertTrue(claim["evidence_ids"])
            self.assertTrue(set(claim["evidence_ids"]).issubset(valid_ids))

    def test_empty_investigation_has_no_claims(self):
        report = investigate(SimpleNamespace(evidence=()), use_granite=False)
        self.assertEqual(report["claims"], [])
        self.assertEqual(report["provider"], "deterministic")

    def test_recommendations_require_explicit_approval_and_never_execute(self):
        recommendations = recommend_remediations(self.legacy_incident)
        self.assertTrue(recommendations)
        self.assertTrue(all(rec.approval_status == "Pending approval" for rec in recommendations))
        disruptive = next(rec for rec in recommendations if rec.destructive)
        with self.assertRaises(ValueError):
            set_approval(recommendations, disruptive.action_id, "Execute", confirmed=True)
        with self.assertRaises(PermissionError):
            set_approval(recommendations, disruptive.action_id, "Approved")
        approved = set_approval(recommendations, disruptive.action_id, "Approved", confirmed=True)
        changed = next(rec for rec in approved if rec.action_id == disruptive.action_id)
        self.assertEqual(changed.approval_status, "Approved")
        self.assertEqual(changed.execution_status, "Not executed")
        with self.assertRaises(KeyError):
            set_approval(recommendations, "unknown-action", "Approved", confirmed=True)


if __name__ == "__main__":
    unittest.main()
