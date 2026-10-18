import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sentinel.correlation import correlate_incidents
from sentinel.detection import enrich_with_findings
from sentinel.evidence import generate_demo_events
from sentinel.storage import SentinelStore


class SQLiteHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "sentinel-test.db"
        self.store = SentinelStore(self.database)
        self.events = enrich_with_findings(generate_demo_events(seed=17, now=datetime(2026, 2, 3, tzinfo=timezone.utc)))
        self.incidents = correlate_incidents(self.events, window_minutes=90)

    def tearDown(self):
        self.temp_dir.cleanup()

    def load(self):
        self.store.save_demo_snapshot(17, 90, self.events, self.incidents)

    def test_initialization_is_safe_to_repeat(self):
        self.store.initialize()
        self.store = SentinelStore(self.database)
        self.assertEqual(self.store.counts(), {
            "evidence_events": 0, "incidents": 0,
            "recommendations": 0, "approval_history": 0,
        })

    def test_snapshot_round_trip_is_idempotent_and_integrates_modules(self):
        self.load()
        initial_counts = self.store.counts()
        self.load()
        self.assertEqual(self.store.counts(), initial_counts)
        restored = self.store.list_incidents()
        self.assertEqual([case.incident_id for case in restored], [case.incident_id for case in self.incidents])
        case = next(incident for incident in restored if incident.business_process == "Payroll close")
        self.assertGreaterEqual(case.risk.score, 80)
        self.assertTrue(case.evidence)
        self.assertEqual(case.business_criticality, "critical")
        self.assertEqual(case.business_process, "Payroll close")
        self.assertTrue(self.store.list_recommendations(case.incident_id))
        stored_ids = {event.evidence_id for event in case.evidence}
        for recommendation in self.store.list_recommendations(case.incident_id):
            self.assertTrue(set(recommendation.evidence_ids).issubset(stored_ids))

    def test_explicit_confirmation_and_persistent_approval_transitions(self):
        self.load()
        case = self.store.list_incidents()[0]
        recommendation = self.store.list_recommendations(case.incident_id)[0]
        with self.assertRaises(PermissionError):
            self.store.record_decision(case.incident_id, recommendation.action_id, "Approved", "operator", confirmed=False)
        with self.assertRaises(ValueError):
            self.store.record_decision(case.incident_id, recommendation.action_id, "Approved", " ", confirmed=True)
        self.assertEqual(self.store.list_approval_history(case.incident_id), [])

        approved = self.store.record_decision(case.incident_id, recommendation.action_id,
                                              "Approved", "operator-17", confirmed=True)
        self.assertEqual(approved.approval_status, "Approved")
        self.assertEqual(approved.execution_status, "Not executed")
        rejected = self.store.record_decision(case.incident_id, recommendation.action_id,
                                              "Rejected", "reviewer-2", confirmed=True)
        self.assertEqual(rejected.approval_status, "Rejected")
        self.assertEqual(rejected.execution_status, "Not executed")

        history = self.store.list_approval_history(case.incident_id)
        self.assertEqual([row["decision"] for row in history], ["Rejected", "Approved"])
        self.assertEqual({row["approver"] for row in history}, {"operator-17", "reviewer-2"})
        current = next(rec for rec in self.store.list_recommendations(case.incident_id)
                       if rec.action_id == recommendation.action_id)
        self.assertEqual(current.approval_status, "Rejected")

    def test_refresh_preserves_approval_without_duplicating_history(self):
        self.load()
        case = self.store.list_incidents()[0]
        recommendation = self.store.list_recommendations(case.incident_id)[0]
        self.store.record_decision(case.incident_id, recommendation.action_id,
                                   "Approved", "operator", confirmed=True)
        self.load()
        current = next(rec for rec in self.store.list_recommendations(case.incident_id)
                       if rec.action_id == recommendation.action_id)
        self.assertEqual(current.approval_status, "Approved")
        self.assertEqual(self.store.counts()["approval_history"], 1)


if __name__ == "__main__":
    unittest.main()
