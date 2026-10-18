import unittest
from datetime import datetime, timezone
from sentinel.evidence import generate_demo_events, normalize_event
from sentinel.risk import score_evidence

class EvidenceTests(unittest.TestCase):
    def test_normalization_marks_synthetic_and_converts_timestamp(self):
        event = normalize_event({"timestamp":"2026-01-01T00:00:00Z", "source":"SMF-style security", "event":"AUTH_SUCCESS", "actor":"A", "target":"B", "outcome":"success", "severity":"low", "summary":"test"})
        self.assertTrue(event.synthetic)
        self.assertEqual(event.occurred_at, "2026-01-01T00:00:00+00:00")
        self.assertTrue(event.evidence_id.startswith("ev-"))
    def test_missing_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing event fields"):
            normalize_event({"timestamp":"bad"})
    def test_demo_is_reproducible_and_contains_cross_signal_chain(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        first, second = generate_demo_events(seed=7, now=now), generate_demo_events(seed=7, now=now)
        self.assertEqual([e.to_dict() for e in first], [e.to_dict() for e in second])
        # The integrity monitor is SYSTEM-authored, so include its alert for the
        # same payroll dataset alongside OPSUSER's privilege and job events.
        legacy_chain = [e for e in first if e.actor == "OPSUSER" or
                        (e.event_type == "CHECKSUM_MISMATCH" and e.target == "PAYROLL.PRD")]
        self.assertTrue({"PRIVILEGE_CHANGE", "UNSCHEDULED_JOB", "CHECKSUM_MISMATCH"}.issubset(
            {event.event_type for event in legacy_chain}))
        result = score_evidence(legacy_chain)
        self.assertGreaterEqual(result.score, 80)
        self.assertEqual(result.band, "critical")
        self.assertTrue(any("Correlated privilege" in reason for reason in result.reasons))
    def test_empty_evidence_has_zero_risk(self):
        result = score_evidence([])
        self.assertEqual(result.score, 0)
        self.assertEqual(result.band, "low")

if __name__ == "__main__":
    unittest.main()
