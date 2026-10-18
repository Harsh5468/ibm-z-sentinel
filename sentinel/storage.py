"""SQLite persistence for incident, evidence, recommendation and approval history."""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Iterable

from .correlation import Incident
from .evidence import Evidence
from .remediation import Recommendation, recommend_remediations, set_approval
from .risk import RiskAssessment

SCHEMA_VERSION = 1


class SentinelStore:
    """Small local SQLite store; schema creation is idempotent and writes are transactional."""

    def __init__(self, path: str | Path | None = None):
        configured = path or os.getenv("SENTINEL_DB_PATH", "data/sentinel.db")
        self.path = str(configured)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def initialize(self) -> None:
        """Create the data directory and all tables safely; repeated calls are harmless."""
        if self.path != ":memory:":
            Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection, connection:
            current_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if current_version > SCHEMA_VERSION:
                raise RuntimeError(f"Database schema {current_version} is newer than supported schema {SCHEMA_VERSION}")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS evidence_events (
                    evidence_id TEXT PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    stored_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    risk_score INTEGER NOT NULL,
                    risk_band TEXT NOT NULL,
                    seed INTEGER NOT NULL,
                    window_minutes INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_evidence (
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    evidence_id TEXT NOT NULL REFERENCES evidence_events(evidence_id),
                    ordinal INTEGER NOT NULL,
                    PRIMARY KEY (incident_id, evidence_id)
                );
                CREATE TABLE IF NOT EXISTS recommendations (
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    action_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    approval_status TEXT NOT NULL DEFAULT 'Pending approval',
                    destructive INTEGER NOT NULL DEFAULT 0,
                    execution_status TEXT NOT NULL DEFAULT 'Not executed',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (incident_id, action_id)
                );
                CREATE TABLE IF NOT EXISTS approval_history (
                    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK (decision IN ('Approved', 'Rejected')),
                    approver TEXT NOT NULL,
                    decided_at TEXT NOT NULL,
                    FOREIGN KEY (incident_id, action_id)
                        REFERENCES recommendations(incident_id, action_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_approval_history_incident ON approval_history(incident_id, decided_at DESC);
            """)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, separators=(",", ":"), sort_keys=True)

    def has_incidents(self) -> bool:
        with closing(self._connect()) as connection, connection:
            return connection.execute("SELECT EXISTS(SELECT 1 FROM incidents)").fetchone()[0] == 1

    def save_demo_snapshot(self, seed: int, window_minutes: int, events: Iterable[Evidence],
                           incidents: Iterable[Incident]) -> None:
        """Idempotently upsert a seeded snapshot; existing approval decisions are retained."""
        events = list(events)
        incidents = list(incidents)
        now = self._now()
        with closing(self._connect()) as connection, connection:
            for event in events:
                connection.execute("""INSERT INTO evidence_events(evidence_id, occurred_at, payload_json, stored_at)
                    VALUES(?,?,?,?) ON CONFLICT(evidence_id) DO UPDATE SET
                    occurred_at=excluded.occurred_at, payload_json=excluded.payload_json, stored_at=excluded.stored_at""",
                    (event.evidence_id, event.occurred_at, self._json(event.to_dict()), now))
            for incident in incidents:
                payload = {"actors": incident.actors, "resources": incident.resources,
                           "risk_reasons": incident.risk.reasons,
                           "business_criticality": incident.business_criticality,
                           "business_process": incident.business_process}
                connection.execute("""INSERT INTO incidents(incident_id,risk_score,risk_band,seed,window_minutes,
                    payload_json,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)
                    ON CONFLICT(incident_id) DO UPDATE SET risk_score=excluded.risk_score,
                    risk_band=excluded.risk_band,seed=excluded.seed,window_minutes=excluded.window_minutes,
                    payload_json=excluded.payload_json,last_seen=excluded.last_seen""",
                    (incident.incident_id, incident.risk.score, incident.risk.band, seed,
                     window_minutes, self._json(payload), now, now))
                connection.execute("DELETE FROM incident_evidence WHERE incident_id=?", (incident.incident_id,))
                for ordinal, event in enumerate(incident.evidence):
                    connection.execute("INSERT INTO incident_evidence(incident_id,evidence_id,ordinal) VALUES(?,?,?)",
                                       (incident.incident_id, event.evidence_id, ordinal))
                for recommendation in recommend_remediations(incident):
                    connection.execute("""INSERT INTO recommendations(incident_id,action_id,title,rationale,
                        evidence_ids_json,approval_status,destructive,execution_status,updated_at)
                        VALUES(?,?,?,?,?,'Pending approval',?,'Not executed',?)
                        ON CONFLICT(incident_id,action_id) DO UPDATE SET title=excluded.title,
                        rationale=excluded.rationale,evidence_ids_json=excluded.evidence_ids_json,
                        destructive=excluded.destructive,updated_at=excluded.updated_at""",
                        (incident.incident_id, recommendation.action_id, recommendation.title,
                         recommendation.rationale, self._json(recommendation.evidence_ids),
                         int(recommendation.destructive), now))

    def list_incidents(self) -> list[Incident]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute("SELECT * FROM incidents ORDER BY risk_score DESC,last_seen DESC,incident_id").fetchall()
            result: list[Incident] = []
            for row in rows:
                payload = json.loads(row["payload_json"])
                evidence_rows = connection.execute("""SELECT e.payload_json FROM evidence_events e
                    JOIN incident_evidence ie ON ie.evidence_id=e.evidence_id
                    WHERE ie.incident_id=? ORDER BY ie.ordinal""", (row["incident_id"],)).fetchall()
                evidence = tuple(Evidence(**json.loads(event_row["payload_json"])) for event_row in evidence_rows)
                risk = RiskAssessment(row["risk_score"], row["risk_band"], tuple(payload["risk_reasons"]))
                result.append(Incident(row["incident_id"], evidence, tuple(payload["actors"]),
                                       tuple(payload["resources"]), risk,
                                       payload.get("business_criticality", "unclassified"),
                                       payload.get("business_process", "")))
            return result

    def list_recommendations(self, incident_id: str) -> list[Recommendation]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute("SELECT * FROM recommendations WHERE incident_id=? ORDER BY action_id",
                                      (incident_id,)).fetchall()
        return [Recommendation(row["action_id"], row["title"], row["rationale"],
                               tuple(json.loads(row["evidence_ids_json"])), row["approval_status"],
                               bool(row["destructive"]), row["execution_status"]) for row in rows]

    def record_decision(self, incident_id: str, action_id: str, decision: str,
                        approver: str, *, confirmed: bool = False) -> Recommendation:
        """Validate a confirmed human decision, update current state, and append audit history."""
        approver = approver.strip()
        if decision not in {"Approved", "Rejected"}:
            raise ValueError("decision must be Approved or Rejected")
        if not confirmed:
            raise PermissionError("Explicit human confirmation is required")
        if not approver:
            raise ValueError("approver is required")
        with closing(self._connect()) as connection, connection:
            row = connection.execute("SELECT * FROM recommendations WHERE incident_id=? AND action_id=?",
                                     (incident_id, action_id)).fetchone()
            if row is None:
                raise KeyError(f"Unknown recommendation: {incident_id}/{action_id}")
            current = Recommendation(row["action_id"], row["title"], row["rationale"],
                                     tuple(json.loads(row["evidence_ids_json"])), row["approval_status"],
                                     bool(row["destructive"]), row["execution_status"])
            updated = set_approval([current], action_id, decision, confirmed=True)[0]
            now = self._now()
            connection.execute("""UPDATE recommendations SET approval_status=?,execution_status='Not executed',updated_at=?
                WHERE incident_id=? AND action_id=?""", (decision, now, incident_id, action_id))
            connection.execute("""INSERT INTO approval_history(incident_id,action_id,decision,approver,decided_at)
                VALUES(?,?,?,?,?)""", (incident_id, action_id, decision, approver, now))
            return updated

    def list_approval_history(self, incident_id: str) -> list[dict[str, object]]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute("""SELECT action_id,decision,approver,decided_at FROM approval_history
                WHERE incident_id=? ORDER BY decision_id DESC""", (incident_id,)).fetchall()
        return [dict(row) for row in rows]

    def counts(self) -> dict[str, int]:
        with closing(self._connect()) as connection, connection:
            return {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("evidence_events", "incidents", "recommendations", "approval_history")}
