"""
Open Cloud Agents: Local Append-Only Blackboard Storage (Milestone v1.6 - TASK-3.4).

Embedded SQLite storage configured with Write-Ahead Logging (WAL) and busy handlers
for race-free concurrent agent execution. Provides CRUD operations for run envelopes,
deduplicated findings, and agent execution metrics.
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
import sys
import types
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing import Any as Self

from ocagents.blackboard.dedup import (
    derive_finding_id,
    ensure_finding_id,
    merge_duplicate_findings,
)
from ocagents.blackboard.envelope import RunEnvelope, validate_run_envelope

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(".ocagents/blackboard.db")


class BlackboardStore:
    """
    Append-only Blackboard findings and state store powered by SQLite WAL.
    Thread-safe and process-safe with busy_timeout for concurrent multi-agent access.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path == ":memory:":
            self._db_path = ":memory:"
        else:
            path = Path(db_path or DEFAULT_DB_PATH).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(path)

        self._conn = sqlite3.connect(
            self._db_path,
            timeout=10.0,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode; transactions managed via BEGIN/COMMIT
        )
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        """Configures SQLite pragmas and provisions database schema."""
        cursor = self._conn.cursor()

        # Concurrency & Performance Pragmas
        if self._db_path != ":memory:":
            cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA synchronous=NORMAL;")

        # 1. Runs Envelope Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                commit_sha TEXT NOT NULL,
                base_sha TEXT,
                base_ref TEXT,
                head_ref TEXT,
                pr_number INTEGER,
                risk_tier INTEGER NOT NULL,
                repo TEXT,
                repo_url TEXT,
                invoked_by TEXT,
                schema_version TEXT,
                engine_version TEXT,
                timestamp_utc TEXT NOT NULL,
                envelope_json TEXT NOT NULL
            );
        """)

        # 2. Findings Table (Canonical Schemas/v1/finding.json)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                category TEXT NOT NULL,
                resource TEXT NOT NULL,
                evidence TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL,
                origin TEXT NOT NULL,
                corroboration_status TEXT NOT NULL,
                agent TEXT NOT NULL,
                fact TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                finding_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_origin ON findings(origin);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);")

        # 3. Agent Execution Audit Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                agent TEXT NOT NULL,
                prompt_tokens INTEGER DEFAULT 0,
                output_tokens INTEGER DEFAULT 0,
                duration_ms INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                error_message TEXT,
                timestamp_utc TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_executions_run_id ON agent_executions(run_id);")

    # --- Run Envelope Operations ---

    def save_run(self, envelope: RunEnvelope | dict[str, Any]) -> str:
        """Persists a run metadata envelope. Idempotent across re-executions."""
        if isinstance(envelope, RunEnvelope):
            data = envelope.to_dict()
        else:
            data = dict(envelope)

        valid, errors = validate_run_envelope(data)
        if not valid:
            raise ValueError(f"Cannot save invalid run envelope: {'; '.join(errors)}")

        run_id = data["run_id"]
        envelope_json = json.dumps(data)

        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute("""
                INSERT INTO runs (
                    run_id, commit_sha, base_sha, base_ref, head_ref, pr_number,
                    risk_tier, repo, repo_url, invoked_by, schema_version,
                    engine_version, timestamp_utc, envelope_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    commit_sha = excluded.commit_sha,
                    base_sha = excluded.base_sha,
                    base_ref = excluded.base_ref,
                    head_ref = excluded.head_ref,
                    pr_number = excluded.pr_number,
                    risk_tier = excluded.risk_tier,
                    repo = excluded.repo,
                    repo_url = excluded.repo_url,
                    invoked_by = excluded.invoked_by,
                    schema_version = excluded.schema_version,
                    engine_version = excluded.engine_version,
                    timestamp_utc = excluded.timestamp_utc,
                    envelope_json = excluded.envelope_json;
            """, (
                run_id,
                data["commit_sha"],
                data.get("base_sha"),
                data.get("base_ref"),
                data.get("head_ref"),
                data.get("pr_number"),
                data["risk_tier"],
                data.get("repo"),
                data.get("repo_url"),
                data.get("invoked_by"),
                data.get("schema_version"),
                data.get("engine_version"),
                data["timestamp_utc"],
                envelope_json,
            ))
            cursor.execute("COMMIT;")
        except Exception:
            cursor.execute("ROLLBACK;")
            raise

        return run_id

    def get_run(self, run_id: str) -> RunEnvelope | None:
        """Retrieves a RunEnvelope by run_id."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT envelope_json FROM runs WHERE run_id = ?", (run_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return RunEnvelope.from_dict(json.loads(row["envelope_json"]))

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Lists recent run envelopes ordered by timestamp descending."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT envelope_json FROM runs ORDER BY timestamp_utc DESC LIMIT ?",
            (limit,),
        )
        return [json.loads(row["envelope_json"]) for row in cursor.fetchall()]

    # --- Findings Operations ---

    def publish_finding(self, finding: dict[str, Any], run_id: str) -> str:
        """
        Publishes a finding to the blackboard for the specified run_id.
        Applies deterministic deduplication and transaction-safe merging.
        """
        item = dict(finding)
        ensure_finding_id(item)
        fid = item.get("id")
        if not fid:
            rule_id = item.get("rule_id", "rules/unknown.md")
            res = item.get("resource", "unknown")
            ev = item.get("evidence", "repo:unknown#L1-L1")
            fid = derive_finding_id(rule_id, res, ev)
            item["id"] = fid

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            # Check for existing record with this id
            cursor.execute("SELECT finding_json FROM findings WHERE id = ?", (fid,))
            row = cursor.fetchone()

            if row:
                existing_dict = json.loads(row["finding_json"])
                merged = merge_duplicate_findings(existing_dict, item)
                merged["updated_at"] = now_utc
                merged_json = json.dumps(merged)

                cursor.execute("""
                    UPDATE findings SET
                        severity = ?,
                        confidence = ?,
                        origin = ?,
                        corroboration_status = ?,
                        agent = ?,
                        occurrence_count = ?,
                        finding_json = ?,
                        updated_at = ?
                    WHERE id = ?;
                """, (
                    merged.get("severity", "medium"),
                    merged.get("confidence"),
                    merged.get("origin", "model_assertion"),
                    merged.get("corroboration_status", "unverified_model_claim"),
                    merged.get("agent", "unknown"),
                    merged.get("occurrence_count", 1),
                    merged_json,
                    now_utc,
                    fid,
                ))
            else:
                item["occurrence_count"] = item.get("occurrence_count", 1)
                item["corroborating_agents"] = item.get("corroborating_agents", [item.get("agent", "unknown")])
                item_json = json.dumps(item)

                cursor.execute("""
                    INSERT INTO findings (
                        id, run_id, rule_id, category, resource, evidence,
                        severity, confidence, origin, corroboration_status,
                        agent, fact, recommendation, occurrence_count,
                        finding_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    fid,
                    run_id,
                    item.get("rule_id", ""),
                    item.get("category", ""),
                    item.get("resource", ""),
                    item.get("evidence", ""),
                    item.get("severity", "medium"),
                    item.get("confidence"),
                    item.get("origin", "model_assertion"),
                    item.get("corroboration_status", "unverified_model_claim"),
                    item.get("agent", "unknown"),
                    item.get("fact", ""),
                    item.get("recommendation", ""),
                    item["occurrence_count"],
                    item_json,
                    now_utc,
                    now_utc,
                ))
            cursor.execute("COMMIT;")
        except Exception:
            cursor.execute("ROLLBACK;")
            raise

        return fid

    def publish_findings(self, findings: list[dict[str, Any]], run_id: str) -> list[str]:
        """Publishes a batch of findings in order."""
        return [self.publish_finding(f, run_id) for f in findings]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Retrieves finding by ID."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT finding_json FROM findings WHERE id = ?", (finding_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return json.loads(row["finding_json"])

    def get_findings(
        self,
        run_id: str | None = None,
        severity: str | None = None,
        origin: str | None = None,
        rule_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Queries blackboard findings filtered by run_id, severity, origin, or rule_id."""
        query = "SELECT finding_json FROM findings WHERE 1=1"
        params: list[Any] = []

        if run_id is not None:
            query += " AND run_id = ?"
            params.append(run_id)
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity.lower())
        if origin is not None:
            query += " AND origin = ?"
            params.append(origin)
        if rule_id is not None:
            query += " AND rule_id = ?"
            params.append(rule_id)

        query += " ORDER BY created_at ASC;"

        cursor = self._conn.cursor()
        cursor.execute(query, params)
        return [json.loads(row["finding_json"]) for row in cursor.fetchall()]

    # --- Agent Execution Audit Operations ---

    def record_execution(
        self,
        run_id: str,
        agent: str,
        prompt_tokens: int = 0,
        output_tokens: int = 0,
        duration_ms: int = 0,
        status: str = "success",
        error_message: str | None = None,
    ) -> int:
        """Records an agent execution event for token budget audit tracking."""
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute("""
                INSERT INTO agent_executions (
                    run_id, agent, prompt_tokens, output_tokens, duration_ms,
                    status, error_message, timestamp_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                run_id,
                agent,
                prompt_tokens,
                output_tokens,
                duration_ms,
                status,
                error_message,
                now_utc,
            ))
            exec_id = cursor.lastrowid or 0
            cursor.execute("COMMIT;")
            return exec_id
        except Exception:
            cursor.execute("ROLLBACK;")
            raise

    def get_executions(self, run_id: str) -> list[dict[str, Any]]:
        """Retrieves all agent execution records for a run."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT * FROM agent_executions WHERE run_id = ? ORDER BY id ASC;",
            (run_id,),
        )
        results: list[dict[str, Any]] = []
        for r in cursor.fetchall():
            results.append({
                "id": r["id"],
                "run_id": r["run_id"],
                "agent": r["agent"],
                "prompt_tokens": r["prompt_tokens"],
                "output_tokens": r["output_tokens"],
                "duration_ms": r["duration_ms"],
                "status": r["status"],
                "error_message": r["error_message"],
                "timestamp_utc": r["timestamp_utc"],
            })
        return results

    # --- Export & Maintenance ---

    def export_findings_json(self, run_id: str, indent: int = 2) -> str:
        """Exports all findings for a run as a formatted JSON array string."""
        findings = self.get_findings(run_id=run_id)
        return json.dumps(findings, indent=indent)

    def prune_runs(self, keep_last: int = 20) -> int:
        """Prunes historical runs older than keep_last, cascading to findings and executions."""
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            cursor.execute("""
                DELETE FROM runs WHERE run_id NOT IN (
                    SELECT run_id FROM runs ORDER BY timestamp_utc DESC LIMIT ?
                );
            """, (keep_last,))
            deleted = cursor.rowcount
            cursor.execute("COMMIT;")
            return deleted
        except Exception:
            cursor.execute("ROLLBACK;")
            raise

    def close(self) -> None:
        """Closes the underlying database connection."""
        try:
            self._conn.close()
        except sqlite3.Error as exc:
            logger.debug("Error closing database connection: %s", exc)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.close()

