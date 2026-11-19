"""
Open Cloud Agents: Local Append-Only Blackboard Storage (Milestone v1.6 & v2.2 - TASK-3.4 / Issue #101).

Embedded SQLite storage configured with Write-Ahead Logging (WAL) and busy handlers
for race-free concurrent agent execution. Provides CRUD operations for run envelopes,
deduplicated findings with canonical SHA-256 fingerprinting, finding lifecycle management,
diff-aware stale finding invalidation, evidence ranking, and TTL compaction.
"""

from __future__ import annotations

import datetime
import json
import logging
import sqlite3
import sys
import threading
import types
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing import Any as Self

from ocagents.blackboard.dedupe import (
    compute_finding_fingerprint,
    derive_finding_id,
    ensure_finding_id,
    merge_duplicate_findings,
)
from ocagents.blackboard.envelope import RunEnvelope, validate_run_envelope
from ocagents.blackboard.lifecycle import (
    FindingLifecycleStatus,
    evaluate_diff_invalidations,
    is_finding_expired,
    parse_ttl_string,
    transition_lifecycle_status,
)
from ocagents.blackboard.ranking import rank_findings

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(".ocagents/blackboard.db")

# Statuses a human triage decision may set (see triage/resolution.py).
RESOLVABLE_STATUSES = ("human_verified", "rejected_false_positive")


class BlackboardStore:
    """
    Append-only Blackboard findings and state store powered by SQLite WAL.
    Thread-safe and process-safe with busy_timeout for concurrent multi-agent access.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._lock = threading.RLock()
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
                fingerprint TEXT,
                lifecycle_status TEXT DEFAULT 'OPEN',
                finding_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
        """)

        # Schema evolution for existing on-disk databases
        cursor.execute("PRAGMA table_info(findings);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        if "fingerprint" not in existing_cols:
            cursor.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT;")
        if "lifecycle_status" not in existing_cols:
            cursor.execute("ALTER TABLE findings ADD COLUMN lifecycle_status TEXT DEFAULT 'OPEN';")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_origin ON findings(origin);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_lifecycle_status ON findings(lifecycle_status);")

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

        with self._lock:
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
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT envelope_json FROM runs WHERE run_id = ?", (run_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return RunEnvelope.from_dict(json.loads(row["envelope_json"]))

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Lists recent run envelopes ordered by timestamp descending."""
        with self._lock:
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
        Applies deterministic fingerprint deduplication, corroboration promotion,
        and transaction-safe merging.
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

        fp = item.get("fingerprint") or compute_finding_fingerprint(item)
        item["fingerprint"] = fp

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE;")
            try:
                # Check for existing record by exact ID or canonical fingerprint
                cursor.execute(
                    "SELECT id, finding_json, lifecycle_status FROM findings WHERE id = ? OR (fingerprint IS NOT NULL AND fingerprint = ?)",
                    (fid, fp),
                )
                row = cursor.fetchone()

                if row:
                    target_id = row["id"]
                    existing_dict = json.loads(row["finding_json"])
                    existing_lifecycle = row["lifecycle_status"] or FindingLifecycleStatus.OPEN.value
                    merged = merge_duplicate_findings(existing_dict, item)
                    merged["updated_at"] = now_utc
                    merged["last_seen_utc"] = now_utc

                    # Determine lifecycle state progression on corroboration/re-observation
                    new_lifecycle = existing_lifecycle
                    if existing_lifecycle in (FindingLifecycleStatus.SUPERSEDED.value, FindingLifecycleStatus.EXPIRED.value):
                        # Re-observed in current commit -> re-open
                        new_lifecycle = FindingLifecycleStatus.OPEN.value

                    if (
                        merged.get("corroboration_status") in ("tool_verified", "human_verified", "model_corroborated")
                        and new_lifecycle == FindingLifecycleStatus.OPEN.value
                    ):
                        new_lifecycle = FindingLifecycleStatus.CORROBORATED.value

                    merged["lifecycle_status"] = new_lifecycle
                    merged_json = json.dumps(merged)

                    cursor.execute("""
                        UPDATE findings SET
                            severity = ?,
                            confidence = ?,
                            origin = ?,
                            corroboration_status = ?,
                            agent = ?,
                            occurrence_count = ?,
                            fingerprint = ?,
                            lifecycle_status = ?,
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
                        fp,
                        new_lifecycle,
                        merged_json,
                        now_utc,
                        target_id,
                    ))
                    fid = target_id
                else:
                    item["occurrence_count"] = item.get("occurrence_count", 1)
                    item["corroborating_agents"] = item.get("corroborating_agents", [item.get("agent", "unknown")])
                    item["corroboration_count"] = len(item["corroborating_agents"])

                    # Determine initial lifecycle state
                    if item.get("corroboration_status") in ("tool_verified", "human_verified", "model_corroborated"):
                        initial_lifecycle = FindingLifecycleStatus.CORROBORATED.value
                    else:
                        initial_lifecycle = item.get("lifecycle_status", FindingLifecycleStatus.OPEN.value)

                    item["lifecycle_status"] = initial_lifecycle
                    item["created_at"] = item.get("created_at", now_utc)
                    item["updated_at"] = now_utc
                    item["last_seen_utc"] = now_utc
                    item_json = json.dumps(item)

                    cursor.execute("""
                        INSERT INTO findings (
                            id, run_id, rule_id, category, resource, evidence,
                            severity, confidence, origin, corroboration_status,
                            agent, fact, recommendation, occurrence_count,
                            fingerprint, lifecycle_status, finding_json, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                        fp,
                        initial_lifecycle,
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
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("SELECT finding_json, lifecycle_status, updated_at, created_at, fingerprint FROM findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            f = json.loads(row["finding_json"])
            if row["lifecycle_status"]:
                f["lifecycle_status"] = row["lifecycle_status"]
            if row["updated_at"]:
                f["updated_at"] = row["updated_at"]
            if row["created_at"]:
                f["created_at"] = row["created_at"]
            if row["fingerprint"]:
                f["fingerprint"] = row["fingerprint"]
            return f

    def get_findings(
        self,
        run_id: str | None = None,
        severity: str | None = None,
        origin: str | None = None,
        rule_id: str | None = None,
        lifecycle_status: str | None = None,
        min_confidence: float | None = None,
        limit_top_k: int | None = None,
        rank: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Queries blackboard findings filtered by run_id, severity, origin, rule_id,
        or lifecycle_status. Optionally applies composite evidence ranking and top-K pruning.
        """
        query = "SELECT finding_json, lifecycle_status, updated_at, created_at, fingerprint FROM findings WHERE 1=1"
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
        if lifecycle_status is not None:
            query += " AND lifecycle_status = ?"
            params.append(lifecycle_status.upper())

        query += " ORDER BY created_at ASC;"

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(query, params)
            results: list[dict[str, Any]] = []
            for row in cursor.fetchall():
                f = json.loads(row["finding_json"])
                if row["lifecycle_status"]:
                    f["lifecycle_status"] = row["lifecycle_status"]
                if row["updated_at"]:
                    f["updated_at"] = row["updated_at"]
                if row["created_at"]:
                    f["created_at"] = row["created_at"]
                if row["fingerprint"]:
                    f["fingerprint"] = row["fingerprint"]
                results.append(f)

        if rank or limit_top_k is not None or min_confidence is not None:
            results = rank_findings(
                results,
                limit_top_k=limit_top_k,
                min_confidence=min_confidence,
            )

        return results

    def resolve_finding(
        self,
        finding_id: str,
        corroboration_status: str,
        resolution: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Records a triage decision on a stored finding.
        Updates corroboration_status, lifecycle_status ('RESOLVED' or 'SUPERSEDED'),
        and resolution metadata in one transaction.
        """
        if corroboration_status not in RESOLVABLE_STATUSES:
            raise ValueError(f"Unsupported corroboration_status for triage: {corroboration_status!r}")

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE;")
            try:
                cursor.execute("SELECT finding_json, lifecycle_status FROM findings WHERE id = ?", (finding_id,))
                row = cursor.fetchone()
                if not row:
                    cursor.execute("ROLLBACK;")
                    return None

                finding = json.loads(row["finding_json"])
                metadata = finding.get("metadata")
                if not isinstance(metadata, dict):
                    metadata = {}
                metadata["resolution"] = {
                    "previous_status": finding.get("corroboration_status", "unverified_model_claim"),
                    **resolution,
                    "corroboration_status": corroboration_status,
                }
                finding["metadata"] = metadata
                finding["corroboration_status"] = corroboration_status

                new_lifecycle = (
                    FindingLifecycleStatus.RESOLVED.value
                    if corroboration_status == "human_verified"
                    else FindingLifecycleStatus.SUPERSEDED.value
                )
                finding["lifecycle_status"] = new_lifecycle
                finding["updated_at"] = now_utc

                cursor.execute(
                    """
                    UPDATE findings SET
                        corroboration_status = ?,
                        lifecycle_status = ?,
                        finding_json = ?,
                        updated_at = ?
                    WHERE id = ?;
                    """,
                    (corroboration_status, new_lifecycle, json.dumps(finding), now_utc, finding_id),
                )
                cursor.execute("COMMIT;")
            except Exception:
                cursor.execute("ROLLBACK;")
                raise

        return finding

    def update_lifecycle_status(
        self,
        finding_id: str,
        target_status: str | FindingLifecycleStatus,
        reason: str = "",
    ) -> dict[str, Any] | None:
        """
        Updates finding lifecycle status following valid state transition rules.
        """
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE;")
            try:
                cursor.execute("SELECT finding_json, lifecycle_status FROM findings WHERE id = ?", (finding_id,))
                row = cursor.fetchone()
                if not row:
                    cursor.execute("ROLLBACK;")
                    return None

                finding = json.loads(row["finding_json"])
                current_status = row["lifecycle_status"] or FindingLifecycleStatus.OPEN.value
                new_status = transition_lifecycle_status(current_status, target_status, reason)

                metadata = finding.get("metadata")
                if not isinstance(metadata, dict):
                    metadata = {}
                if reason:
                    metadata["lifecycle_transition"] = {
                        "from": current_status,
                        "to": new_status,
                        "reason": reason,
                        "timestamp_utc": now_utc,
                    }
                finding["metadata"] = metadata
                finding["lifecycle_status"] = new_status
                finding["updated_at"] = now_utc

                cursor.execute(
                    "UPDATE findings SET lifecycle_status = ?, finding_json = ?, updated_at = ? WHERE id = ?;",
                    (new_status, json.dumps(finding), now_utc, finding_id),
                )
                cursor.execute("COMMIT;")
            except Exception:
                cursor.execute("ROLLBACK;")
                raise

        return finding

    def invalidate_by_diff(self, diff_text: str, run_id: str | None = None) -> list[str]:
        """
        Scans active findings and marks any findings whose underlying source lines
        were refactored, modified, or deleted as SUPERSEDED.
        Returns list of invalidated finding IDs.
        """
        active_findings = self.get_findings(run_id=run_id)
        invalidated_pairs = evaluate_diff_invalidations(active_findings, diff_text)
        if not invalidated_pairs:
            return []

        invalidated_ids: list[str] = []
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute("BEGIN IMMEDIATE;")
            try:
                for fid, reason in invalidated_pairs:
                    cursor.execute("SELECT finding_json FROM findings WHERE id = ?", (fid,))
                    row = cursor.fetchone()
                    if row:
                        finding = json.loads(row["finding_json"])
                        metadata = finding.get("metadata") or {}
                        metadata["superseded_reason"] = reason
                        finding["metadata"] = metadata
                        finding["lifecycle_status"] = FindingLifecycleStatus.SUPERSEDED.value
                        finding["updated_at"] = now_utc

                        cursor.execute(
                            "UPDATE findings SET lifecycle_status = ?, finding_json = ?, updated_at = ? WHERE id = ?;",
                            (FindingLifecycleStatus.SUPERSEDED.value, json.dumps(finding), now_utc, fid),
                        )
                        invalidated_ids.append(fid)
                cursor.execute("COMMIT;")
            except Exception:
                cursor.execute("ROLLBACK;")
                raise

        return invalidated_ids

    def prune_findings(
        self,
        ttl: str = "14d",
        dry_run: bool = False,
        run_id: str | None = None,
        archive_resolved: bool = True,
    ) -> dict[str, Any]:
        """
        Compacts the blackboard store by expiring or pruning stale findings past TTL.
        Evaluates TTL against 'last_seen_utc', 'updated_at', or 'created_at'.
        """
        ttl_seconds = parse_ttl_string(ttl)
        findings = self.get_findings(run_id=run_id)

        expired_ids: list[str] = []
        prune_ids: list[str] = []

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        for f in findings:
            fid = f.get("id")
            if not fid:
                continue

            status = f.get("lifecycle_status", FindingLifecycleStatus.OPEN.value)

            if is_finding_expired(f, ttl_seconds):
                if status in (FindingLifecycleStatus.RESOLVED.value, FindingLifecycleStatus.SUPERSEDED.value, FindingLifecycleStatus.EXPIRED.value):
                    if archive_resolved:
                        prune_ids.append(fid)
                else:
                    expired_ids.append(fid)

        if not dry_run and (expired_ids or prune_ids):
            with self._lock:
                cursor = self._conn.cursor()
                cursor.execute("BEGIN IMMEDIATE;")
                try:
                    # Mark active expired findings as EXPIRED
                    for fid in expired_ids:
                        cursor.execute("SELECT finding_json FROM findings WHERE id = ?", (fid,))
                        row = cursor.fetchone()
                        if row:
                            f_dict = json.loads(row["finding_json"])
                            f_dict["lifecycle_status"] = FindingLifecycleStatus.EXPIRED.value
                            f_dict["updated_at"] = now_utc
                            cursor.execute(
                                "UPDATE findings SET lifecycle_status = ?, finding_json = ?, updated_at = ? WHERE id = ?;",
                                (FindingLifecycleStatus.EXPIRED.value, json.dumps(f_dict), now_utc, fid),
                            )

                    # Delete pruned terminal findings
                    if prune_ids:
                        placeholders = ",".join("?" for _ in prune_ids)
                        cursor.execute(f"DELETE FROM findings WHERE id IN ({placeholders});", prune_ids)

                    cursor.execute("COMMIT;")
                except Exception:
                    cursor.execute("ROLLBACK;")
                    raise

        return {
            "scanned_count": len(findings),
            "expired_count": len(expired_ids),
            "pruned_count": len(prune_ids),
            "dry_run": dry_run,
            "ttl": ttl,
            "ttl_seconds": ttl_seconds,
        }

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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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
