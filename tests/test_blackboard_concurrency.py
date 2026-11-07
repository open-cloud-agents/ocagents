"""
Concurrency & Lock Stress Tests for Open Cloud Agents Blackboard Store (TASK-3.7).

Validates concurrent multi-agent write safety, race condition prevention, and SQLite WAL
resilience under heavy parallel thread load.
"""

import concurrent.futures
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ocagents.blackboard.envelope import create_run_envelope
from ocagents.blackboard.store import BlackboardStore


class TestBlackboardConcurrency(unittest.TestCase):
    """Stress testing suite validating concurrent blackboard writes."""

    def test_concurrent_agent_findings_writes(self):
        """
        Simulates 5 specialist agents concurrently writing 20 findings each
        to a shared SQLite WAL database file.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "concurrent_blackboard.db"
            store = BlackboardStore(db_path)

            envelope = create_run_envelope(
                risk_tier=2,
                commit_sha="3333331234567890abcdef1234567890abcdef12",
                repo="open-cloud-agents/ocagents",
            )
            run_id = store.save_run(envelope)
            store.close()

            agents = [
                "principal-cloud-architect",
                "security-compliance-commander",
                "finops-cloud-cost-optimizer",
                "sre-reliability-engineer",
                "devsecops-reviewer",
            ]

            def worker_task(agent_name: str, worker_id: int) -> int:
                """Worker thread that creates its own connection and writes findings."""
                worker_store = BlackboardStore(db_path)
                written = 0
                try:
                    for i in range(20):
                        # Items 0-4 are shared across all agents to stress deduplication
                        # Items 5-19 are unique to each agent
                        if i < 5:
                            res_name = f"shared_resource_{i}"
                            ev = f"diff:infra/shared.tf#L{i * 10}-L{i * 10 + 2}"
                        else:
                            res_name = f"{agent_name}_res_{i}"
                            ev = f"diff:{agent_name}/file.tf#L{i * 10}-L{i * 10 + 2}"

                        finding = {
                            "rule_id": "rules/04-cloud-well-architected-invariants.md",
                            "category": "Concurrency Stress",
                            "resource": res_name,
                            "evidence": ev,
                            "severity": "high" if i % 2 == 0 else "medium",
                            "confidence": 0.90,
                            "origin": "model_assertion",
                            "corroboration_status": "unverified_model_claim",
                            "agent": agent_name,
                            "fact": f"Concurrency fact {i} from {agent_name}",
                            "recommendation": "Remediation recommendation",
                        }
                        worker_store.publish_finding(finding, run_id)
                        written += 1

                    # Record execution event
                    worker_store.record_execution(
                        run_id=run_id,
                        agent=agent_name,
                        prompt_tokens=3000 + worker_id * 100,
                        output_tokens=500 + worker_id * 50,
                        duration_ms=1200 + worker_id * 200,
                        status="success",
                    )
                finally:
                    worker_store.close()
                return written

            # Execute workers concurrently across a thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(worker_task, agent, idx)
                    for idx, agent in enumerate(agents)
                ]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            self.assertEqual(len(results), 5)
            self.assertEqual(sum(results), 100)

            # Re-open and verify state integrity
            verification_store = BlackboardStore(db_path)
            with verification_store:
                # Total unique findings should be:
                # 5 shared items + (15 unique * 5 agents) = 5 + 75 = 80 unique findings
                all_findings = verification_store.get_findings(run_id=run_id)
                self.assertEqual(len(all_findings), 80)

                # Check shared items have occurrence_count == 5 and all 5 corroborating agents
                for i in range(5):
                    shared_items = [f for f in all_findings if f["resource"] == f"shared_resource_{i}"]
                    self.assertEqual(len(shared_items), 1)
                    item = shared_items[0]
                    self.assertEqual(item["occurrence_count"], 5)
                    self.assertEqual(len(item["corroborating_agents"]), 5)

                # Check execution audit records (5 agents)
                execs = verification_store.get_executions(run_id)
                self.assertEqual(len(execs), 5)

                # Integrity check on SQLite database
                cursor = verification_store._conn.cursor()
                cursor.execute("PRAGMA integrity_check;")
                row = cursor.fetchone()
                self.assertEqual(row[0], "ok")


if __name__ == "__main__":
    unittest.main()
