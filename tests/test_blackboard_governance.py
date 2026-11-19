"""
Open Cloud Agents: Anti-Swamp Governance Test Suite (Milestone v2.2 - Issue #101).

Validates:
  1. Deterministic fingerprinting & canonical path extraction
  2. Idempotent deduplication and corroboration promotion
  3. Finding lifecycle state machine transitions
  4. Git-diff source range refactoring invalidation
  5. TTL duration parsing, age expiration & store compaction
  6. Composite risk evidence ranking & top-K context pruning
  7. BlackboardStore database integration with lifecycle and ranking
"""

from __future__ import annotations

import datetime
import unittest

from ocagents.blackboard.dedupe import (
    FindingDeduplicator,
    compute_finding_fingerprint,
    derive_fingerprint,
    ensure_finding_id,
    extract_canonical_path,
    merge_duplicate_findings,
    normalize_fact,
)
from ocagents.blackboard.envelope import create_run_envelope
from ocagents.blackboard.lifecycle import (
    FindingLifecycleStatus,
    is_finding_expired,
    is_finding_invalidated_by_diff,
    parse_diff_modified_ranges,
    parse_ttl_string,
    transition_lifecycle_status,
)
from ocagents.blackboard.ranking import (
    calculate_corroboration_factor,
    calculate_priority_score,
    get_effective_confidence,
    rank_findings,
)
from ocagents.blackboard.store import BlackboardStore


class TestDeterministicFingerprinting(unittest.TestCase):
    """Validates deterministic fingerprinting and canonical extraction."""

    def test_extract_canonical_path(self):
        """Extracts normalized relative paths from various evidence URI formats."""
        self.assertEqual(
            extract_canonical_path("diff:terraform/s3.tf#L10-L15"),
            "terraform/s3.tf",
        )
        self.assertEqual(
            extract_canonical_path("repo:src/app/main.py#L42"),
            "src/app/main.py",
        )
        self.assertEqual(
            extract_canonical_path("diff:infra\\network\\vpc.tf#L5"),
            "infra/network/vpc.tf",
        )
        self.assertEqual(
            extract_canonical_path("cloud:aws:arn:aws:s3:::my-bucket"),
            "aws:arn:aws:s3:::my-bucket",
        )
        self.assertEqual(extract_canonical_path(""), "")

    def test_normalize_fact(self):
        """Normalizes facts by collapsing whitespace, newlines, and lowercasing."""
        raw = "  Bucket   force_destroy  \n  is TRUE  "
        expected = "bucket force_destroy is true"
        self.assertEqual(normalize_fact(raw), expected)

    def test_fingerprint_stability_and_invariance(self):
        """Fingerprint remains identical despite line offset shifts or formatting whitespace."""
        rule_id = "rules/01-destructive-actions.md"
        resource = "aws_s3_bucket.data"
        path = "terraform/s3.tf"
        fact1 = "Bucket force_destroy is true."
        fact2 = "  bucket   force_destroy  \n is  true.  "

        fp1 = derive_fingerprint(rule_id, resource, path, normalize_fact(fact1))
        fp2 = derive_fingerprint(rule_id, resource, path, normalize_fact(fact2))

        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

        # Different resource or path yields different fingerprint
        fp3 = derive_fingerprint(rule_id, "aws_s3_bucket.other", path, normalize_fact(fact1))
        self.assertNotEqual(fp1, fp3)

    def test_compute_finding_fingerprint(self):
        """Computes canonical fingerprint from finding dictionary."""
        f = {
            "rule_id": "rules/02-secrets-and-identity.md",
            "resource": "aws_iam_policy.admin",
            "evidence": "diff:iam/policy.json#L20-L35",
            "fact": "Wildcard action * allowed",
        }
        fp = compute_finding_fingerprint(f)
        self.assertEqual(len(fp), 64)

        # ensure_finding_id injects both id and fingerprint
        enriched = ensure_finding_id(dict(f))
        self.assertTrue(enriched["id"].startswith("FND-"))
        self.assertEqual(enriched["fingerprint"], fp)


class TestDeduplicationAndCorroboration(unittest.TestCase):
    """Validates cross-scanner deduplication, occurrence count, and promotion."""

    def test_merge_model_claim_with_linter(self):
        """Model claim merged with deterministic linter promotes to tool_verified."""
        existing = {
            "id": "FND-000000000001",
            "rule_id": "rules/01-destructive-actions.md",
            "resource": "aws_s3_bucket.data",
            "severity": "medium",
            "confidence": 0.85,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "security-compliance-commander",
            "corroborating_agents": ["security-compliance-commander"],
            "occurrence_count": 1,
        }

        incoming = {
            "id": "FND-000000000001",
            "rule_id": "rules/01-destructive-actions.md",
            "resource": "aws_s3_bucket.data",
            "severity": "critical",
            "confidence": None,
            "origin": "deterministic_linter",
            "corroboration_status": "tool_verified",
            "agent": "checkov",
        }

        merged = merge_duplicate_findings(existing, incoming)

        self.assertEqual(merged["occurrence_count"], 2)
        self.assertEqual(merged["corroboration_count"], 2)
        self.assertIn("security-compliance-commander", merged["corroborating_agents"])
        self.assertIn("checkov", merged["corroborating_agents"])
        self.assertEqual(merged["severity"], "critical")
        self.assertEqual(merged["origin"], "deterministic_linter")
        self.assertIsNone(merged["confidence"])
        self.assertEqual(merged["corroboration_status"], "tool_verified")
        self.assertIn("last_seen_utc", merged)

    def test_in_memory_finding_deduplicator(self):
        """FindingDeduplicator deduplicates findings across runs."""
        dedup = FindingDeduplicator()

        f1 = {
            "rule_id": "rules/01-destructive-actions.md",
            "resource": "aws_s3_bucket.vault",
            "evidence": "diff:s3.tf#L10",
            "fact": "force_destroy is true",
            "severity": "high",
            "confidence": 0.9,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "devsecops-reviewer",
        }

        f2 = dict(f1)
        f2["agent"] = "sre-reliability-engineer"

        id1 = dedup.ingest(f1)
        id2 = dedup.ingest(f2)

        self.assertEqual(id1, id2)
        self.assertEqual(dedup.count(), 1)

        result = dedup.get_by_id(id1)
        self.assertIsNotNone(result)
        self.assertEqual(result["occurrence_count"], 2)
        self.assertEqual(len(result["corroborating_agents"]), 2)


class TestLifecycleStateMachine(unittest.TestCase):
    """Validates lifecycle transitions and rules."""

    def test_valid_transitions(self):
        """Verifies canonical forward transitions."""
        self.assertEqual(
            transition_lifecycle_status("OPEN", "CORROBORATED"),
            FindingLifecycleStatus.CORROBORATED.value,
        )
        self.assertEqual(
            transition_lifecycle_status("CORROBORATED", "TRIAGED"),
            FindingLifecycleStatus.TRIAGED.value,
        )
        self.assertEqual(
            transition_lifecycle_status("TRIAGED", "RESOLVED"),
            FindingLifecycleStatus.RESOLVED.value,
        )
        self.assertEqual(
            transition_lifecycle_status("OPEN", "SUPERSEDED"),
            FindingLifecycleStatus.SUPERSEDED.value,
        )
        self.assertEqual(
            transition_lifecycle_status("OPEN", "EXPIRED"),
            FindingLifecycleStatus.EXPIRED.value,
        )

    def test_invalid_transition_raises_error(self):
        """Reversing or skipping invalid states raises ValueError."""
        with self.assertRaises(ValueError):
            transition_lifecycle_status("TRIAGED", "OPEN")

        with self.assertRaises(ValueError):
            transition_lifecycle_status("OPEN", "NONEXISTENT_STATE")

    def test_reopening_terminal_states(self):
        """Terminal states can transition back to OPEN if observed again."""
        self.assertEqual(
            transition_lifecycle_status("SUPERSEDED", "OPEN"),
            FindingLifecycleStatus.OPEN.value,
        )
        self.assertEqual(
            transition_lifecycle_status("EXPIRED", "OPEN"),
            FindingLifecycleStatus.OPEN.value,
        )


class TestDiffSourceInvalidation(unittest.TestCase):
    """Validates detection of modified and refactored line ranges in git diffs."""

    def setUp(self):
        self.sample_diff = """diff --git a/terraform/s3.tf b/terraform/s3.tf
index 1111111..2222222 100644
--- a/terraform/s3.tf
+++ b/terraform/s3.tf
@@ -10,4 +10,4 @@ resource "aws_s3_bucket" "data" {
-  force_destroy = true
+  force_destroy = false
   versioning {
diff --git a/old_config.json b/old_config.json
deleted file mode 100644
--- a/old_config.json
+++ /dev/null
@@ -1,3 +0,0 @@
-{"key": "val"}
"""

    def test_parse_diff_modified_ranges(self):
        """Parses deleted files and modified line ranges."""
        deleted_files, modified_ranges = parse_diff_modified_ranges(self.sample_diff)
        self.assertIn("old_config.json", deleted_files)
        self.assertIn("terraform/s3.tf", modified_ranges)
        self.assertEqual(modified_ranges["terraform/s3.tf"], [(10, 13)])

    def test_stale_finding_invalidated_by_overlapping_diff(self):
        """Finding on lines 10-12 in modified file is marked as invalidated."""
        f_stale = {
            "id": "FND-0001",
            "evidence": "diff:terraform/s3.tf#L10-L12",
            "lifecycle_status": "OPEN",
        }
        deleted_files, modified_ranges = parse_diff_modified_ranges(self.sample_diff)
        is_stale, reason = is_finding_invalidated_by_diff(f_stale, deleted_files, modified_ranges)

        self.assertTrue(is_stale)
        self.assertIn("modified by hunk", reason)

    def test_finding_on_unmodified_lines_not_invalidated(self):
        """Finding on line 80 in same file remains active."""
        f_active = {
            "id": "FND-0002",
            "evidence": "diff:terraform/s3.tf#L80-L90",
            "lifecycle_status": "OPEN",
        }
        deleted_files, modified_ranges = parse_diff_modified_ranges(self.sample_diff)
        is_stale, _ = is_finding_invalidated_by_diff(f_active, deleted_files, modified_ranges)

        self.assertFalse(is_stale)

    def test_finding_in_deleted_file_invalidated(self):
        """Finding in a deleted file is superseded."""
        f_deleted = {
            "id": "FND-0003",
            "evidence": "repo:old_config.json#L2",
            "lifecycle_status": "OPEN",
        }
        deleted_files, modified_ranges = parse_diff_modified_ranges(self.sample_diff)
        is_stale, reason = is_finding_invalidated_by_diff(f_deleted, deleted_files, modified_ranges)

        self.assertTrue(is_stale)
        self.assertIn("was deleted", reason)


class TestTTLExpiryAndCompaction(unittest.TestCase):
    """Validates TTL duration parsing and finding expiration logic."""

    def test_parse_ttl_string(self):
        """Parses human-readable TTL strings."""
        self.assertEqual(parse_ttl_string("14d"), 14 * 86400)
        self.assertEqual(parse_ttl_string("24h"), 24 * 3600)
        self.assertEqual(parse_ttl_string("30m"), 30 * 60)
        self.assertEqual(parse_ttl_string("60s"), 60)
        self.assertEqual(parse_ttl_string("3600"), 3600)

        with self.assertRaises(ValueError):
            parse_ttl_string("invalid_ttl")

    def test_is_finding_expired(self):
        """Detects findings older than TTL threshold."""
        now = datetime.datetime.now(datetime.timezone.utc)
        ten_days_ago = (now - datetime.timedelta(days=10)).isoformat().replace("+00:00", "Z")
        twenty_days_ago = (now - datetime.timedelta(days=20)).isoformat().replace("+00:00", "Z")

        f_recent = {"updated_at": ten_days_ago}
        f_old = {"updated_at": twenty_days_ago}

        ttl_14d = 14 * 86400
        self.assertFalse(is_finding_expired(f_recent, ttl_14d, reference_time=now))
        self.assertTrue(is_finding_expired(f_old, ttl_14d, reference_time=now))


class TestEvidenceRanking(unittest.TestCase):
    """Validates Priority = SeverityScore * Confidence * CorroborationFactor scoring."""

    def test_effective_confidence_contract(self):
        """Nullable confidence contract assigns 1.0 to deterministic linters."""
        self.assertEqual(get_effective_confidence(None), 1.0)
        self.assertEqual(get_effective_confidence(0.95), 0.95)
        # Bounded between 0.1 and 1.0
        self.assertEqual(get_effective_confidence(0.02), 0.1)

    def test_calculate_corroboration_factor(self):
        """Corroboration factor scales with status and observer count."""
        f_single = {"corroboration_status": "unverified_model_claim", "corroborating_agents": ["agent1"]}
        self.assertEqual(calculate_corroboration_factor(f_single), 1.0)

        f_two = {"corroboration_status": "model_corroborated", "corroborating_agents": ["agent1", "agent2"]}
        self.assertEqual(calculate_corroboration_factor(f_two), 1.25)

        f_tool = {"corroboration_status": "tool_verified", "corroborating_agents": ["agent1", "checkov"]}
        self.assertEqual(calculate_corroboration_factor(f_tool), 1.5)

        f_human = {"corroboration_status": "human_verified"}
        self.assertEqual(calculate_corroboration_factor(f_human), 2.0)

        f_fp = {"corroboration_status": "rejected_false_positive"}
        self.assertEqual(calculate_corroboration_factor(f_fp), 0.0)

    def test_calculate_priority_score(self):
        """Verifies exact composite score computation."""
        # Critical (4.0) * tool_verified (1.0 conf, 1.5 corrob) = 6.0
        f_crit = {
            "severity": "critical",
            "confidence": None,
            "corroboration_status": "tool_verified",
        }
        self.assertEqual(calculate_priority_score(f_crit), 6.0)

        # High (3.0) * 0.9 conf * 1.0 corrob = 2.7
        f_high = {
            "severity": "high",
            "confidence": 0.9,
            "corroboration_status": "unverified_model_claim",
            "corroborating_agents": ["agent1"],
        }
        self.assertEqual(calculate_priority_score(f_high), 2.7)

    def test_rank_findings_and_top_k_pruning(self):
        """rank_findings sorts by composite priority descending and respects limit_top_k."""
        f_low = {"id": "FND-LOW", "severity": "low", "confidence": 0.5, "corroboration_status": "unverified_model_claim"}
        f_med = {"id": "FND-MED", "severity": "medium", "confidence": 0.8, "corroboration_status": "unverified_model_claim"}
        f_crit = {"id": "FND-CRIT", "severity": "critical", "confidence": None, "corroboration_status": "tool_verified"}

        ranked = rank_findings([f_low, f_med, f_crit])
        self.assertEqual([f["id"] for f in ranked], ["FND-CRIT", "FND-MED", "FND-LOW"])

        # Top-K pruning
        top_1 = rank_findings([f_low, f_med, f_crit], limit_top_k=1)
        self.assertEqual(len(top_1), 1)
        self.assertEqual(top_1[0]["id"], "FND-CRIT")

        # Min confidence filtering
        high_conf_only = rank_findings([f_low, f_med, f_crit], min_confidence=0.7)
        # f_low (0.5) is filtered out; f_crit (None -> 1.0) and f_med (0.8) are retained
        self.assertEqual(len(high_conf_only), 2)
        self.assertEqual([f["id"] for f in high_conf_only], ["FND-CRIT", "FND-MED"])


class TestBlackboardStoreGovernanceIntegration(unittest.TestCase):
    """End-to-end integration tests for BlackboardStore anti-swamp features."""

    def setUp(self):
        self.store = BlackboardStore(":memory:")
        self.envelope = create_run_envelope(risk_tier=2, commit_sha="abcdef1234567890abcdef1234567890abcdef12")
        self.run_id = self.store.save_run(self.envelope)

    def tearDown(self):
        self.store.close()

    def test_fingerprint_deduplication_in_store(self):
        """Publishing duplicate findings with identical fingerprint merges in SQLite."""
        f1 = {
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Destructive Actions",
            "resource": "aws_s3_bucket.data",
            "evidence": "diff:terraform/s3.tf#L10",
            "fact": "Bucket force_destroy is true",
            "recommendation": "Remove force_destroy",
            "severity": "medium",
            "confidence": 0.8,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "security-compliance-commander",
        }

        f2 = dict(f1)
        f2["severity"] = "critical"
        f2["confidence"] = None
        f2["origin"] = "deterministic_linter"
        f2["corroboration_status"] = "tool_verified"
        f2["agent"] = "checkov"

        fid1 = self.store.publish_finding(f1, self.run_id)
        fid2 = self.store.publish_finding(f2, self.run_id)

        self.assertEqual(fid1, fid2)

        stored = self.store.get_finding(fid1)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["occurrence_count"], 2)
        self.assertEqual(stored["severity"], "critical")
        self.assertEqual(stored["corroboration_status"], "tool_verified")
        self.assertEqual(stored["lifecycle_status"], FindingLifecycleStatus.CORROBORATED.value)

    def test_diff_invalidation_in_store(self):
        """invalidate_by_diff updates matching finding lifecycle_status to SUPERSEDED."""
        f = {
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Destructive Actions",
            "resource": "aws_s3_bucket.data",
            "evidence": "diff:terraform/s3.tf#L10-L12",
            "fact": "force_destroy is true",
            "recommendation": "fix",
            "severity": "high",
            "confidence": 0.9,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "devsecops-reviewer",
        }
        fid = self.store.publish_finding(f, self.run_id)

        diff_text = """diff --git a/terraform/s3.tf b/terraform/s3.tf
--- a/terraform/s3.tf
+++ b/terraform/s3.tf
@@ -10,3 +10,3 @@
-  force_destroy = true
+  force_destroy = false
"""
        invalidated_ids = self.store.invalidate_by_diff(diff_text, run_id=self.run_id)
        self.assertIn(fid, invalidated_ids)

        updated = self.store.get_finding(fid)
        self.assertEqual(updated["lifecycle_status"], FindingLifecycleStatus.SUPERSEDED.value)

    def test_query_findings_with_ranking_and_top_k(self):
        """Querying findings with rank=True and limit_top_k returns ranked slice."""
        f_low = {
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "category": "FinOps",
            "resource": "res1",
            "evidence": "diff:a.tf#L1",
            "fact": "Idle volume",
            "recommendation": "Delete",
            "severity": "low",
            "confidence": 0.5,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "finops-cloud-cost-optimizer",
        }
        f_crit = {
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Security",
            "resource": "res2",
            "evidence": "diff:b.tf#L1",
            "fact": "Drop table",
            "recommendation": "Prevent",
            "severity": "critical",
            "confidence": None,
            "origin": "deterministic_linter",
            "corroboration_status": "tool_verified",
            "agent": "checkov",
        }

        self.store.publish_finding(f_low, self.run_id)
        self.store.publish_finding(f_crit, self.run_id)

        ranked = self.store.get_findings(run_id=self.run_id, rank=True, limit_top_k=1)
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0]["severity"], "critical")
        self.assertGreater(ranked[0]["priority_score"], 5.0)

    def test_prune_findings_by_ttl(self):
        """Prunes stale resolved findings and marks active expired findings."""
        now = datetime.datetime.now(datetime.timezone.utc)
        thirty_days_ago = (now - datetime.timedelta(days=30)).isoformat().replace("+00:00", "Z")

        f_old = {
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Security",
            "resource": "res_old",
            "evidence": "diff:old.tf#L1",
            "fact": "Old issue",
            "recommendation": "Fix",
            "severity": "low",
            "confidence": 0.5,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "devsecops-reviewer",
            "created_at": thirty_days_ago,
            "updated_at": thirty_days_ago,
        }
        fid = self.store.publish_finding(f_old, self.run_id)

        item = self.store.get_finding(fid)
        item["created_at"] = thirty_days_ago
        item["updated_at"] = thirty_days_ago
        item["last_seen_utc"] = thirty_days_ago

        # Force timestamps to thirty_days_ago
        with self.store._lock:
            import json

            self.store._conn.execute(
                "UPDATE findings SET created_at = ?, updated_at = ?, finding_json = ? WHERE id = ?",
                (thirty_days_ago, thirty_days_ago, json.dumps(item), fid),
            )

        # Run prune with ttl=14d
        summary = self.store.prune_findings(ttl="14d", dry_run=False, run_id=self.run_id)
        self.assertEqual(summary["expired_count"], 1)

        f_expired = self.store.get_finding(fid)
        self.assertEqual(f_expired["lifecycle_status"], FindingLifecycleStatus.EXPIRED.value)


if __name__ == "__main__":
    unittest.main()
