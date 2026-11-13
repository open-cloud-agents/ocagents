"""
Open Cloud Agents: Versioned Synthetic Evaluation Callsets (TASK-4.6).

Defines reproducible benchmark scenarios across risk tiers (Tier 0-2) and ground truth findings
for confidence threshold calibration.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

BENCHMARK_VERSION = "2026.11-v1"


@dataclass
class GroundTruthFinding:
    """Ground truth finding item used to benchmark detection accuracy and confidence calibration."""

    finding_id: str
    rule_id: str
    category: str
    resource: str
    fact: str
    severity: str
    is_true_positive: bool
    model_confidence: float

    def to_dict(self) -> dict[str, Any]:
        """Converts ground truth finding to dictionary."""
        return asdict(self)


@dataclass
class BenchmarkScenario:
    """A benchmark test scenario representing a distinct PR changeset and operational workload."""

    scenario_id: str
    name: str
    risk_tier: int
    description: str
    files_changed: list[str]
    diff_hunk_bytes: int
    expected_blackboard_agents: list[str]
    ground_truth_findings: list[GroundTruthFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Converts benchmark scenario to dictionary."""
        d = asdict(self)
        d["ground_truth_findings"] = [f.to_dict() for f in self.ground_truth_findings]
        return d


def load_benchmark_callsets() -> list[BenchmarkScenario]:
    """
    Loads the canonical versioned synthetic evaluation callsets (v2026.11-v1).
    Spans Tier 0 (docs), Tier 1 (application logic), and Tier 2 (high blast radius IaC).
    """
    scenarios: list[BenchmarkScenario] = [
        # Scenario 1: Tier 0 Documentation & Non-Code Assets (LLM Bypass)
        BenchmarkScenario(
            scenario_id="SCN-01-DOCS",
            name="Documentation & Non-Code Assets Update",
            risk_tier=0,
            description="Documentation, architectural diagram images, and Markdown guides.",
            files_changed=[
                "README.md",
                "docs/architecture-overview.md",
                "docs/adr-002-blackboard-findings.md",
                "assets/diagram.png",
                "CHANGELOG.md",
            ],
            diff_hunk_bytes=3800,
            expected_blackboard_agents=[],
            ground_truth_findings=[],
        ),
        # Scenario 2: Tier 1 Application Code Logic Only
        BenchmarkScenario(
            scenario_id="SCN-02-APP-LOGIC",
            name="Microservice API Route & Handler Refactoring",
            risk_tier=1,
            description="Python application code modifying REST route handlers and JWT verification.",
            files_changed=[
                "src/api/auth.py",
                "src/api/routes.py",
                "tests/test_auth.py",
                "pyproject.toml",
            ],
            diff_hunk_bytes=5200,
            expected_blackboard_agents=["devsecops-reviewer"],
            ground_truth_findings=[
                GroundTruthFinding(
                    finding_id="FND-APP-00000001",
                    rule_id="rules/02-secrets-and-identity.md",
                    category="Authentication & Token Handling",
                    resource="src/api/auth.py:verify_jwt",
                    fact="Hardcoded fallback HMAC signing secret detected in test fixture branch",
                    severity="high",
                    is_true_positive=True,
                    model_confidence=0.94,
                ),
                GroundTruthFinding(
                    finding_id="FND-APP-00000002",
                    rule_id="rules/03-surgical-scope-discipline.md",
                    category="API Design & Scope",
                    resource="src/api/routes.py:list_items",
                    fact="Missing pagination limit on query parameter could lead to memory exhaustion",
                    severity="medium",
                    is_true_positive=True,
                    model_confidence=0.87,
                ),
                GroundTruthFinding(
                    finding_id="FND-APP-00000003",
                    rule_id="rules/05-repository-and-path-hygiene.md",
                    category="Lint & Hygiene",
                    resource="src/api/auth.py:import",
                    fact="Unused import os in module header",
                    severity="low",
                    is_true_positive=False,  # Synthetic false positive
                    model_confidence=0.62,
                ),
            ],
        ),
        # Scenario 3: Tier 2 Multi-Region Database Disaster Recovery
        BenchmarkScenario(
            scenario_id="SCN-03-MULTIREGION-DR",
            name="Multi-Region Aurora Global Database & VPC Peering",
            risk_tier=2,
            description="Terraform infrastructure deploying Aurora PostgreSQL cross-region replica with peering.",
            files_changed=[
                "terraform/aurora_global.tf",
                "terraform/vpc_peering.tf",
                "terraform/variables.tf",
                "k8s/database-secret.yaml",
                ".github/workflows/deploy.yml",
            ],
            diff_hunk_bytes=8900,
            expected_blackboard_agents=[
                "principal-cloud-architect",
                "security-compliance-commander",
                "finops-cloud-cost-optimizer",
                "sre-reliability-engineer",
                "devsecops-reviewer",
            ],
            ground_truth_findings=[
                GroundTruthFinding(
                    finding_id="FND-DR-00000001",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="Disaster Recovery & Multi-Region",
                    resource="aws_rds_global_cluster.aurora",
                    fact="Secondary region cluster lacks automated cross-region snapshot replication",
                    severity="high",
                    is_true_positive=True,
                    model_confidence=0.93,
                ),
                GroundTruthFinding(
                    finding_id="FND-DR-00000002",
                    rule_id="rules/01-destructive-actions.md",
                    category="State Protection",
                    resource="aws_rds_cluster.primary",
                    fact="lifecycle prevent_destroy is omitted on primary production database cluster",
                    severity="critical",
                    is_true_positive=True,
                    model_confidence=0.97,
                ),
                GroundTruthFinding(
                    finding_id="FND-DR-00000003",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="Cost & FinOps",
                    resource="aws_vpc_peering_connection.cross_region",
                    fact="Inter-region egress data transfer costs unmodeled for high-volume replication",
                    severity="medium",
                    is_true_positive=True,
                    model_confidence=0.88,
                ),
                GroundTruthFinding(
                    finding_id="FND-DR-00000004",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="Observability",
                    resource="datadog_monitor.replication_lag",
                    fact="AuroraGlobalDBRPOLag monitor window threshold is overly sensitive (<10s)",
                    severity="low",
                    is_true_positive=False,  # False positive: 10s is appropriate for financial ledger
                    model_confidence=0.74,
                ),
            ],
        ),
        # Scenario 4: Tier 2 Security-Critical Wildcard IAM & Public Storage
        BenchmarkScenario(
            scenario_id="SCN-04-SECURITY-CRITICAL",
            name="Critical IAM Permission & Public S3 Bucket Exposure",
            risk_tier=2,
            description="Terraform changes adding IAM assume-role policies and S3 bucket definitions.",
            files_changed=[
                "terraform/iam_roles.tf",
                "terraform/s3_buckets.tf",
                "terraform/security_groups.tf",
            ],
            diff_hunk_bytes=6400,
            expected_blackboard_agents=[
                "principal-cloud-architect",
                "security-compliance-commander",
                "finops-cloud-cost-optimizer",
                "sre-reliability-engineer",
                "devsecops-reviewer",
            ],
            ground_truth_findings=[
                GroundTruthFinding(
                    finding_id="FND-SEC-00000001",
                    rule_id="rules/02-secrets-and-identity.md",
                    category="IAM & Least Privilege",
                    resource="aws_iam_policy.workload",
                    fact="Action: * specified across all resources without conditions (administrative privilege)",
                    severity="critical",
                    is_true_positive=True,
                    model_confidence=0.99,
                ),
                GroundTruthFinding(
                    finding_id="FND-SEC-00000002",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="Data Encryption & Public Access",
                    resource="aws_s3_bucket.artifacts",
                    fact="Bucket public read enabled and KMS customer-managed envelope encryption disabled",
                    severity="critical",
                    is_true_positive=True,
                    model_confidence=0.96,
                ),
                GroundTruthFinding(
                    finding_id="FND-SEC-00000003",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="Network Security",
                    resource="aws_security_group.app",
                    fact="Ingress from 0.0.0.0/0 on port 22 (SSH) open to public internet",
                    severity="high",
                    is_true_positive=True,
                    model_confidence=0.95,
                ),
                GroundTruthFinding(
                    finding_id="FND-SEC-00000004",
                    rule_id="rules/02-secrets-and-identity.md",
                    category="Token Expiry",
                    resource="aws_iam_role.ci_runner",
                    fact="max_session_duration set to 3600s instead of recommended 1800s",
                    severity="low",
                    is_true_positive=False,  # False positive: 1hr is standard for CI jobs
                    model_confidence=0.69,
                ),
            ],
        ),
        # Scenario 5: Tier 2 FinOps Cloud Waste & Idle Resources
        BenchmarkScenario(
            scenario_id="SCN-05-FINOPS-WASTE",
            name="Idle Cloud NAT Gateways & Unattached EBS Volumes",
            risk_tier=2,
            description="Terraform configurations with oversized compute instances and redundant NATs.",
            files_changed=[
                "terraform/nat_gateways.tf",
                "terraform/ebs_volumes.tf",
                "terraform/ec2_instances.tf",
            ],
            diff_hunk_bytes=5800,
            expected_blackboard_agents=[
                "principal-cloud-architect",
                "security-compliance-commander",
                "finops-cloud-cost-optimizer",
                "sre-reliability-engineer",
                "devsecops-reviewer",
            ],
            ground_truth_findings=[
                GroundTruthFinding(
                    finding_id="FND-FIN-00000001",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="FinOps Cost Waste",
                    resource="aws_nat_gateway.az3",
                    fact="Cloud NAT Gateway provisioned in AZ with zero private route table associations ($32.40/mo idle fee)",
                    severity="medium",
                    is_true_positive=True,
                    model_confidence=0.92,
                ),
                GroundTruthFinding(
                    finding_id="FND-FIN-00000002",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="FinOps Cost Waste",
                    resource="aws_ebs_volume.scratch",
                    fact="Unattached 500GB io2 EBS volume provisioned without instance attachment",
                    severity="medium",
                    is_true_positive=True,
                    model_confidence=0.89,
                ),
                GroundTruthFinding(
                    finding_id="FND-FIN-00000003",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="Instance Sizing",
                    resource="aws_instance.bastion",
                    fact="Instance type c5.2xlarge allocated for administrative bastion host",
                    severity="low",
                    is_true_positive=True,
                    model_confidence=0.86,
                ),
                GroundTruthFinding(
                    finding_id="FND-FIN-00000004",
                    rule_id="rules/04-cloud-well-architected-invariants.md",
                    category="Reserved Instances",
                    resource="aws_instance.worker",
                    fact="Suggest Purchasing 3-year All-Upfront Reserved Instance immediately",
                    severity="low",
                    is_true_positive=False,  # False positive: dev environment does not warrant 3-yr commit
                    model_confidence=0.71,
                ),
            ],
        ),
    ]
    return scenarios
