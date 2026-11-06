# Open Cloud Agents: Institutional Rego Policy
# Rule 04: Cloud Well-Architected Invariants (rules/04-cloud-well-architected-invariants.md)
# Enforces encryption at rest, multi-AZ disaster recovery, Kubernetes QoS, and container security.

package open_cloud_agents.well_architected

import future.keywords.in

# 1. Kubernetes: Container must not run as privileged
violations[violation] {
    is_workload(input.kind)
    some container in input.spec.template.spec.containers
    container.securityContext.privileged == true
    violation := {
        "rule_id": "rules/04-cloud-well-architected-invariants.md",
        "severity": "critical",
        "resource": sprintf("%s/%s", [lower(input.kind), input.metadata.name]),
        "title": sprintf("Container '%s' in %s '%s' is configured as privileged", [container.name, input.kind, input.metadata.name]),
        "recommendation": "Set securityContext.privileged = false to prevent host filesystem and device compromise.",
        "line": 1
    }
}

# 2. Kubernetes: Container must specify memory limits to guarantee QoS and avoid OOM eviction
violations[violation] {
    is_workload(input.kind)
    some container in input.spec.template.spec.containers
    not container.resources.limits.memory
    violation := {
        "rule_id": "rules/04-cloud-well-architected-invariants.md",
        "severity": "high",
        "resource": sprintf("%s/%s", [lower(input.kind), input.metadata.name]),
        "title": sprintf("Container '%s' in %s '%s' is missing memory limit", [container.name, input.kind, input.metadata.name]),
        "recommendation": "Configure matching resources.limits.memory and resources.requests.memory to guarantee QoS and prevent node OOM cascade.",
        "line": 1
    }
}

# 3. Kubernetes: Production workloads must define readiness probes
violations[violation] {
    is_workload(input.kind)
    some container in input.spec.template.spec.containers
    not container.readinessProbe
    violation := {
        "rule_id": "rules/04-cloud-well-architected-invariants.md",
        "severity": "medium",
        "resource": sprintf("%s/%s", [lower(input.kind), input.metadata.name]),
        "title": sprintf("Container '%s' in %s '%s' has no readinessProbe defined", [container.name, input.kind, input.metadata.name]),
        "recommendation": "Add readinessProbe to ensure traffic is only routed after application startup and dependencies are ready.",
        "line": 1
    }
}

# 4. Terraform: S3 Bucket must have server-side encryption enabled
violations[violation] {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    after := resource.change.after
    not after.server_side_encryption_configuration
    violation := {
        "rule_id": "rules/04-cloud-well-architected-invariants.md",
        "severity": "high",
        "resource": resource.address,
        "title": sprintf("S3 Bucket '%s' has no server-side encryption configuration", [resource.address]),
        "recommendation": "Configure server_side_encryption_configuration with KMS (aws:kms) to satisfy encryption at rest invariants.",
        "line": 1
    }
}

# 5. Terraform: Relational databases must specify multi_az = true
violations[violation] {
    some resource in input.resource_changes
    resource.type == "aws_db_instance"
    after := resource.change.after
    after.multi_az != true
    violation := {
        "rule_id": "rules/04-cloud-well-architected-invariants.md",
        "severity": "high",
        "resource": resource.address,
        "title": sprintf("Database '%s' is not configured for Multi-AZ deployment (multi_az != true)", [resource.address]),
        "recommendation": "Set multi_az = true to satisfy high-availability and disaster recovery RTO/RPO requirements.",
        "line": 1
    }
}

is_workload(kind) {
    workload_kinds := ["Deployment", "StatefulSet", "DaemonSet", "Job", "Pod"]
    kind in workload_kinds
}
