# Open Cloud Agents: Institutional Rego Policy
# Rule 01: Zero Unplanned Destruction (rules/01-destructive-actions.md)
# Enforces safeguards against accidental resource drops, database truncations, and forced replacements.

package open_cloud_agents.destructive_actions

import future.keywords.in

# 1. Block resource deletions in Terraform plan
violations[violation] {
    some resource in input.resource_changes
    actions := resource.change.actions
    "delete" in actions
    violation := {
        "rule_id": "rules/01-destructive-actions.md",
        "severity": "critical",
        "resource": resource.address,
        "title": sprintf("Resource '%s' is scheduled for deletion (actions: %v)", [resource.address, actions]),
        "recommendation": "Destructive deletion blocked by default. Obtain explicit human maintainer sign-off or add lifecycle prevent_destroy.",
        "line": 1
    }
}

# 2. Block forced replacements on stateful resources (databases, persistent disks, buckets)
violations[violation] {
    some resource in input.resource_changes
    actions := resource.change.actions
    "delete" in actions
    "create" in actions
    is_stateful_resource(resource.type)
    violation := {
        "rule_id": "rules/01-destructive-actions.md",
        "severity": "critical",
        "resource": resource.address,
        "title": sprintf("Stateful resource '%s' (%s) triggers forced replacement (delete + create)", [resource.address, resource.type]),
        "recommendation": "Forced replacement will destroy existing state/data. Migrate in-place or isolate changes to non-destructive attributes.",
        "line": 1
    }
}

# 3. Block explicit force_destroy flag in IaC attributes
violations[violation] {
    some resource in input.resource_changes
    resource.change.after.force_destroy == true
    violation := {
        "rule_id": "rules/01-destructive-actions.md",
        "severity": "critical",
        "resource": resource.address,
        "title": sprintf("Resource '%s' enables force_destroy", [resource.address]),
        "recommendation": "Disable force_destroy to prevent catastrophic automated data loss on bucket or cluster deletion.",
        "line": 1
    }
}

is_stateful_resource(type) {
    stateful_prefixes := [
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_s3_bucket",
        "google_sql_database_instance",
        "google_storage_bucket",
        "azurerm_mssql_database",
        "azurerm_storage_account",
        "kubernetes_persistent_volume"
    ]
    some prefix in stateful_prefixes
    startswith(type, prefix)
}
