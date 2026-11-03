#!/usr/bin/env bash
set -euo pipefail

# audit_playbook_hygiene.sh - Automated scanner for Ansible playbook hygiene & security risks

TARGET_DIR="${1:-.}"
echo "=========================================================="
echo "🛡️  Ansible Playbook Hygiene & Security Static Scanner"
echo "Target directory: $TARGET_DIR"
echo "=========================================================="

VIOLATIONS=0

# 1. Scan for global 'become: true' at play level
echo "ℹ Checking for overprivileged global 'become: true'..."
while IFS= read -r match; do
  echo "  ✖ [HIGH] Global 'become: true' detected: $match"
  echo "    ↳ Remediation: Scope 'become: true' strictly to tasks requiring elevated privileges."
  VIOLATIONS=$((VIOLATIONS + 1))
done < <(grep -rnE '^\s*-\s*hosts:.*' "$TARGET_DIR" -A 2 2>/dev/null | grep -E '^\s*become:\s*true' || true)

# 2. Scan for unquoted Jinja2 variables (syntax trap)
echo "ℹ Checking for unquoted Jinja2 template expressions..."
while IFS= read -r match; do
  echo "  ✖ [WARN] Unquoted Jinja2 expression detected: $match"
  echo "    ↳ Remediation: Wrap Jinja2 expressions in double quotes: \"{{ var }}\""
  VIOLATIONS=$((VIOLATIONS + 1))
done < <(grep -rnE ':\s*\{\{' "$TARGET_DIR" --include="*.yml" --include="*.yaml" 2>/dev/null || true)

# 3. Scan for unguarded command/shell tasks
echo "ℹ Checking for command/shell tasks without changed_when/creates..."
while IFS= read -r file; do
  if grep -qE 'ansible\.builtin\.(command|shell):' "$file"; then
    if ! grep -qE '(changed_when|creates|removes)' "$file"; then
      echo "  ✖ [WARN] File '$file' uses command/shell without explicit changed_when or creates."
      echo "    ↳ Remediation: Ensure tasks are idempotent or declare changed_when."
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  fi
done < <(find "$TARGET_DIR" -name "*.yml" -o -name "*.yaml" 2>/dev/null)

echo "=========================================================="
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "✔ All Ansible playbooks passed hygiene checks cleanly!"
  exit 0
else
  echo "✖ Total hygiene warnings/violations found: $VIOLATIONS"
  exit 1
fi

