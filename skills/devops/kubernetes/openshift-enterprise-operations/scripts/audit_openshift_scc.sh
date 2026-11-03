#!/usr/bin/env bash
set -euo pipefail

# audit_openshift_scc.sh - Automated scanner for dangerous OpenShift SCC bindings & insecure routes

TARGET_DIR="${1:-.}"
echo "=========================================================="
echo "🛡️  OpenShift Security & Route Static Scanner"
echo "Target directory: $TARGET_DIR"
echo "=========================================================="

VIOLATIONS=0

# 1. Scan for dangerous SCC rolebindings (anyuid or privileged)
echo "ℹ Checking for dangerous SCC bindings (anyuid / privileged)..."
while IFS= read -r match; do
  echo "  ✖ [CRITICAL] High-privilege SCC detected: $match"
  echo "    ↳ Remediation: Avoid anyuid/privileged. Standardize workloads on restricted-v2 SCC."
  VIOLATIONS=$((VIOLATIONS + 1))
done < <(grep -rnE '(scc:anyuid|scc:privileged|name:\s*privileged|name:\s*anyuid)' "$TARGET_DIR" --include="*.yml" --include="*.yaml" 2>/dev/null || true)

# 2. Scan for unencrypted OpenShift Routes
echo "ℹ Checking OpenShift Routes for missing or insecure TLS..."
while IFS= read -r file; do
  if grep -qE 'kind:\s*Route' "$file"; then
    if ! grep -qE 'termination:' "$file"; then
      echo "  ✖ [HIGH] Route '$file' lacks 'tls.termination' block (plain HTTP)."
      echo "    ↳ Remediation: Configure edge, reencrypt, or passthrough TLS termination."
      VIOLATIONS=$((VIOLATIONS + 1))
    elif grep -qE 'insecureEdgeTerminationPolicy:\s*Allow' "$file"; then
      echo "  ✖ [HIGH] Route '$file' allows insecure unencrypted edge termination."
      echo "    ↳ Remediation: Set 'insecureEdgeTerminationPolicy: Redirect'."
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  fi
done < <(find "$TARGET_DIR" -name "*.yml" -o -name "*.yaml" 2>/dev/null)

echo "=========================================================="
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "✔ All OpenShift manifests passed SCC and Route security checks cleanly!"
  exit 0
else
  echo "✖ Total OpenShift security violations/warnings found: $VIOLATIONS"
  exit 1
fi

