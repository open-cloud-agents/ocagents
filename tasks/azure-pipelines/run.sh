#!/usr/bin/env bash
# ==============================================================================
# Open Cloud Agents: Azure DevOps Task Execution Script (ADR-003, Issue #108)
# ==============================================================================
set -euo pipefail

echo "============================================================"
echo " 🌐 Open Cloud Agents: Azure DevOps Quality Gate (v2.1)"
echo "============================================================"

# Ensure ocagents is available or install via pip
if ! command -v ocagents &> /dev/null; then
  echo "📦 Installing open-cloud-agents..."
  python3 -m pip install --no-cache-dir --quiet --upgrade pip
  python3 -m pip install --no-cache-dir --quiet open-cloud-agents
fi

RISK_TIER="${INPUT_RISK_TIER:-auto}"
FAIL_ON_P0="${INPUT_FAIL_ON_P0:-true}"
OFFLINE_MODE="${INPUT_OFFLINE_MODE:-false}"
SARIF_OUTPUT="${INPUT_SARIF_OUTPUT:-$(pwd)/ocagents.sarif}"

mkdir -p "$(dirname "$SARIF_OUTPUT")"

echo "🔍 Changeset Risk Tier: $RISK_TIER"
echo "🔍 Running Deterministic Pre-Flight Gate..."
PREFLIGHT_FLAGS=()
if [ "$OFFLINE_MODE" = "true" ]; then
  PREFLIGHT_FLAGS+=("--offline")
fi

set +e
ocagents preflight "${PREFLIGHT_FLAGS[@]}"
PREFLIGHT_EXIT=$?
set -e

if [ "$PREFLIGHT_EXIT" -ne 0 ] && [ "$PREFLIGHT_EXIT" -ne 2 ]; then
  echo "❌ Deterministic pre-flight checks failed (exit $PREFLIGHT_EXIT)."
  if [ "$FAIL_ON_P0" = "true" ]; then
    exit "$PREFLIGHT_EXIT"
  fi
fi

# Export findings to native SARIF 2.1.0 log
echo "📋 Exporting findings to SARIF: $SARIF_OUTPUT"
ocagents findings export --format sarif --out "$SARIF_OUTPUT" || true

# Upload SARIF artifact for Azure DevOps Code Analysis
echo "##vso[artifact.upload containerfolder=CodeAnalysisLogs;artifactname=CodeAnalysisLogs]$SARIF_OUTPUT"

echo "✔ Open Cloud Agents Azure DevOps quality gate completed successfully."
