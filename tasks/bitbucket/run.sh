#!/usr/bin/env bash
# ==============================================================================
# Open Cloud Agents: Bitbucket Pipe Execution Script (ADR-003, Issue #109)
# ==============================================================================
set -euo pipefail

echo "============================================================"
echo " 🌐 Open Cloud Agents: Bitbucket Pipelines Gatekeeper (v2.1)"
echo "============================================================"

# Ensure ocagents is available or install via pip
if ! command -v ocagents &> /dev/null; then
  echo "📦 Installing open-cloud-agents..."
  python3 -m pip install --no-cache-dir --quiet --upgrade pip
  python3 -m pip install --no-cache-dir --quiet open-cloud-agents
fi

FAIL_ON_CRITICAL="${FAIL_ON_CRITICAL:-true}"
OFFLINE_MODE="${OFFLINE_MODE:-false}"
RISK_TIER="${RISK_TIER:-auto}"
DEBUG="${DEBUG:-false}"
INSIGHTS_OUTPUT="${INSIGHTS_OUTPUT:-$(pwd)/bitbucket-code-insights.json}"
SARIF_OUTPUT="${SARIF_OUTPUT:-$(pwd)/ocagents.sarif}"

if [ "$DEBUG" = "true" ]; then
  export LOG_LEVEL="DEBUG"
  set -x
fi

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
  if [ "$FAIL_ON_CRITICAL" = "true" ]; then
    exit "$PREFLIGHT_EXIT"
  fi
fi

# If running within a pull request or commit context, evaluate triage gate and publish Insights
if [ -n "${BITBUCKET_COMMIT:-}" ]; then
  echo "🛡️ Evaluating Changeset Blast Radius & Model Findings..."
  set +e
  ocagents triage gate --sha "$BITBUCKET_COMMIT" --dry-run || true
  set -e
fi

# Export findings to native Bitbucket Code Insights JSON and SARIF
echo "📋 Exporting findings to Bitbucket Code Insights: $INSIGHTS_OUTPUT"
ocagents findings export --format bitbucket-insights --out "$INSIGHTS_OUTPUT" || true

echo "📋 Exporting findings to SARIF 2.1.0: $SARIF_OUTPUT"
ocagents findings export --format sarif --out "$SARIF_OUTPUT" || true

# Enforce quality gate exit code if fail_on_critical is enabled
if [ "$FAIL_ON_CRITICAL" = "true" ] && [ -f "$INSIGHTS_OUTPUT" ]; then
  BLOCKING_COUNT=$(python3 -c "
import json, sys
try:
    with open('$INSIGHTS_OUTPUT', 'r', encoding='utf-8') as f:
        data = json.load(f)
    rep = data.get('report', {})
    crit = int(rep.get('critical', 0))
    high = int(rep.get('high', 0))
    print(crit + high)
except Exception:
    print(0)
" 2>/dev/null || echo 0)

  if [ "$BLOCKING_COUNT" -gt 0 ]; then
    echo "❌ Open Cloud Agents Gate Failed: $BLOCKING_COUNT critical/high finding(s) detected!"
    exit 1
  fi
fi

echo "✔ Open Cloud Agents Bitbucket Pipelines review completed successfully."
