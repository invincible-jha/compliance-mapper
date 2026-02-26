#!/usr/bin/env bash
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2026 MuVeraAI Corporation
#
# fire-line-audit.sh — Verify compliance-mapper source files respect scope boundaries.
# Exits non-zero if any fire-line violation is found.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VIOLATIONS=0
WARNINGS=0

echo "=== compliance-mapper Fire Line Audit ==="
echo "Repository: ${REPO_ROOT}"
echo ""

# ── 1. Forbidden identifiers ────────────────────────────────────────────────

FORBIDDEN_IDENTIFIERS=(
  "progressLevel"
  "promoteLevel"
  "computeTrustScore"
  "behavioralScore"
  "adaptiveBudget"
  "optimizeBudget"
  "predictSpending"
  "detectAnomaly"
  "generateCounterfactual"
  "PersonalWorldModel"
  "MissionAlignment"
  "SocialTrust"
  "CognitiveLoop"
  "AttentionFilter"
  "GOVERNANCE_PIPELINE"
)

echo "--- Checking for forbidden identifiers ---"
for identifier in "${FORBIDDEN_IDENTIFIERS[@]}"; do
  results=$(grep -rn --include="*.ts" --include="*.py" "${identifier}" "${REPO_ROOT}/typescript/src" "${REPO_ROOT}/python/src" "${REPO_ROOT}/examples" 2>/dev/null || true)
  if [[ -n "${results}" ]]; then
    echo "VIOLATION: Forbidden identifier '${identifier}' found:"
    echo "${results}"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done

# ── 2. Jurisdiction-specific regulations ────────────────────────────────────

OUT_OF_SCOPE_JURISDICTIONS=(
  "DPDPA"
  "IT Act"
  "CCPA"
  "CPRA"
  "PIPL"
  "LGPD"
  "CERT-In"
)

echo ""
echo "--- Checking for out-of-scope jurisdiction-specific regulations ---"
for regulation in "${OUT_OF_SCOPE_JURISDICTIONS[@]}"; do
  results=$(grep -rn --include="*.ts" --include="*.py" "${regulation}" "${REPO_ROOT}/typescript/src" "${REPO_ROOT}/python/src" 2>/dev/null || true)
  if [[ -n "${results}" ]]; then
    echo "VIOLATION: Out-of-scope regulation '${regulation}' found in source:"
    echo "${results}"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done

# ── 3. Vertical-specific regulations ────────────────────────────────────────

OUT_OF_SCOPE_VERTICALS=(
  "HIPAA"
  "HITECH"
  "FINRA"
  "SOX"
  "Sarbanes"
  "PCI.DSS"
  "PCIDSS"
  "FedRAMP"
  "FISMA"
  "CMMC"
  "GLBA"
)

echo ""
echo "--- Checking for out-of-scope vertical-specific regulations ---"
for vertical in "${OUT_OF_SCOPE_VERTICALS[@]}"; do
  results=$(grep -rn --include="*.ts" --include="*.py" "${vertical}" "${REPO_ROOT}/typescript/src" "${REPO_ROOT}/python/src" 2>/dev/null || true)
  if [[ -n "${results}" ]]; then
    echo "VIOLATION: Out-of-scope vertical regulation '${vertical}' found in source:"
    echo "${results}"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done

# ── 4. Continuous monitoring patterns ───────────────────────────────────────

CONTINUOUS_MONITORING_PATTERNS=(
  "continuousMonitor"
  "realtimeAlert"
  "real_time_alert"
  "startMonitoring"
  "watchdog"
  "autoRemediat"
  "auto_remediat"
)

echo ""
echo "--- Checking for continuous monitoring patterns ---"
for pattern in "${CONTINUOUS_MONITORING_PATTERNS[@]}"; do
  results=$(grep -rn --include="*.ts" --include="*.py" -i "${pattern}" "${REPO_ROOT}/typescript/src" "${REPO_ROOT}/python/src" 2>/dev/null || true)
  if [[ -n "${results}" ]]; then
    echo "WARNING: Potential continuous monitoring pattern '${pattern}' found:"
    echo "${results}"
    WARNINGS=$((WARNINGS + 1))
  fi
done

# ── 5. SPDX header presence ─────────────────────────────────────────────────

echo ""
echo "--- Checking for SPDX headers ---"

# TypeScript files
while IFS= read -r -d '' tsfile; do
  if ! grep -q "SPDX-License-Identifier: BSL-1.1" "${tsfile}"; then
    echo "VIOLATION: Missing SPDX header in TypeScript file: ${tsfile}"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done < <(find "${REPO_ROOT}/typescript/src" -name "*.ts" -print0 2>/dev/null)

# Python files
while IFS= read -r -d '' pyfile; do
  if ! grep -q "SPDX-License-Identifier: BSL-1.1" "${pyfile}"; then
    echo "VIOLATION: Missing SPDX header in Python file: ${pyfile}"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done < <(find "${REPO_ROOT}/python/src" -name "*.py" -print0 2>/dev/null)

# Example files
while IFS= read -r -d '' exfile; do
  if ! grep -q "SPDX-License-Identifier: BSL-1.1" "${exfile}"; then
    echo "VIOLATION: Missing SPDX header in example file: ${exfile}"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done < <(find "${REPO_ROOT}/examples" -name "*.py" -print0 2>/dev/null)

# ── 6. Summary ───────────────────────────────────────────────────────────────

echo ""
echo "=== Audit Complete ==="
echo "Violations: ${VIOLATIONS}"
echo "Warnings:   ${WARNINGS}"
echo ""

if [[ ${VIOLATIONS} -gt 0 ]]; then
  echo "FAILED — ${VIOLATIONS} fire-line violation(s) must be resolved."
  exit 1
elif [[ ${WARNINGS} -gt 0 ]]; then
  echo "PASSED with ${WARNINGS} warning(s) — review patterns manually."
  exit 0
else
  echo "PASSED — No fire-line violations detected."
  exit 0
fi
