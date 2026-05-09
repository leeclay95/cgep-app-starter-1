#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
##
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
CURRENT_DATE=$(date +%Y-%m-%d)
EVIDENCE_DIR="evidence/${CURRENT_DATE}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path> [--policy <dir>]" >&2; exit 2; }

WORKSPACE=$(realpath "$WORKSPACE")
POLICY_DIR=$(realpath "$POLICY_DIR")
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_DIR=$(realpath "$EVIDENCE_DIR")

if [[ -f "$WORKSPACE/tfplan" ]]; then
  echo "==> Generating plan.json from $WORKSPACE/tfplan"
  terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"
elif [[ -f "$WORKSPACE/plan.json" ]]; then
  echo "==> Using existing $WORKSPACE/plan.json"
else
  echo "ERROR: No tfplan or plan.json in $WORKSPACE" >&2; exit 2
fi

echo "==> Running conftest"
echo "    Workspace : $WORKSPACE"
echo "    Policies  : $POLICY_DIR"
echo "    Evidence  : $EVIDENCE_DIR/conftest-results.json"
echo ""

# Run conftest and save output
conftest test \
  "$WORKSPACE/plan.json" \
  --policy "$POLICY_DIR" \
  --output json \
  > "$EVIDENCE_DIR/conftest-results.json" 2>&1 || true

# Count failures and print violations
FAILURES=$(python3 - "$EVIDENCE_DIR/conftest-results.json" << 'PYEOF'
import json, sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception as e:
    print(f"WARN: {e}", file=sys.stderr)
    print(0)
    sys.exit(0)

results = data if isinstance(data, list) else [data]
total = 0
for r in results:
    for failure in (r.get("failures") or []):
        total += 1
        print(f"  VIOLATION: {failure.get('msg', failure)}", file=sys.stderr)

print(total)
PYEOF
)

echo "==> Results"
echo "    Failures : $FAILURES"
echo "    Evidence : $EVIDENCE_DIR/conftest-results.json"
echo ""

if [[ "$FAILURES" -eq 0 ]]; then
  echo "policy-gate: PASS"
  exit 0
else
  echo "policy-gate: FAIL ($FAILURES violation(s))"
  exit 1
fi
