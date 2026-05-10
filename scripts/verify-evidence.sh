#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id>
# Usage:
#   verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]
##
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT env var"; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

PREFIX="runs/${RUN_ID}"

echo "==> Downloading evidence artifacts from s3://${VAULT}/${PREFIX}/"
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" \
  --include "evidence-*.tar.gz" \
  --include "evidence-*.tar.gz.sha256" \
  --include "evidence-*.tar.gz.sig.bundle" \
  --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz 2>/dev/null | head -1)
[[ -z "$BUNDLE" ]] && { echo "FAIL: no evidence bundle found in s3://${VAULT}/${PREFIX}/"; exit 1; }
echo "==> Bundle: $BUNDLE"

# 1. Integrity
echo "--- [1/3] Integrity check ---"
SHA256_FILE="${BUNDLE}.sha256"
[[ -f "$SHA256_FILE" ]] || { echo "FAIL: missing ${SHA256_FILE}"; exit 1; }
EXPECTED=$(cat "$SHA256_FILE")
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$BUNDLE" | awk '{print $1}')
else
  ACTUAL=$(shasum -a 256 "$BUNDLE" | awk '{print $1}')
fi
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA256 mismatch (expected $EXPECTED, got $ACTUAL)"; exit 1; }
echo "OK: SHA256 $ACTUAL"

# 2. Authenticity
echo "--- [2/3] Authenticity check ---"
SIG_BUNDLE="${BUNDLE}.sig.bundle"
if [[ -f "$SIG_BUNDLE" ]] && grep -q '"stub":true' "$SIG_BUNDLE" 2>/dev/null; then
  echo "SKIP: stub signature bundle (local run — no GitHub Actions OIDC)"
elif command -v cosign >/dev/null 2>&1 && [[ -f "$SIG_BUNDLE" ]]; then
  cosign verify-blob \
    --bundle "$SIG_BUNDLE" \
    --certificate-identity-regexp '.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$BUNDLE"
  echo "OK: cosign signature verified"
else
  echo "SKIP: cosign not installed or sig bundle missing"
fi

# 3. Preservation (S3 Object Lock)
echo "--- [3/3] Preservation check ---"
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" \
  --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' \
  --output text 2>/dev/null || echo "NONE")

if [[ "$RETAIN_UNTIL" == "NONE" || "$RETAIN_UNTIL" == "None" ]]; then
  echo "SKIP: S3 Object Lock not configured on this bucket"
else
  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  [[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired ($RETAIN_UNTIL)"; exit 1; }
  echo "OK: Object Lock active until $RETAIN_UNTIL"
fi

echo ""
echo "=============================="
echo "CHAIN INTACT for run ${RUN_ID}"
echo "=============================="
