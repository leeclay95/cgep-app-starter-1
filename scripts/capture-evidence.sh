#!/usr/bin/env bash
# scripts/capture-evidence.sh
# Usage:
#   capture-evidence.sh --workspace <path> --run-id <id> --vault <bucket> [--profile <p>]

set -euo pipefail

PROFILE_ARG=""
WORKSPACE=""
RUN_ID=""
VAULT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --run-id)    RUN_ID="$2";    shift 2 ;;
    --vault)     VAULT="$2";     shift 2 ;;
    --profile)   PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" || -z "$RUN_ID" || -z "$VAULT" ]] && {
  echo "Usage: $0 --workspace <path> --run-id <id> --vault <bucket> [--profile <p>]" >&2
  exit 2
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum    >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BUNDLE_DIR="$WORK/bundle-$RUN_ID"
mkdir -p "$BUNDLE_DIR"

( cd "$WORKSPACE" && [[ -f tfplan ]] && \
    terraform show -json tfplan > "$BUNDLE_DIR/plan.json" 2>/dev/null || true )
( cd "$WORKSPACE" && terraform state pull > "$BUNDLE_DIR/state.json" 2>/dev/null || true )
( cd "$WORKSPACE" && git log -1 --pretty=full > "$BUNDLE_DIR/commit.txt" 2>/dev/null \
    || echo "no git commit available" > "$BUNDLE_DIR/commit.txt" )
terraform version > "$BUNDLE_DIR/version.txt"

# manifest.json
{
  echo "["
  FIRST=1
  for f in "$BUNDLE_DIR"/*; do
    base=$(basename "$f")
    [[ "$base" == "manifest.json" ]] && continue
    HASH=$($SHASUM "$f" | awk '{print $1}')
    SIZE=$(wc -c < "$f" | tr -d ' ')
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    printf '\n  {"filename":"%s","sha256":"%s","size":%s,"captured_at_utc":"%s"}' \
      "$base" "$HASH" "$SIZE" "$CAPTURED_AT"
  done
  echo
  echo "]"
} > "$BUNDLE_DIR/manifest.json"

BUNDLE_TGZ="/tmp/evidence-$RUN_ID.tar.gz"
( cd "$WORK" && tar czf "$BUNDLE_TGZ" "bundle-$RUN_ID" )

# --- SHA256 sidecar ---
SHA256=$($SHASUM "$BUNDLE_TGZ" | awk '{print $1}')
SHA256_FILE="/tmp/evidence-$RUN_ID.tar.gz.sha256"
echo "$SHA256" > "$SHA256_FILE"

# --- cosign signing (GitHub Actions OIDC) or local stub ---
SIG_BUNDLE_FILE="/tmp/evidence-$RUN_ID.tar.gz.sig.bundle"
if command -v cosign >/dev/null 2>&1 && [[ -n "${COSIGN_EXPERIMENTAL:-}" ]]; then
  cosign sign-blob \
    --bundle "$SIG_BUNDLE_FILE" \
    "$BUNDLE_TGZ"
else
  echo '{"stub":true,"reason":"local-run-no-oidc"}' > "$SIG_BUNDLE_FILE"
fi

KEY="runs/$RUN_ID/evidence-$RUN_ID.tar.gz"

# Upload bundle
UPLOAD_OUT=$(aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" --key "$KEY" --body "$BUNDLE_TGZ" --output json)
VERSION_ID=$(echo "$UPLOAD_OUT" | awk -F'"' '/"VersionId"/{print $4}')

# Upload sidecar files
aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" --key "${KEY}.sha256" \
  --body "$SHA256_FILE" --output json > /dev/null

aws $PROFILE_ARG s3api put-object \
  --bucket "$VAULT" --key "${KEY}.sig.bundle" \
  --body "$SIG_BUNDLE_FILE" --output json > /dev/null

RECEIPT=$(printf '{"run_id":"%s","vault":"%s","key":"%s","version_id":"%s","sha256":"%s","captured_at_utc":"%s"}\n' \
  "$RUN_ID" "$VAULT" "$KEY" "$VERSION_ID" "$SHA256" "$CAPTURED_AT")

echo "$RECEIPT"

# --- Save local evidence artifact ---
CURRENT_DATE=$(date +%Y-%m-%d)
EVIDENCE_DIR="evidence/$CURRENT_DATE"
mkdir -p "$EVIDENCE_DIR"

echo "$RECEIPT" > "$EVIDENCE_DIR/receipt-$RUN_ID.json"
cp "$SHA256_FILE" "$EVIDENCE_DIR/evidence-$RUN_ID.tar.gz.sha256"
echo "Local evidence written to $EVIDENCE_DIR/"
