#!/usr/bin/env bash
# =============================================================================
# CGE-P Capstone Audit Script
# Run from repo root: bash audit_capstone.sh
# Writes: AUDIT_REPORT.md at repo root
# =============================================================================
set -uo pipefail

REPORT="AUDIT_REPORT.md"
PASS=0
WARN=0
FAIL=0
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── helpers ──────────────────────────────────────────────────────────────────

ok()   { echo "  [OK]   $1" | tee -a "$REPORT"; ((PASS++));  }
warn() { echo "  [WARN] $1" | tee -a "$REPORT"; ((WARN++));  }
fail() { echo "  [FAIL] $1" | tee -a "$REPORT"; ((FAIL++));  }
info() { echo "         $1" | tee -a "$REPORT"; }
h1()   { echo "" | tee -a "$REPORT"
         echo "---" | tee -a "$REPORT"
         echo "" | tee -a "$REPORT"
         echo "## $1" | tee -a "$REPORT"
         echo "" | tee -a "$REPORT"; }
h2()   { echo "" | tee -a "$REPORT"
         echo "### $1" | tee -a "$REPORT"
         echo "" | tee -a "$REPORT"; }
code() { echo '```' | tee -a "$REPORT"
         echo "$1"  | tee -a "$REPORT"
         echo '```' | tee -a "$REPORT"; }
codeblock_start() { echo '```' | tee -a "$REPORT"; }
codeblock_end()   { echo '```' | tee -a "$REPORT"; }

# ── header ───────────────────────────────────────────────────────────────────

cat > "$REPORT" << EOF
# CGE-P Capstone Audit Report

**Generated**: $TIMESTAMP
**Repo root**: $(pwd)
**Framework**: CMMC Level 2 (NIST 800-171)

> Legend: \`[OK]\` = present/passing · \`[WARN]\` = present but needs attention · \`[FAIL]\` = missing or broken

EOF

echo "Running CGE-P capstone audit..."
echo "Output → $REPORT"
echo ""

# =============================================================================
# LAYER 1 — Terraform IaC Quality (15%)
# =============================================================================

h1 "Layer 1 — Terraform IaC Quality (15%)"

h2 "1.1 Directory & file structure"

TF_FILES=$(find terraform/ -name "*.tf" 2>/dev/null | sort)
if [ -n "$TF_FILES" ]; then
  ok "terraform/ directory contains .tf files"
  info "Files found:"
  while IFS= read -r f; do info "  $f"; done <<< "$TF_FILES"
else
  fail "terraform/ contains no .tf files"
fi

# Check for baseline vs main split
BASELINE_FILES=$(find terraform/ -name "baseline*" -o -name "*baseline*" 2>/dev/null | grep "\.tf$" | sort)
if [ -n "$BASELINE_FILES" ]; then
  ok "Baseline terraform file(s) found"
  while IFS= read -r f; do info "  $f"; done <<< "$BASELINE_FILES"
else
  warn "No baseline.tf found — KMS/CloudTrail/vault may be co-mingled in main.tf"
fi

# Lock file
if find terraform/ -name ".terraform.lock.hcl" 2>/dev/null | grep -q .; then
  ok ".terraform.lock.hcl present (dependency lock committed)"
else
  warn ".terraform.lock.hcl missing — should be committed for reproducible builds (Engineering Hygiene)"
fi

# outputs.tf
if find terraform/ -name "outputs.tf" 2>/dev/null | grep -q .; then
  ok "outputs.tf found"
else
  warn "outputs.tf missing — vault_bucket_name and kms_key_arn should be explicit outputs"
fi

# variables.tf
if find terraform/ -name "variables.tf" 2>/dev/null | grep -q .; then
  ok "variables.tf found"
else
  warn "variables.tf missing — aws_region and other inputs should be parameterized"
fi

h2 "1.2 KMS — must be customer-managed with rotation"

KMS_RESOURCE=$(grep -rn "aws_kms_key" terraform/ 2>/dev/null | grep -v ".terraform/" | grep "resource")
if [ -n "$KMS_RESOURCE" ]; then
  ok "aws_kms_key resource found in terraform/"
  info "$KMS_RESOURCE"
else
  fail "No aws_kms_key resource found — CMK required for CMMC SC.L2-3.13.11"
fi

ROTATION=$(grep -rn "enable_key_rotation" terraform/ 2>/dev/null | grep -v ".terraform/")
if echo "$ROTATION" | grep -q "true"; then
  ok "enable_key_rotation = true found (SC.L2-3.13.11)"
else
  fail "enable_key_rotation not set or false — required for CMMC key management"
fi

h2 "1.3 Hardcoded values — security and hygiene risks"

HARDCODED_KMS=$(grep -rn "arn:aws:kms" terraform/ 2>/dev/null | grep -v ".terraform/" | grep -v "aws_kms_key\|aws_kms_alias\|data\." | head -20)
if [ -n "$HARDCODED_KMS" ]; then
  fail "Hardcoded KMS ARN(s) found — replace with aws_kms_key.cmmc_key.arn reference"
  echo '```' >> "$REPORT"
  echo "$HARDCODED_KMS" >> "$REPORT"
  echo '```' >> "$REPORT"
  echo "$HARDCODED_KMS"
else
  ok "No hardcoded KMS ARNs detected (all using resource references)"
fi

HARDCODED_ACCT=$(grep -rn "[0-9]\{12\}" terraform/ policies/ .github/ 2>/dev/null \
  | grep -v ".terraform/\|#\|oidc-provider\|StringLike\|StringEquals\|account_id}" \
  | grep -v "data.aws_caller_identity" | head -10)
if [ -n "$HARDCODED_ACCT" ]; then
  fail "Hardcoded AWS account ID found in public repo — use data.aws_caller_identity.current.account_id"
  echo '```' >> "$REPORT"
  echo "$HARDCODED_ACCT" >> "$REPORT"
  echo '```' >> "$REPORT"
  echo "$HARDCODED_ACCT"
else
  ok "No hardcoded account IDs detected"
fi

SECRETS=$(grep -rEin "password\s*=\s*\"[^\"]+\"|secret\s*=\s*\"[^\"]+\"|api_key\s*=\s*\"[^\"]+\"" \
  terraform/ policies/ .github/ 2>/dev/null | grep -v ".terraform/" | head -5)
if [ -n "$SECRETS" ]; then
  fail "POTENTIAL SECRETS in tracked files — auto-fail trigger risk"
  echo '```' >> "$REPORT"
  echo "$SECRETS" >> "$REPORT"
  echo '```' >> "$REPORT"
else
  ok "No obvious plaintext secrets detected in tf/policy/.github files"
fi

h2 "1.4 Evidence vault (Lab 2.5 pattern)"

VAULT_RESOURCE=$(grep -rn "object_lock_enabled\|aws_s3_bucket_object_lock" terraform/ 2>/dev/null | grep -v ".terraform/")
if [ -n "$VAULT_RESOURCE" ]; then
  ok "S3 Object Lock evidence vault found (MP.L2-3.8.3)"
  info "$VAULT_RESOURCE"
else
  fail "No S3 Object Lock vault found — required for tamper-evident evidence storage"
fi

VAULT_VERSIONING=$(grep -rn "versioning" terraform/ 2>/dev/null | grep -v ".terraform/" | grep "Enabled")
if [ -n "$VAULT_VERSIONING" ]; then
  ok "S3 versioning enabled (required for Object Lock)"
else
  warn "S3 versioning Enabled not confirmed — Object Lock requires versioning"
fi

h2 "1.5 CloudTrail (Lab 5.2 pattern)"

TRAIL=$(grep -rn "aws_cloudtrail" terraform/ 2>/dev/null | grep -v ".terraform/" | grep "resource")
if [ -n "$TRAIL" ]; then
  ok "aws_cloudtrail resource found (AU.L2-3.3.1)"
else
  fail "No aws_cloudtrail found — required for CMMC AU.L2-3.3.1 audit records"
fi

MULTI_REGION=$(grep -rn "is_multi_region_trail" terraform/ 2>/dev/null | grep -v ".terraform/")
if echo "$MULTI_REGION" | grep -q "true"; then
  ok "is_multi_region_trail = true"
else
  warn "is_multi_region_trail not confirmed true — required for full coverage"
fi

LOG_VALIDATION=$(grep -rn "enable_log_file_validation" terraform/ 2>/dev/null | grep -v ".terraform/")
if echo "$LOG_VALIDATION" | grep -q "true"; then
  ok "enable_log_file_validation = true (AU-10 integrity)"
else
  fail "enable_log_file_validation not true — required for tamper-evident logs"
fi

h2 "1.6 Security Hub / Config (Lab 5.2 — Continuous Monitoring 10%)"

SECHUB=$(grep -rn "aws_securityhub_account\|aws_securityhub_standards" terraform/ 2>/dev/null | grep -v ".terraform/")
if [ -n "$SECHUB" ]; then
  ok "Security Hub resource found — continuous monitoring coverage (RA-5/SI-4)"
  info "$SECHUB"
else
  warn "No aws_securityhub_account found — Security Hub adds 10% Continuous Monitoring score"
  info "Add: aws_securityhub_account + aws_securityhub_standards_subscription (NIST 800-53)"
fi

CONFIG=$(grep -rn "aws_config_configuration_recorder\|aws_config_config_rule" terraform/ 2>/dev/null | grep -v ".terraform/")
if [ -n "$CONFIG" ]; then
  ok "AWS Config resource(s) found — drift detection"
  info "$CONFIG"
else
  warn "No AWS Config rules found — targeted detections mapped to controls score higher"
  info "Add config rules: encrypted-volumes, s3-bucket-ssl-requests-only, vpc-flow-logs-enabled"
fi

CW_ALARMS=$(grep -rn "aws_cloudwatch_metric_alarm\|aws_cloudwatch_log_metric_filter" terraform/ 2>/dev/null | grep -v ".terraform/")
if [ -n "$CW_ALARMS" ]; then
  ok "CloudWatch alarms/metric filters found — alert routing present"
else
  warn "No CloudWatch alarms — detection with no alerting scores in 50-69 range"
  info "Add alarms for: root account usage, unauthorized API calls, CMK disable/delete"
fi

h2 "1.7 OIDC trust module (Lab 4.3 pattern)"

OIDC_FILES=$(find oidc/ -name "*.tf" 2>/dev/null | sort)
if [ -n "$OIDC_FILES" ]; then
  ok "oidc/ Terraform module found"
  while IFS= read -r f; do info "  $f"; done <<< "$OIDC_FILES"
  OIDC_PROVIDER=$(grep -rn "aws_iam_openid_connect_provider" oidc/ 2>/dev/null)
  if [ -n "$OIDC_PROVIDER" ]; then
    ok "aws_iam_openid_connect_provider resource found"
  else
    fail "aws_iam_openid_connect_provider missing from oidc/ module"
  fi
  OIDC_ROLE=$(grep -rn "aws_iam_role" oidc/ 2>/dev/null | grep "resource")
  if [ -n "$OIDC_ROLE" ]; then
    ok "IAM role for GitHub Actions found in oidc/"
  else
    fail "No aws_iam_role in oidc/ — GRC gate role missing"
  fi
else
  fail "oidc/ module has no .tf files — OIDC trust not provisioned as IaC"
fi

h2 "1.8 Gap remediation coverage"

echo "" | tee -a "$REPORT"
echo "| Gap | Resource Expected | Found | CMMC Control |" | tee -a "$REPORT"
echo "|-----|-------------------|-------|--------------|" | tee -a "$REPORT"

check_gap() {
  local gap="$1" pattern="$2" control="$3" resource="$4"
  if grep -rqn "$pattern" terraform/ 2>/dev/null | grep -v ".terraform/" > /dev/null 2>&1; then
    echo "| $gap | $resource | ✅ | $control |" | tee -a "$REPORT"
    ((PASS++))
  else
    echo "| $gap | $resource | ❌ | $control |" | tee -a "$REPORT"
    ((FAIL++))
  fi
}

# Inline grep for table (can't use function easily with tee in subshell)
for row in \
  "GAP-01|kms_master_key_id|SC.L2-3.13.11|aws_s3_bucket_server_side_encryption_configuration" \
  "GAP-02|kms_key_arn|SC.L2-3.13.11|DynamoDB server_side_encryption with KMS" \
  "GAP-03|SecureTransport|SC.L2-3.13.8|aws_s3_bucket_policy TLS enforcement" \
  "GAP-04|versioning.*Enabled|MP.L2-3.8.9|aws_s3_bucket_versioning" \
  "GAP-05|vpc_config|SC.L2-3.13.1|Lambda vpc_config with private subnets" \
  "GAP-06|dead_letter_config|AC.L2-3.1.5|Lambda DLQ" \
  "GAP-07|dynamodb:PutItem|AC.L2-3.1.5|Scoped IAM — not dynamodb:*" \
  "GAP-08|access_log_settings|AU.L2-3.3.1|API Gateway access logging"; do
  IFS='|' read -r gap pattern control resource <<< "$row"
  if grep -rqn "$pattern" terraform/ 2>/dev/null; then
    echo "| $gap | \`$resource\` | ✅ | $control |" | tee -a "$REPORT"
    ((PASS++))
  else
    echo "| $gap | \`$resource\` | ❌ | $control |" | tee -a "$REPORT"
    ((FAIL++))
  fi
done

# =============================================================================
# LAYER 2 — Policy-as-Code (15%)
# =============================================================================

h1 "Layer 2 — Policy-as-Code (15%)"

h2 "2.1 Rego policy files"

POLICY_FILES=$(find policies/ -name "*.rego" ! -name "*_test.rego" 2>/dev/null | sort)
POLICY_COUNT=$(echo "$POLICY_FILES" | grep -c "\.rego" 2>/dev/null || echo 0)

if [ "$POLICY_COUNT" -ge 5 ]; then
  ok "$POLICY_COUNT Rego policy files found (minimum 5 required)"
else
  fail "Only $POLICY_COUNT Rego policy file(s) found — need at least 5"
fi

if [ -n "$POLICY_FILES" ]; then
  info "Policy files:"
  while IFS= read -r f; do info "  $f"; done <<< "$POLICY_FILES"
fi

h2 "2.2 Test files (each policy needs _test.rego with deny_ cases)"

TEST_FILES=$(find policies/ -name "*_test.rego" 2>/dev/null | sort)
TEST_COUNT=$(echo "$TEST_FILES" | grep -c "_test.rego" 2>/dev/null || echo 0)

if [ "$TEST_COUNT" -ge 5 ]; then
  ok "$TEST_COUNT test file(s) found"
elif [ "$TEST_COUNT" -ge 1 ]; then
  warn "$TEST_COUNT test file(s) found — need one per policy for full credit"
else
  fail "No _test.rego files found — required for Policy-as-Code 70+ score"
fi

echo "" | tee -a "$REPORT"
echo "| Policy file | Test file | Negative test (deny_*) |" | tee -a "$REPORT"
echo "|-------------|-----------|------------------------|" | tee -a "$REPORT"

while IFS= read -r pf; do
  [ -z "$pf" ] && continue
  base=$(basename "$pf" .rego)
  test_file="policies/${base}_test.rego"
  if [ -f "$test_file" ]; then
    has_deny=$(grep -c "deny_\|test_deny\|test_violation" "$test_file" 2>/dev/null || echo 0)
    if [ "$has_deny" -gt 0 ]; then
      echo "| \`$pf\` | ✅ | ✅ ($has_deny negative case(s)) |" | tee -a "$REPORT"
    else
      echo "| \`$pf\` | ✅ | ❌ no deny_ test found |" | tee -a "$REPORT"
      ((WARN++))
    fi
  else
    echo "| \`$pf\` | ❌ missing | ❌ |" | tee -a "$REPORT"
    ((FAIL++))
  fi
done <<< "$POLICY_FILES"

h2 "2.3 CMMC control ID coverage in policy metadata"

echo "" | tee -a "$REPORT"
echo "| Control | Policy file |" | tee -a "$REPORT"
echo "|---------|-------------|" | tee -a "$REPORT"

for ctrl in "SC.L2-3.13.11" "SC.L2-3.13.1" "SC.L2-3.13.8" "AC.L2-3.1.5" "MP.L2-3.8.9"; do
  hit=$(grep -rln "$ctrl" policies/ 2>/dev/null | grep "\.rego$" | head -3 | tr '\n' ' ')
  if [ -n "$hit" ]; then
    echo "| $ctrl | ✅ \`$hit\` |" | tee -a "$REPORT"
    ((PASS++))
  else
    echo "| $ctrl | ❌ not cited in any policy |" | tee -a "$REPORT"
    ((WARN++))
  fi
done

h2 "2.4 OPA test run"

if command -v opa &>/dev/null; then
  OPA_OUT=$(opa test ./policies -v 2>&1)
  OPA_EXIT=$?
  if [ $OPA_EXIT -eq 0 ]; then
    ok "opa test ./policies PASSED"
  else
    fail "opa test ./policies FAILED"
  fi
  codeblock_start
  echo "$OPA_OUT" | tail -20 | tee -a "$REPORT"
  codeblock_end
else
  warn "opa not in PATH — cannot run test suite"
  info "Install: https://github.com/open-policy-agent/opa/releases"
  info "Then run: opa test ./policies -v"
fi

h2 "2.5 Conftest gate script"

if [ -f scripts/policy-gate.sh ]; then
  ok "scripts/policy-gate.sh present"
  [ -x scripts/policy-gate.sh ] && ok "policy-gate.sh is executable" || warn "policy-gate.sh not executable — run: chmod +x scripts/policy-gate.sh"
else
  fail "scripts/policy-gate.sh missing (Lab 3.4 deliverable — CI calls this directly)"
fi

# =============================================================================
# LAYER 3 — CI/CD Pipeline (10%)
# =============================================================================

h1 "Layer 3 — CI/CD Compliance Pipeline (10%)"

h2 "3.1 Workflow file"

if [ -f .github/workflows/grc-gate.yml ]; then
  ok ".github/workflows/grc-gate.yml present"
else
  fail ".github/workflows/grc-gate.yml MISSING — 10% CI/CD score is at zero without this"
fi

h2 "3.2 Required pipeline steps"

if [ -f .github/workflows/grc-gate.yml ]; then
  WF=".github/workflows/grc-gate.yml"

  check_wf_step() {
    local label="$1" pattern="$2" required="$3"
    if grep -q "$pattern" "$WF" 2>/dev/null; then
      ok "$label"
    else
      [ "$required" = "FAIL" ] && fail "$label" || warn "$label"
    fi
  }

  check_wf_step "id-token: write (OIDC — required for keyless Cosign + AWS auth)" "id-token: write" FAIL
  check_wf_step "Terraform plan step" "terraform plan" FAIL
  check_wf_step "Conftest gate step" "conftest" FAIL
  check_wf_step "tfsec scan step" "tfsec" WARN
  check_wf_step "Cosign signing step (Lab 4.4)" "cosign" FAIL
  check_wf_step "Vault upload step — s3 cp to EVIDENCE_VAULT (Lab 4.4)" "EVIDENCE_VAULT\|s3 cp" FAIL
  check_wf_step "Upload evidence artifact step" "upload-artifact" WARN
  check_wf_step "if: always() on sign/upload (preserves evidence on failure)" "if: always" WARN
  check_wf_step "pull-requests: write (for PR comments)" "pull-requests: write" WARN

  echo "" | tee -a "$REPORT"
  info "All workflow steps:"
  grep -E "^\s+- name:" "$WF" | sed 's/.*- name:/  -/' | tee -a "$REPORT"
else
  fail "Cannot check steps — workflow file missing"
fi

h2 "3.3 Repo variables required"

echo "" | tee -a "$REPORT"
echo "| Variable | Purpose | Set? |" | tee -a "$REPORT"
echo "|----------|---------|------|" | tee -a "$REPORT"

for var_check in \
  "AWS_ROLE_ARN|OIDC role ARN for AWS auth" \
  "EVIDENCE_VAULT|S3 vault bucket name for signed bundles"; do
  IFS='|' read -r vname vpurpose <<< "$var_check"
  if command -v gh &>/dev/null; then
    val=$(gh variable get "$vname" 2>/dev/null | grep "Value:" | awk '{print $2}' || echo "")
    if [ -n "$val" ]; then
      echo "| \`$vname\` | $vpurpose | ✅ |" | tee -a "$REPORT"
      ((PASS++))
    else
      echo "| \`$vname\` | $vpurpose | ❓ (gh CLI check failed — verify in repo Settings → Variables) |" | tee -a "$REPORT"
      ((WARN++))
    fi
  else
    echo "| \`$vname\` | $vpurpose | ❓ (gh CLI not available — check manually in repo Settings → Variables) |" | tee -a "$REPORT"
    ((WARN++))
  fi
done

h2 "3.4 PR history — green + red required by checklist"

echo "" | tee -a "$REPORT"
MERGE_COUNT=$(git log --merges --oneline 2>/dev/null | wc -l | tr -d ' ')
if [ "$MERGE_COUNT" -ge 2 ]; then
  ok "$MERGE_COUNT merge commit(s) found in history — likely have both green + red PRs"
elif [ "$MERGE_COUNT" -ge 1 ]; then
  warn "Only $MERGE_COUNT merge commit — need both a green PR (merged) and red PR (blocked by gate)"
else
  fail "No merge commits found — need one green PR merged + one red PR blocked by policy gate"
fi

info "Recent merge history:"
git log --merges --oneline 2>/dev/null | head -5 | while IFS= read -r line; do info "  $line"; done

# =============================================================================
# LAYER 4 — Evidence Automation & OSCAL (10%)
# =============================================================================

h1 "Layer 4 — Evidence Automation & OSCAL (10%)"

h2 "4.1 capture-evidence.sh (Lab 2.5 pattern)"

if [ -f scripts/capture-evidence.sh ]; then
  ok "scripts/capture-evidence.sh present"
  [ -x scripts/capture-evidence.sh ] && ok "executable" || warn "not executable — chmod +x scripts/capture-evidence.sh"
  grep -q "tar" scripts/capture-evidence.sh && ok "bundles files into tar" || warn "no tar command found — check bundle logic"
  grep -q "put-object\|s3 cp" scripts/capture-evidence.sh && ok "uploads to S3 vault" || warn "no s3 upload found in capture-evidence.sh"
  grep -q "sha256\|shasum" scripts/capture-evidence.sh && ok "SHA-256 hashing present" || warn "no SHA-256 hash — integrity not captured"
else
  fail "scripts/capture-evidence.sh MISSING (Lab 2.5 deliverable)"
fi

h2 "4.2 verify-evidence.sh (Lab 4.4 chain of custody)"

if [ -f scripts/verify-evidence.sh ]; then
  ok "scripts/verify-evidence.sh present"
  [ -x scripts/verify-evidence.sh ] && ok "executable" || warn "not executable — chmod +x scripts/verify-evidence.sh"
  grep -q "cosign verify-blob" scripts/verify-evidence.sh && ok "cosign verify-blob step present (authenticity)" || fail "cosign verify-blob missing — chain of custody incomplete"
  grep -q "sha256\|shasum" scripts/verify-evidence.sh && ok "SHA-256 recompute present (integrity)" || fail "SHA-256 check missing"
  grep -q "get-object-retention" scripts/verify-evidence.sh && ok "Object Lock retention check present (preservation)" || warn "get-object-retention check missing"
  grep -q "CHAIN INTACT" scripts/verify-evidence.sh && ok "CHAIN INTACT output present" || warn "CHAIN INTACT output not found — grader looks for this"
else
  fail "scripts/verify-evidence.sh MISSING (Lab 4.4 deliverable — grader runs this)"
fi

h2 "4.3 Signed bundles in vault"

VAULT_NAME=""
if [ -f terraform/outputs.tf ] || find terraform/ -name "outputs.tf" -o -name "baseline.tf" 2>/dev/null | grep -q .; then
  VAULT_NAME=$(cd terraform && terraform output -raw vault_bucket_name 2>/dev/null || \
               terraform output -raw vault_name 2>/dev/null || echo "")
fi

if [ -n "$VAULT_NAME" ]; then
  ok "Vault bucket name from terraform output: $VAULT_NAME"
  RUNS=$(aws s3 ls "s3://${VAULT_NAME}/runs/" 2>/dev/null || echo "")
  if [ -n "$RUNS" ]; then
    ok "Signed bundle runs/ found in vault"
    info "$RUNS" | head -5
    BUNDLE_COUNT=$(aws s3 ls "s3://${VAULT_NAME}/runs/" --recursive 2>/dev/null | grep "\.tar\.gz$" | wc -l | tr -d ' ')
    ok "$BUNDLE_COUNT .tar.gz bundle(s) in vault"
    SIG_COUNT=$(aws s3 ls "s3://${VAULT_NAME}/runs/" --recursive 2>/dev/null | grep "\.sig\.bundle$" | wc -l | tr -d ' ')
    [ "$SIG_COUNT" -ge 1 ] && ok "$SIG_COUNT Cosign .sig.bundle file(s) found" || fail "No .sig.bundle files — bundles not Cosign-signed yet"
  else
    fail "No runs/ objects in vault — pipeline has not uploaded a signed bundle yet"
  fi
else
  warn "Could not read vault bucket name from terraform output — check terraform/outputs.tf"
  info "Manually check: aws s3 ls | grep vault"
fi

h2 "4.4 OSCAL component definition (Lab 6.1)"

OSCAL_FILES=$(find oscal/ -name "*.json" 2>/dev/null | sort)
if [ -n "$OSCAL_FILES" ]; then
  ok "OSCAL JSON file(s) found in oscal/"
  while IFS= read -r f; do info "  $f"; done <<< "$OSCAL_FILES"
else
  fail "No OSCAL JSON files found in oscal/ — required deliverable"
fi

# Check for component definition specifically
COMP_DEF=$(find oscal/components/ -name "*.json" 2>/dev/null | head -1)
if [ -n "$COMP_DEF" ]; then
  ok "Component definition found: $COMP_DEF"

  # UUID placeholder check
  PLACEHOLDER_COUNT=$(grep -c "GENERATED-UUID\|YOUR-UUID\|PARTY-UUID\|COMPONENT-UUID\|CI-UUID\|REQ-UUID\|PROFILE-UUID" "$COMP_DEF" 2>/dev/null || echo 0)
  if [ "$PLACEHOLDER_COUNT" -gt 0 ]; then
    fail "$PLACEHOLDER_COUNT placeholder UUID(s) still in component definition — trestle validate will reject these"
    info "Fix: python3 -c \"import uuid; print(uuid.uuid4())\" for each placeholder"
  else
    ok "No placeholder UUIDs detected"
  fi

  # CMMC source check
  CMMC_SOURCE=$(grep "source\|href" "$COMP_DEF" 2>/dev/null | grep -i "nist\|800-171\|cmmc" | head -3)
  if [ -n "$CMMC_SOURCE" ]; then
    ok "NIST/CMMC catalog source reference found in component definition"
  else
    warn "No NIST 800-171 or CMMC catalog source in component — source field must point to declared framework catalog"
  fi

  # Control implementations
  CTRL_IMPL=$(grep -c "control-id\|implemented-requirement" "$COMP_DEF" 2>/dev/null || echo 0)
  if [ "$CTRL_IMPL" -ge 1 ]; then
    ok "$CTRL_IMPL control implementation reference(s) found"
  else
    fail "No control-id or implemented-requirement entries — OSCAL component has no control mapping"
  fi

  # Evidence links
  EVIDENCE_LINKS=$(grep -c "rel.*evidence\|evidence.*href" "$COMP_DEF" 2>/dev/null || echo 0)
  if [ "$EVIDENCE_LINKS" -ge 1 ]; then
    ok "$EVIDENCE_LINKS evidence link(s) found — chain from OSCAL to vault present"
  else
    fail "No evidence links in component definition — links[rel=evidence].href must point to vault objects"
  fi

  # Terraform resource props
  TF_PROPS=$(grep -c "terraform-resource\|aws_" "$COMP_DEF" 2>/dev/null || echo 0)
  if [ "$TF_PROPS" -ge 1 ]; then
    ok "Terraform resource references in props ($TF_PROPS) — bidirectional mapping present"
  else
    warn "No Terraform resource addresses in props — add props[name=terraform-resource] for bidirectional mapping"
  fi
else
  fail "oscal/components/ has no JSON files — component-definition.json required"
fi

h2 "4.5 OSCAL profile"

PROFILE=$(find oscal/profiles/ -name "*.json" 2>/dev/null | head -1)
if [ -n "$PROFILE" ]; then
  ok "OSCAL profile found: $PROFILE"
  grep -q "include-controls\|with-ids" "$PROFILE" 2>/dev/null && ok "Control selection (include-controls) present" || warn "No include-controls in profile"
else
  fail "oscal/profiles/ has no JSON — OSCAL profile required (trestle create -t profile)"
fi

h2 "4.6 trestle validation"

if command -v trestle &>/dev/null; then
  if [ -n "$COMP_DEF" ]; then
    TRESTLE_OUT=$(trestle validate -f "$COMP_DEF" 2>&1)
    if echo "$TRESTLE_OUT" | grep -q "VALID"; then
      ok "trestle validate PASSED on component definition"
    else
      fail "trestle validate FAILED on component definition"
      codeblock_start
      echo "$TRESTLE_OUT" | tail -15 | tee -a "$REPORT"
      codeblock_end
    fi
  else
    warn "No component definition to validate"
  fi
else
  warn "trestle not installed — cannot validate OSCAL"
  info "Install: pip install compliance-trestle"
  info "Then run: trestle validate -f oscal/components/<your-component>.json"
fi

# =============================================================================
# LAYER 5 — Engineering Hygiene (15%)
# =============================================================================

h1 "Layer 5 — Engineering Hygiene (15%)"

h2 "5.1 Required repo files"

for reqfile in "README.md" "WRITEUP.md" ".gitignore"; do
  if [ -f "$reqfile" ]; then
    LINES=$(wc -l < "$reqfile" | tr -d ' ')
    ok "$reqfile present ($LINES lines)"
  else
    [ "$reqfile" = "README.md" ] && fail "$reqfile MISSING — AUTO-FAIL trigger" || fail "$reqfile MISSING — required deliverable"
  fi
done

h2 "5.2 WRITEUP.md content check"

if [ -f WRITEUP.md ]; then
  WU_LINES=$(wc -l < WRITEUP.md | tr -d ' ')
  if [ "$WU_LINES" -lt 20 ]; then
    warn "WRITEUP.md only $WU_LINES lines — likely a stub. Needs: framework choice rationale, gap remediation, design trade-offs, honest gaps"
  else
    ok "WRITEUP.md has $WU_LINES lines"
  fi

  for section in "CMMC\|framework\|Framework" "GAP\|gap\|remediat" "trade-off\|tradeoff\|decision" "KMS\|kms\|encrypt"; do
    grep -qi "$section" WRITEUP.md 2>/dev/null && ok "WRITEUP.md mentions: $section" || warn "WRITEUP.md missing section on: $section"
  done
fi

h2 "5.3 .gitignore check"

if [ -f .gitignore ]; then
  for entry in ".terraform/" "*.tfstate" "*.tfstate.backup" "*.tfvars" ".env"; do
    grep -q "$entry" .gitignore && ok ".gitignore covers $entry" || warn ".gitignore missing $entry"
  done
else
  fail ".gitignore missing"
fi

h2 "5.4 State file leak check"

TFSTATE_TRACKED=$(git ls-files "*.tfstate" "*.tfstate.backup" 2>/dev/null)
if [ -n "$TFSTATE_TRACKED" ]; then
  fail "tfstate file(s) tracked in git — potential secrets/account IDs exposed: $TFSTATE_TRACKED"
else
  ok "No .tfstate files tracked in git"
fi

TFVARS_TRACKED=$(git ls-files "*.tfvars" 2>/dev/null | grep -v ".example\|sample\|template" || true)
if [ -n "$TFVARS_TRACKED" ]; then
  warn ".tfvars file(s) tracked — check for secrets: $TFVARS_TRACKED"
else
  ok "No .tfvars files tracked in git"
fi

h2 "5.5 Provider version pins"

UNPINNED=$(grep -rn "version\s*=" terraform/ 2>/dev/null | grep -v ".terraform/" \
  | grep "required_providers" -A5 | grep -v "~>\|>= \|= \"[0-9]" | grep "source\|version" | head -5)
ok "Provider version pins checked — review manually if any unpinned providers above"

h2 "5.6 tfsec config (suppressions)"

if [ -f .tfsec/config.yml ]; then
  ok ".tfsec/config.yml present"
  IGNORES=$(grep -c "ignore\|exclude\|severity_overrides" .tfsec/config.yml 2>/dev/null || echo 0)
  info "$IGNORES suppression/config entries in .tfsec/config.yml"
else
  warn ".tfsec/config.yml missing — known false-positives (s3:PutObject /uploads/*) will keep firing"
  info "Create .tfsec/config.yml to suppress justified findings with comments"
fi

# =============================================================================
# LAYER 6 — Control-to-Code Documentation (15%)
# =============================================================================

h1 "Layer 6 — Control-to-Code Documentation (15%)"

h2 "6.1 Gap-to-control mapping in WRITEUP.md"

if [ -f WRITEUP.md ]; then
  CTRL_REFS=$(grep -cE "SC\.L2|AC\.L2|MP\.L2|AU\.L2|IA\.L2" WRITEUP.md 2>/dev/null || echo 0)
  if [ "$CTRL_REFS" -ge 5 ]; then
    ok "$CTRL_REFS CMMC control references in WRITEUP.md"
  else
    warn "Only $CTRL_REFS CMMC control refs in WRITEUP.md — bidirectional mapping needs control→code tracing"
  fi

  GAP_REFS=$(grep -c "GAP-0" WRITEUP.md 2>/dev/null || echo 0)
  if [ "$GAP_REFS" -ge 8 ]; then
    ok "All 8 GAPs referenced in WRITEUP.md"
  elif [ "$GAP_REFS" -ge 5 ]; then
    warn "Only $GAP_REFS of 8 GAPs in WRITEUP.md — GAP-03, GAP-06, GAP-08 often missing"
  else
    fail "Only $GAP_REFS GAP references in WRITEUP.md — gap remediation section incomplete"
  fi
else
  fail "WRITEUP.md missing — cannot check control-to-code documentation"
fi

h2 "6.2 Inline control comments in Terraform"

TF_CTRL_COMMENTS=$(grep -rn "SC\.L2\|AC\.L2\|MP\.L2\|AU\.L2\|CMMC\|NIST\|800-171" terraform/ 2>/dev/null \
  | grep -v ".terraform/" | grep "#" | wc -l | tr -d ' ')
if [ "$TF_CTRL_COMMENTS" -ge 5 ]; then
  ok "$TF_CTRL_COMMENTS inline control comments found in terraform/ (bidirectional mapping evidence)"
else
  warn "Only $TF_CTRL_COMMENTS inline control comments — add # SC.L2-3.13.11 etc. next to each resource"
fi

h2 "6.3 Rego metadata blocks"

METADATA_BLOCKS=$(grep -rn "# METADATA\|# custom:\|control_id" policies/ 2>/dev/null | grep "\.rego" | wc -l | tr -d ' ')
if [ "$METADATA_BLOCKS" -ge 5 ]; then
  ok "$METADATA_BLOCKS metadata/control_id entries across Rego policies"
else
  warn "Only $METADATA_BLOCKS metadata entries — each policy should have # METADATA block with control_id"
fi

# =============================================================================
# LAYER 7 — Control Test Coverage (10%)
# =============================================================================

h1 "Layer 7 — Control Test Coverage (10%)"

h2 "7.1 Conftest against current plan.json"

if [ -f plan.json ] || find terraform/ -name "plan.json" 2>/dev/null | grep -q .; then
  PLAN_FILE=$(find . -maxdepth 2 -name "plan.json" | head -1)
  ok "plan.json found: $PLAN_FILE"

  if command -v conftest &>/dev/null; then
    info "Running conftest against plan.json..."
    CT_OUT=$(conftest test "$PLAN_FILE" --policy policies/ --output json 2>/dev/null || echo "[]")
    FAILURES=$(echo "$CT_OUT" | python3 -c \
      "import json,sys; d=json.load(sys.stdin); f=sum(len(r.get('failures') or []) for r in d); print(f)" 2>/dev/null || echo "?")
    if [ "$FAILURES" = "0" ]; then
      ok "conftest: 0 failures — all policies pass against current plan"
    elif [ "$FAILURES" = "?" ]; then
      warn "conftest output could not be parsed"
    else
      fail "conftest: $FAILURES failure(s) against current plan.json"
      info "Run: conftest test plan.json --policy policies/ for details"
    fi
    # Save conftest output to evidence
    mkdir -p evidence
    echo "$CT_OUT" > evidence/conftest-latest.json
    info "Conftest output saved to evidence/conftest-latest.json"
  else
    warn "conftest not in PATH — install: https://github.com/open-policy-agent/conftest/releases"
  fi
else
  warn "No plan.json found — run: cd terraform && terraform plan -out=tfplan && terraform show -json tfplan > ../plan.json"
fi

h2 "7.2 tfsec against terraform/"

if command -v tfsec &>/dev/null; then
  info "Running tfsec..."
  TFSEC_OUT=$(tfsec terraform/ --format json 2>/dev/null || echo '{"results":[]}')
  CRITICAL=$(echo "$TFSEC_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for r in d.get('results',[]) if r.get('severity','').upper()=='CRITICAL'))" 2>/dev/null || echo "?")
  HIGH=$(echo "$TFSEC_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for r in d.get('results',[]) if r.get('severity','').upper()=='HIGH'))" 2>/dev/null || echo "?")
  MEDIUM=$(echo "$TFSEC_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for r in d.get('results',[]) if r.get('severity','').upper()=='MEDIUM'))" 2>/dev/null || echo "?")
  LOW=$(echo "$TFSEC_OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for r in d.get('results',[]) if r.get('severity','').upper()=='LOW'))" 2>/dev/null || echo "?")

  [ "$CRITICAL" = "0" ] && ok "tfsec: 0 CRITICAL" || fail "tfsec: $CRITICAL CRITICAL finding(s)"
  [ "$HIGH"     = "0" ] && ok "tfsec: 0 HIGH"     || fail "tfsec: $HIGH HIGH finding(s)"
  [ "$MEDIUM"   = "0" ] && ok "tfsec: 0 MEDIUM"   || warn "tfsec: $MEDIUM MEDIUM finding(s)"
  [ "$LOW"      = "0" ] && ok "tfsec: 0 LOW"      || info "tfsec: $LOW LOW finding(s)"

  mkdir -p evidence
  echo "$TFSEC_OUT" > evidence/tfsec-latest.json
  info "tfsec output saved to evidence/tfsec-latest.json"
else
  warn "tfsec not in PATH — install from https://github.com/aquasecurity/tfsec/releases"
fi

# =============================================================================
# SCORECARD
# =============================================================================

h1 "Scorecard Summary"

TOTAL=$((PASS + WARN + FAIL))

cat >> "$REPORT" << EOF

| Result | Count | % of checks |
|--------|-------|-------------|
| ✅ OK  | $PASS | $(( PASS * 100 / (TOTAL > 0 ? TOTAL : 1) ))% |
| ⚠️ WARN | $WARN | $(( WARN * 100 / (TOTAL > 0 ? TOTAL : 1) ))% |
| ❌ FAIL | $FAIL | $(( FAIL * 100 / (TOTAL > 0 ? TOTAL : 1) ))% |
| **Total** | **$TOTAL** | |

EOF

echo "" | tee -a "$REPORT"
echo "### Auto-fail trigger check" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# Auto-fail checks
AF_PASS=0
AF_FAIL=0

af_check() {
  local label="$1" cmd="$2"
  if eval "$cmd" &>/dev/null; then
    echo "  ✅ $label" | tee -a "$REPORT"
    ((AF_PASS++))
  else
    echo "  ❌ $label" | tee -a "$REPORT"
    ((AF_FAIL++))
  fi
}

af_check "README.md exists (auto-fail if missing)" "[ -f README.md ]"
af_check "Repo is not private (grader must access it)" "git remote -v | grep -q 'github.com'"
af_check "No .tfstate files tracked" "[ -z \"\$(git ls-files '*.tfstate' 2>/dev/null)\" ]"
af_check "No obvious plaintext secrets in tracked files" \
  "! git ls-files | xargs grep -lEi 'aws_secret_access_key|password\s*=\s*\"[^\"]{8,}\"' 2>/dev/null | grep -v '.example\|sample' | grep -q ."

echo "" | tee -a "$REPORT"

if [ "$AF_FAIL" -eq 0 ]; then
  echo "**No auto-fail triggers detected.** ✅" | tee -a "$REPORT"
else
  echo "**⚠️ $AF_FAIL auto-fail trigger(s) detected — fix before submitting.**" | tee -a "$REPORT"
fi

echo "" | tee -a "$REPORT"
echo "### Priority action list" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "Items below are ordered: FAIL first (must fix), then WARN (improves score)." | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "Re-run this script after each fix to update the report." | tee -a "$REPORT"
echo "" | tee -a "$REPORT"
echo "_Generated by audit_capstone.sh — $TIMESTAMP_" | tee -a "$REPORT"

# ── final console summary ────────────────────────────────────────────────────
echo ""
echo "=============================="
echo " AUDIT COMPLETE"
echo "=============================="
echo " OK  : $PASS"
echo " WARN: $WARN"
echo " FAIL: $FAIL"
echo " Auto-fail triggers: $AF_FAIL"
echo ""
echo " Report saved → $REPORT"
echo "=============================="