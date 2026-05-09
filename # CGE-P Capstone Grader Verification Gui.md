# CGE-P Capstone Grader Verification Guide

**Repository:** https://github.com/leeclay95/cgep-app-starter-1  
**Primary Framework:** CMMC Level 2 (NIST SP 800-171 Rev 2)  
**Evidence Vault:** acme-health-evidence-vault-969958573430

---

## Prerequisites

```bash
# Clone the repo
git clone https://github.com/leeclay95/cgep-app-starter-1.git
cd cgep-app-starter-1

# Install required tools
pip install compliance-trestle
# opa, conftest, tfsec, gitleaks, cosign must be on PATH
# AWS CLI configured with read access to the account
```

---

## Step 1 — Repository Structure Check

```bash
# Confirm repo is a derivative of the CGE-P starter
git log --oneline | tail -3

# Confirm required files exist
ls README.md WRITEUP.md GAPS.md FRAMEWORKS.md

# Confirm framework is declared in first paragraph of WRITEUP.md
head -3 WRITEUP.md

# Confirm repo structure matches capstone requirements
ls terraform/
ls terraform/baselines/aws/
ls policies/
ls .github/workflows/grc-gate.yml
ls oscal/component-definitions/patient-intake-api/component-definition.json
ls oscal/profiles/cmmc-level-2/profile.json
ls scripts/verify-evidence.sh
```

---

## Step 2 — Policy Suite Verification

```bash
# Confirm 5 policy files exist (excluding test files)
ls policies/*.rego | grep -v test

# Confirm all 12 tests pass
opa test ./policies --verbose
# Expected: PASS 12/12

# Confirm each policy has a CMMC control ID metadata header
grep -A6 "METADATA" policies/enforce_kms.rego
grep -A6 "METADATA" policies/enforce_least_privilege.rego
grep -A6 "METADATA" policies/enforce_tls.rego
grep -A6 "METADATA" policies/enforce_versioning.rego
grep -A6 "METADATA" policies/enforce_vpc.rego
```

---

## Step 3 — Pipeline History Verification

```bash
# Confirm one red PR (blocked) and one green PR (merged) in history
gh pr list --state merged --limit 10

# List all workflow runs
gh run list --limit 20

# Confirm the red run failed on the tfsec gate
gh run view 25576629006 --log | grep -E "dynamodb|FAILURE|exit code"

# Confirm the green run passed all gates
gh run view 25576780518 --log | grep -E "conftest failures|tfsec high|PASS"
```

---

## Step 4 — Evidence Bundle Verification

### 4a Discover vault and get the latest run

```bash
# Discover the evidence vault dynamically
VAULT=$(aws s3api list-buckets \
  --query 'Buckets[?contains(Name,`evidence-vault`)].Name' \
  --output text)

echo "Vault: $VAULT"

# Get the latest run ID
LATEST_RUN=$(aws s3 ls s3://${VAULT}/runs/ \
  --recursive | grep receipt.json | sort | tail -1 | awk -F'/' '{print $2}')

echo "Latest run ID: $LATEST_RUN"

# Read the receipt
aws s3 cp \
  s3://${VAULT}/runs/${LATEST_RUN}/receipt.json \
  - | python3 -m json.tool
```

Expected output:
```json
{
    "run_id": "<run_id>",
    "vault": "acme-health-evidence-vault-969958573430",
    "bundle_key": "runs/<run_id>/evidence-25603298600-<sha>.tar.gz",
    "version_id": "<s3_version_id>",
    "sha256": "<sha256_of_bundle>",
    "commit": "<git_commit_sha>"
}
```

### 4b Download and extract the bundle to inspect its contents

```bash
# Get bundle key from receipt
BUNDLE_KEY=$(aws s3 cp \
  s3://${VAULT}/runs/${LATEST_RUN}/receipt.json \
  - | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['bundle_key'])")

BUNDLE_FILE=$(basename $BUNDLE_KEY)

# Download the bundle
aws s3 cp s3://${VAULT}/${BUNDLE_KEY} /tmp/${BUNDLE_FILE}

# Clean extract directory and extract
rm -rf /tmp/bundle-inspect
mkdir -p /tmp/bundle-inspect
tar -xzf /tmp/${BUNDLE_FILE} -C /tmp/bundle-inspect

# List all files in the bundle
echo "=== Bundle contents ==="
find /tmp/bundle-inspect -type f | sort

# Read conftest results
echo "=== conftest-results.json ==="
cat /tmp/bundle-inspect/conftest-results.json | python3 -m json.tool

# Read plan summary
echo "=== plan.txt (first 40 lines) ==="
cat /tmp/bundle-inspect/plan.txt | head -40

# Read tfsec results
echo "=== tfsec-latest.json ==="
cat /tmp/bundle-inspect/tfsec-latest.json | python3 -m json.tool

# Read trestle validation output
echo "=== trestle-validate.txt ==="
cat /tmp/bundle-inspect/trestle-validate.txt

# Read plan.json summary
echo "=== plan.json summary ==="
cat /tmp/bundle-inspect/plan.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('Top level keys:', list(d.keys()))
print('Terraform version:', d.get('terraform_version'))
print('Resource changes:', len(d.get('resource_changes', [])))
"
```

### 4c Run the full chain verification

```bash
EVIDENCE_VAULT=${VAULT} bash scripts/verify-evidence.sh ${LATEST_RUN}
```

Expected output:
```
==> Bundle: evidence-<run_id>-<sha>.tar.gz
--- [1/3] Integrity check ---
OK: SHA256 <hash>
--- [2/3] Authenticity check ---
Verified OK
OK: cosign signature verified
--- [3/3] Preservation check ---
OK: Object Lock active until <date>
==============================
CHAIN INTACT for run <run_id>
==============================
```

### 4d Confirm Object Lock on vault and absence on PHI bucket

```bash
# Vault must have Object Lock
aws s3api get-object-lock-configuration --bucket ${VAULT}
# Expected: ObjectLockEnabled Enabled, Mode GOVERNANCE

# PHI uploads bucket must NOT have Object Lock
PHI_BUCKET=$(aws s3api list-buckets \
  --query 'Buckets[?contains(Name,`uploads`)].Name' \
  --output text)

aws s3api get-object-lock-configuration \
  --bucket ${PHI_BUCKET} \
  2>&1 || echo "Correct — no Object Lock on PHI bucket, deletion rights preserved"
```

---

## Step 5 — OSCAL Verification

```bash
cd oscal

# Validate component definition
python3 -m trestle validate \
  -f component-definitions/patient-intake-api/component-definition.json
# Expected: VALID

# Validate profile
python3 -m trestle validate \
  -f profiles/cmmc-level-2/profile.json
# Expected: VALID

# List all 5 implemented requirements with their control IDs
python3 -c "
import json
d = json.load(open('component-definitions/patient-intake-api/component-definition.json'))
reqs = d['component-definition']['components'][0]['control-implementations'][0]['implemented-requirements']
print(f'Total implemented requirements: {len(reqs)}')
for r in reqs:
    print(f\"  {r['control-id']} — {r['description'][:70]}\")
"
# Expected: 5 requirements — sc-28, ac-6, sc-8, cp-9, sc-7

# Confirm each requirement references real Terraform resources
python3 -c "
import json
d = json.load(open('component-definitions/patient-intake-api/component-definition.json'))
reqs = d['component-definition']['components'][0]['control-implementations'][0]['implemented-requirements']
for r in reqs:
    props = [p['value'] for p in r.get('props', []) if p['name'] == 'terraform-resource']
    print(f\"{r['control-id']}: {props}\")
"

# Confirm evidence links point to real vault objects
python3 -c "
import json
d = json.load(open('component-definitions/patient-intake-api/component-definition.json'))
reqs = d['component-definition']['components'][0]['control-implementations'][0]['implemented-requirements']
for r in reqs:
    print(r['control-id'], '->', r['links'][0]['href'])
"

cd ..
```

---

## Step 6 — Infrastructure Control Verification

### SC.L2-3.13.11 — KMS Encryption at Rest

```bash
# Confirm CMK exists with rotation enabled
aws kms describe-key \
  --key-id alias/cmmc-key \
  --query 'KeyMetadata.{KeyId:KeyId,Enabled:Enabled,KeyState:KeyState}'


# Confirm DynamoDB uses the CMK
aws dynamodb describe-table \
  --table-name acme-health-intake-submissions-4fa2ee1b \
  --query 'Table.SSEDescription'
# Expected: Status ENABLED, SSEType KMS

# Confirm S3 uploads bucket uses the CMK
aws s3api get-bucket-encryption \
  --bucket acme-health-intake-uploads-4fa2ee1b
# Expected: SSEAlgorithm aws:kms with CMK ARN

# Confirm conftest catches the gap when missing
cat > /tmp/test_bad_kms.json << 'EOF'
{"configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.bad","type":"aws_s3_bucket","expressions":{}}
]}}}
EOF
conftest test /tmp/test_bad_kms.json --policy ./policies --namespace kms
# Expected: FAILURE
```

### AC.L2-3.1.5 — Least Privilege

```bash
# Confirm lambda_inline has no wildcard actions
aws iam get-role-policy \
  --role-name $(aws iam list-roles \
    --query 'Roles[?contains(RoleName,`acme-health-intake`)&&contains(RoleName,`lambda`)].RoleName' \
    --output text | head -1) \
  --policy-name intake-data-access \
  --query 'PolicyDocument' | python3 -m json.tool

# Confirm conftest catches wildcard
cat > /tmp/test_bad_iam.json << 'EOF'
{"resource_changes":[{
  "address":"aws_iam_role_policy.violation",
  "type":"aws_iam_role_policy",
  "change":{"after":{"policy":"{\"Action\":\"*\"}"}}
}]}
EOF
conftest test /tmp/test_bad_iam.json --policy ./policies --namespace least_privilege
# Expected: FAILURE

# Confirm tfsec config has scoped ignores not global exclude
cat .tfsec/config.yml
# Expected: exclude_results with specific resource addresses, no global exclude
```

### SC.L2-3.13.8 — TLS in Transit

```bash
# Confirm bucket policy denies non-TLS
aws s3api get-bucket-policy \
  --bucket acme-health-intake-uploads-4fa2ee1b \
  --query 'Policy' --output text | python3 -m json.tool | \
  grep -A3 "SecureTransport"
# Expected: Deny with aws:SecureTransport false condition

# Confirm conftest catches missing TLS policy
cat > /tmp/test_bad_tls.json << 'EOF'
{"configuration":{"root_module":{"resources":[
  {"address":"aws_s3_bucket.unprotected","type":"aws_s3_bucket","expressions":{}}
]}}}
EOF
conftest test /tmp/test_bad_tls.json --policy ./policies --namespace tls
# Expected: FAILURE
```

### MP.L2-3.8.9 — Versioning

```bash
# Confirm versioning enabled
aws s3api get-bucket-versioning \
  --bucket acme-health-intake-uploads-4fa2ee1b
# Expected: Status Enabled

# Confirm no lifecycle policy — documented gap
aws s3api get-bucket-lifecycle-configuration \
  --bucket acme-health-intake-uploads-4fa2ee1b \
  2>&1 || echo "NoSuchLifecycleConfiguration — gap documented in WRITEUP.md"

# Confirm DynamoDB TTL disabled — records retained indefinitely
aws dynamodb describe-time-to-live \
  --table-name acme-health-intake-submissions-4fa2ee1b
# Expected: TimeToLiveStatus DISABLED

# Confirm conftest catches missing versioning
cat > /tmp/test_bad_ver.json << 'EOF'
{"resource_changes":[
  {"type":"aws_s3_bucket","address":"aws_s3_bucket.bad"}
]}
EOF
conftest test /tmp/test_bad_ver.json --policy ./policies --namespace versioning
# Expected: FAILURE
```

### SC.L2-3.13.6 — VPC Network Segmentation

```bash
# Confirm Lambda is in VPC with private subnets
aws lambda get-function-configuration \
  --function-name acme-health-intake-handler-4fa2ee1b \
  --query 'VpcConfig'
# Expected: SubnetIds and SecurityGroupIds populated

# Confirm VPC endpoints exist for all downstream services
aws ec2 describe-vpc-endpoints \
  --filters "Name=vpc-id,Values=vpc-017ff5a2690d07dcb" \
  --query 'VpcEndpoints[].{Service:ServiceName,State:State}' \
  --output table
# Expected: dynamodb, s3, kms, sqs, logs, xray — all available

# Confirm no NAT gateway
aws ec2 describe-nat-gateways \
  --filter "Name=vpc-id,Values=vpc-017ff5a2690d07dcb" \
  --query 'NatGateways[?State!=`deleted`].State' \
  --output text
# Expected: empty — no internet egress

# Confirm conftest catches Lambda without VPC
cat > /tmp/test_bad_vpc.json << 'EOF'
{"configuration":{"root_module":{"resources":[{
  "address":"aws_lambda_function.bad",
  "type":"aws_lambda_function",
  "expressions":{"vpc_config":{"constant_value":"{}"}}
}]}}}
EOF
conftest test /tmp/test_bad_vpc.json --policy ./policies --namespace vpc
# Expected: FAILURE
```

---

## Step 7 — Continuous Monitoring Verification

```bash
# Confirm CloudTrail is logging
aws cloudtrail get-trail-status \
  --name cgep-lab-mgmt \
  --query '{IsLogging:IsLogging,LatestDeliveryTime:LatestDeliveryTime}'
# Expected: IsLogging true

# Confirm log file validation is enabled
aws cloudtrail describe-trails \
  --query 'trailList[?Name==`cgep-lab-mgmt`].LogFileValidationEnabled'
# Expected: true

# Confirm Security Hub standards are subscribed
aws securityhub get-enabled-standards \
  --query 'StandardsSubscriptions[].StandardsArn'
# Expected: nist-800-53 and aws-foundational-security-best-practices

# Confirm Config rules are active
aws configservice describe-config-rules \
  --query 'ConfigRules[].{Name:ConfigRuleName,State:ConfigRuleState}'
# Expected: cmk-rotation, s3-ssl-only, vpc-flow-logs — ACTIVE

# Confirm VPC flow logs are enabled
aws ec2 describe-flow-logs \
  --filter "Name=resource-id,Values=vpc-017ff5a2690d07dcb" \
  --query 'FlowLogs[].{Status:FlowLogStatus,Destination:LogDestinationType}'
# Expected: ACTIVE, cloud-watch-logs
```

---

## Step 8 — Engineering Hygiene

```bash
# Confirm no secrets in full repo history
gitleaks detect --source . --log-opts="--all" --verbose
# Expected: 0 leaks found

# Confirm terraform fmt passes
cd terraform && terraform fmt -check -recursive
cd ..

# Confirm terraform validate passes
cd terraform && terraform validate
cd ..
```

---

## Summary Checklist

| Check | Command | Expected |
|---|---|---|
| OPA tests | `opa test ./policies` | PASS 12/12 |
| OSCAL component | `trestle validate -f component-definitions/...` | VALID |
| OSCAL profile | `trestle validate -f profiles/...` | VALID |
| Chain of custody | `verify-evidence.sh <latest_run>` | CHAIN INTACT |
| Object Lock vault | `get-object-lock-configuration vault` | ENABLED GOVERNANCE |
| KMS rotation | `get-key-rotation-status alias/cmmc-key` | true |
| DynamoDB KMS | `describe-table intake_table` | ENABLED KMS |
| S3 KMS | `get-bucket-encryption uploads` | aws:kms |
| TLS policy | `get-bucket-policy uploads` | Deny SecureTransport false |
| Versioning | `get-bucket-versioning uploads` | Enabled |
| Lambda VPC | `get-function-configuration` | SubnetIds populated |
| VPC endpoints | `describe-vpc-endpoints` | 6 endpoints available |
| No NAT gateway | `describe-nat-gateways` | empty |
| CloudTrail | `get-trail-status cgep-lab-mgmt` | IsLogging true |
| Security Hub | `get-enabled-standards` | nist-800-53 subscribed |
| Gitleaks | `gitleaks detect --log-opts="--all"` | 0 leaks |
