# Acme Health Patient Intake API — CGE-P Capstone

This repository is a governed derivative of the CGE-P capstone starter. It wraps a deliberately non-compliant patient intake API with four layers of GRC controls aligned to CMMC Level 2, the primary framework selected for this submission.

The original starter ships eight named compliance gaps. This repository closes five of them with Terraform infrastructure overrides, five Rego policies that fail the CI gate when gaps are reintroduced, a GitHub Actions evidence pipeline that signs and vaults every run, and an OSCAL component definition that traces each control to the specific code satisfying it.

---

## Repository Layout

```
cgep-app-starter-1/
├── terraform/                        # Application stack — workload + gap remediations
│   ├── main.tf                       # Lambda, DynamoDB, S3, VPC, IAM, KMS wiring
│   ├── variables.tf
│   ├── outputs.tf
│   ├── baselines/
│   │   └── aws/                      # Baseline stack — KMS CMK, CloudTrail, Config, Security Hub, vault
│   └── lambda/handler.py
├── policies/                         # OPA Rego policy suite (5 policies + 5 test files)
│   ├── enforce_kms.rego              # SC.L2-3.13.11 — KMS encryption at rest
│   ├── enforce_kms_test.rego
│   ├── enforce_tls.rego              # SC.L2-3.13.8  — TLS in transit
│   ├── enforce_tls_test.rego
│   ├── enforce_versioning.rego       # MP.L2-3.8.9   — S3 versioning
│   ├── enforce_versioning_test.rego
│   ├── enforce_vpc.rego              # SC.L2-3.13.6  — Lambda VPC placement
│   ├── enforce_vpc_test.rego
│   ├── enforce_least_privilege.rego  # AC.L2-3.1.5   — IAM least privilege
│   └── enforce_least_privilege_test.rego
├── .github/workflows/grc-gate.yml   # CI pipeline: plan -> conftest -> tfsec -> sign -> vault
├── .tfsec/config.yml                 # Scoped tfsec ignores with justification comments
├── oscal/
│   ├── component-definitions/
│   │   └── patient-intake-api/
│   │       └── component-definition.json   # trestle-validated OSCAL component
│   └── profiles/
│       └── cmmc-level-2/
│           └── profile.json                # NIST 800-53 Rev 5 control selection
├── scripts/
│   ├── capture-evidence.sh           # Manual evidence bundle capture
│   ├── policy-gate.sh                # Local conftest runner
│   └── verify-evidence.sh            # Chain of custody verification
├── evidence/                         # Local evidence artifacts
├── oidc/                             # Terraform for GitHub Actions OIDC trust
├── WRITEUP.md                        # Design decisions, gap remediation, trade-offs
├── GAPS.md                           # Eight named starter gaps
└── FRAMEWORKS.md                     # Framework mapping primer
```

---

## What Was Built

### Layer 1 — Terraform Baseline

Two stacks deploy the governed infrastructure.

`terraform/baselines/aws/` provisions account-level controls: a Customer Managed KMS key with rotation enabled, a multi-region CloudTrail trail with log file validation, AWS Config with rules for CMK rotation, S3 SSL enforcement, and VPC flow log presence, Security Hub with NIST 800-53 and FSBP standards, and an S3 evidence vault with Object Lock in GOVERNANCE mode.

`terraform/` provisions the workload with all gap remediations applied: KMS SSE on S3 and DynamoDB, TLS-enforcing bucket policies, S3 versioning, Lambda VPC placement with private subnets and VPC endpoints for all downstream services, scoped IAM policies replacing wildcard actions, a DLQ, X-Ray tracing, and API Gateway access logging.

### Layer 2 — OPA Policy Suite

Five Rego policies enforce CMMC Level 2 controls at plan time via conftest. Each policy has passing and failing test fixtures. All twelve tests pass under `opa test ./policies`.

tfsec provides complementary HCL-level static analysis for IAM wildcard actions.

### Layer 3 — GitHub Actions Pipeline

The `grc-gate` workflow runs on every pull request targeting main. It plans Terraform, runs conftest against all five policy namespaces, runs tfsec at HIGH severity, assembles an evidence bundle, signs it with Cosign via GitHub Actions OIDC (keyless), and uploads the signed bundle with SHA-256 sidecar and receipt to the evidence vault under `runs/<run_id>/`. Object Lock retention is applied at the bucket level.

The repo history contains one red PR blocked by the tfsec gate on a `dynamodb:*` wildcard and one green PR that passed all gates.

### Layer 4 — OSCAL Component

`oscal/component-definitions/patient-intake-api/component-definition.json` describes the Patient Intake API against the NIST 800-53 Rev 5 catalog. Five implemented requirements map each CMMC practice to its 800-53 equivalent, reference the specific Terraform resource addresses satisfying each control, and link to the signed evidence receipt in the vault. Both the component definition and the profile validate under `trestle validate`.

---


## Framework

Primary: CMMC Level 2 (NIST SP 800-171 Rev 2)
OSCAL catalog source: NIST SP 800-53 Rev 5
