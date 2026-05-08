# CGE-P Capstone Progress: Phase 1
## Layer 1 — Infrastructure-as-Code & CMMC Hardening

### Overview
In this phase, I established the GRC Baseline and hardened the Acme Health Patient Intake API to meet CMMC Level 2 (NIST 800-171) requirements. The system was transitioned from an "audit-indefensible" state to a governed, encrypted, and isolated architecture.

---

### Technical Implementations

#### 1. Identity & Chain of Custody (OIDC)
* **Action**: Provisioned an IAM OpenID Connect Provider and a dedicated GRC Gate role (acme-grc-gate-role).
* **Purpose**: Enables the GitHub Actions pipeline to assume a role via OIDC, eliminating the need for long-lived AWS access keys and preventing auto-fail triggers.
* **CMMC Mapping**: AC.L2-3.1.1 (Authorized Access Enforcement).

#### 2. Cryptographic Foundation (KMS)
* **Action**: Created a Customer Managed Key (CMK) with rotation enabled.
* **Purpose**: Moves the workload away from AWS-managed default encryption to customer-custody keys.
* **CMMC Mapping**: SC.L2-3.13.11 (FIPS-validated cryptography).

#### 3. Evidence Vault & Integrity
* **Action**: Created an S3 bucket with Object Lock in Governance mode and versioning enabled.
* **Purpose**: Provides an immutable destination for signed evidence bundles, satisfying protection of storage media requirements.
* **CMMC Mapping**: MP.L2-3.8.3 (Protecting information on removable media).

#### 4. Audit & Accountability
* **Action**: Provisioned a multi-region CloudTrail with log-file validation writing to a dedicated, policy-hardened bucket.
* **Purpose**: Records all management events and ensures logs are tamper-evident.
* **CMMC Mapping**: AU.L2-3.3.1 (Generate and retain audit records).

---

### Workload Hardening (Gap Remediation)

I applied the following overrides to the cgep-app-starter resources in terraform/main.tf:

| Gap ID | Remediation Action | CMMC Practice |
| :--- | :--- | :--- |
| **GAP-01** | Forced uploads S3 bucket to use KMS CMK via encryption configuration. | SC.L2-3.13.11 |
| **GAP-02** | Applied KMS CMK to the DynamoDB submissions table. | SC.L2-3.13.11 |
| **GAP-04** | Enabled S3 bucket versioning to prevent unrecoverable data overwrites. | MP.L2-3.8.9 |
| **GAP-05** | Migrated Lambda from public environment into Private Subnets via vpc_config. | SC.L2-3.13.1 |
| **GAP-07** | Refined Lambda IAM Policy from dynamodb:* to specific actions (PutItem, DescribeTable). | AC.L2-3.1.5 |

---

### Verification Results
* **Terraform Apply**: Successfully provisioned the starter workload and GRC baseline resources.
* **Connectivity Test**: make test returned status received, confirming the Lambda successfully communicates with DynamoDB and S3 from within the VPC.
* **Audit Trail**: Verified CloudTrail is actively capturing events in the AWS Console.

