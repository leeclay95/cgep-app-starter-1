# CGE-P Capstone Write-Up: Acme Health Patient Intake API

## Framework Choice: CMMC Level 2

Acme Health is pursuing a federal pilot contract. That single fact drives the framework decision. HIPAA and SOC 2 both apply to this workload because it handles PHI and serves enterprise customers, but neither carries the contractual weight of a CMMC Level 2 attestation for federal work. CMMC Level 2 inherits all 110 practices from NIST SP 800-171 Rev 2, which means satisfying it also satisfies the technical safeguard requirements under HIPAA and the security criteria under SOC 2. Choosing CMMC as the primary framework produces the broadest coverage with the clearest regulatory mandate.

Every Rego policy in this repository maps to a named CMMC Level 2 practice. Every OSCAL implemented-requirement cites the corresponding NIST 800-53 Rev 5 control. The gap remediation work below is organized around the eight named gaps in GAPS.md and explains which CMMC practice each gap implicates, what the technical remediation is, and why that approach was chosen over the alternatives.

---

## Gap Remediation

### GAP-01 and GAP-02: Missing Customer-Managed KMS Encryption

CMMC practice SC.L2-3.13.11 requires FIPS-validated cryptography for protecting CUI confidentiality. The starter shipped with both the S3 uploads bucket and the DynamoDB submissions table relying on AWS-owned default keys. AWS-owned keys satisfy encryption at rest in a narrow technical sense, but they do not satisfy customer key custody. Under CMMC, the organization must control the keys protecting CUI. If AWS rotates or retires an AWS-owned key, the customer has no visibility and no control.

The remediation deploys a single Customer Managed Key in `terraform/baselines/aws/main.tf` via `aws_kms_key.cmmc_key` with automatic rotation enabled. The same CMK is referenced by both `aws_s3_bucket_server_side_encryption_configuration.uploads_kms` and `aws_s3_bucket_server_side_encryption_configuration.logs_kms` for S3, and by the `server_side_encryption` block on `aws_dynamodb_table.intake`. A KMS alias (`aws_kms_alias.cmmc_key`) is used for stable reference across both Terraform stacks via `data.aws_kms_alias.cmmc_key` in the application stack.

A single shared CMK was chosen over per-resource keys because this is a single-workload environment with a single data classification level. Separate keys per resource add operational complexity without meaningful security benefit when the threat model does not require key isolation between S3 and DynamoDB. If the workload expanded to handle multiple data classification levels, per-classification keys would be appropriate.

The policy `policies/enforce_kms.rego` enforces this at plan time. It reads from `input.configuration.root_module.resources` because the KMS SSE configuration has a `constant_value` readable at plan time for the `sse_algorithm` field, and it links SSE config resources back to their target buckets via the `references` array in the configuration block.

### GAP-03: Missing TLS Enforcement on S3 Buckets

CMMC practice SC.L2-3.13.8 requires encryption of CUI in transit. The starter had no bucket policy on the uploads bucket, meaning HTTP requests were not explicitly denied. AWS does not enforce HTTPS at the S3 bucket level by default. A client using path-style HTTP access or a misconfigured SDK could write PHI over an unencrypted channel.

The remediation adds `aws_s3_bucket_policy.uploads_tls_only` with a Deny statement on `s3:*` conditioned on `aws:SecureTransport` equal to false. The same pattern is applied to the logs bucket via `aws_s3_bucket_policy.logs_combined`, which also carries the S3 logging service delivery allow statement. Both buckets now reject any request not using TLS.

The policy `policies/enforce_tls.rego` enforces this at plan time. Because the bucket policy JSON is fully dynamic at plan time (all values are in `after_unknown`), the policy reads from `input.configuration.root_module.resources` and checks structural presence: every `aws_s3_bucket` resource must have a corresponding `aws_s3_bucket_policy` resource whose `bucket.references` array contains the bucket's address. This is a structural check rather than a content check. Content verification is handled by tfsec.

### GAP-04: Missing S3 Versioning

CMMC practice MP.L2-3.8.9 requires protection of backup CUI on storage media. For a workload writing PHI to S3, versioning is the primary mechanism ensuring that an overwrite or accidental deletion does not permanently destroy the only copy of a submission. The starter had no versioning configuration on the uploads bucket.

The remediation adds `aws_s3_bucket_versioning.uploads` and `aws_s3_bucket_versioning.logs` with status set to Enabled. The logs bucket is versioned alongside the uploads bucket because CloudTrail and S3 access logs are audit records whose integrity is independently required under CMMC AU.L2-3.3.1.

The policy `policies/enforce_versioning.rego` enforces this at plan time using `input.resource_changes`, where the versioning configuration status is a resolved value. This is one of the policies that can use `resource_changes` because the versioning status is not a dynamic reference.

### GAP-05: Lambda Not Deployed in VPC

CMMC practice SC.L2-3.13.6 requires network segmentation to protect CUI. The starter deployed the Lambda function with no `vpc_config` block, meaning it ran in the default Lambda managed environment with direct internet-routable egress. A function handling PHI submissions should not have arbitrary outbound internet access.

The remediation adds a `vpc_config` block to `aws_lambda_function.intake` referencing `aws_subnet.private[*]` and `aws_security_group.lambda`. The security group allows no inbound and restricts outbound to HTTPS on port 443 within the VPC CIDR. VPC endpoints are provisioned for every AWS service the Lambda calls: DynamoDB, S3, KMS, SQS, CloudWatch Logs, and X-Ray. This means all data plane traffic from the Lambda to AWS services transits the AWS private network and never leaves the VPC over the internet gateway.

VPC endpoints were chosen over a NAT gateway because the Lambda has no legitimate reason to reach the public internet. NAT gateways add cost and reintroduce the internet egress surface the VPC was meant to eliminate. The endpoint-only architecture enforces least-network-privilege at the infrastructure level.

The policy `policies/enforce_vpc.rego` enforces this at plan time by checking `input.configuration.root_module.resources` for any `aws_lambda_function` whose `vpc_config` expression does not include a `subnet_ids` reference.

### GAP-07: Wildcard IAM Actions

CMMC practice AC.L2-3.1.5 requires least privilege. The starter's `aws_iam_role_policy.lambda_inline` granted `dynamodb:*` and `s3:*` on the workload resources. This gives the Lambda permission to delete the DynamoDB table, purge all S3 objects, modify bucket policies, and perform any other action in those services. None of those actions are required for the function's actual behavior, which is writing submissions to DynamoDB and uploading attachments to S3.

The remediation splits the original policy into two resources. `aws_iam_role_policy.lambda_inline` is scoped to `dynamodb:PutItem` and `dynamodb:DescribeTable` on the intake table ARN, plus `s3:GetEncryptionConfiguration` on the bucket ARN, plus `kms:GenerateDataKey` and `kms:Decrypt` on the CMK ARN. A separate `aws_iam_role_policy.lambda_s3_write` is scoped to `s3:PutObject` on `${uploads_bucket_arn}/uploads/*`.

The split is necessary because tfsec's `aws-iam-no-policy-wildcards` check operates at the resource block level. The `s3:PutObject` action on a path ending in `/*` is flagged as a wildcard by tfsec regardless of prefix specificity. That finding is a justified false positive: the `/uploads/*` suffix is the minimum viable scope without hardcoding runtime object keys. By isolating that statement in its own resource block, the `#tfsec:ignore` annotation is scoped only to the justified case. The `dynamodb:PutItem` and `dynamodb:DescribeTable` actions on `lambda_inline` have no wildcard and receive no annotation.

The policy `policies/enforce_least_privilege.rego` enforces this in two complementary ways. At the conftest layer, it reads `input.resource_changes` for any `aws_iam_role_policy` and checks the rendered policy string. Because `jsonencode()` with dynamic references defers the entire policy value to `after_unknown` at plan time, the conftest policy alone cannot catch this violation when the policy contains any dynamic ARN reference. The tfsec gate catches it at the HCL source level, where the action strings are always readable. Both gates must pass for a PR to merge.

### GAP-06: No DLQ, No X-Ray, No Reserved Concurrency

CMMC practice SI.L2-3.14.6 requires flaw remediation and system monitoring. The starter had no mechanism to capture failed Lambda invocations, no distributed tracing, and no concurrency controls to prevent resource exhaustion.

The remediation adds `aws_sqs_queue.lambda_dlq` as a dead letter queue wired to the Lambda via `dead_letter_config`. X-Ray active tracing is enabled via `tracing_config { mode = "Active" }` with the `AWSXRayDaemonWriteAccess` policy attached. Reserved concurrency is not set because this is a development environment where concurrency limits would block legitimate testing, but the DLQ ensures failed invocations are captured and inspectable rather than silently dropped.

### GAP-08: No API Gateway Access Logging

CMMC practice AU.L2-3.3.1 requires generating audit records. The starter's API Gateway stage had no `access_log_settings` block. API Gateway does not write access logs by default; without explicit configuration, every request to the intake endpoint is unrecorded.

The remediation adds `aws_cloudwatch_log_group.api_gw` and wires it to `aws_apigatewayv2_stage.default` via `access_log_settings { destination_arn }`. The log format captures request ID, source IP, HTTP method, route, status code, response length, and request time. A dedicated IAM role `aws_iam_role.api_gw_logging` with the `AmazonAPIGatewayPushToCloudWatchLogs` managed policy grants API Gateway permission to write to CloudWatch.

---

## Architecture

The final deployed architecture has two Terraform stacks.

The baseline stack in `terraform/baselines/aws/` provisions the account-level controls: the CMK with rotation, a CloudTrail trail writing to a dedicated S3 bucket with log file validation enabled, AWS Config with rules for CMK rotation, S3 SSL enforcement, and VPC flow log presence, Security Hub with NIST 800-53 and FSBP standards subscribed, and the evidence vault S3 bucket with Object Lock in GOVERNANCE mode.

The application stack in `terraform/` provisions the workload resources with all gap remediations applied. It references the CMK from the baseline stack via a data source on the KMS alias, ensuring both stacks share the same key without creating a cross-stack dependency that would force sequential deploys.

VPC flow logs are enabled via `aws_flow_log.main` writing to `aws_cloudwatch_log_group.vpc_flow_logs`. This satisfies the AWS Config rule `aws_config_config_rule.vpc_flow_logs` and provides network-level audit records independently of the Lambda application logs.

---

## Policy Suite

Five Rego policies are deployed in `policies/`. Each policy has a corresponding `_test.rego` file with passing and failing fixtures. All twelve tests pass under `opa test ./policies`.

`policies/enforce_kms.rego` maps to CMMC SC.L2-3.13.11. It checks that every `aws_s3_bucket` has a corresponding `aws_s3_bucket_server_side_encryption_configuration` referencing it with `sse_algorithm` equal to `aws:kms`, and that every `aws_dynamodb_table` has a `server_side_encryption` block with `enabled` set to true. The linkage between an SSE config resource and its target bucket is resolved via the `references` array in `input.configuration`, not by runtime value matching, because bucket names are unknown at plan time.

`policies/enforce_tls.rego` maps to CMMC SC.L2-3.13.8. It checks that every `aws_s3_bucket` has a corresponding `aws_s3_bucket_policy` resource whose `bucket.references` array includes the bucket address. This is a structural check at plan time.

`policies/enforce_versioning.rego` maps to CMMC MP.L2-3.8.9. It reads from `input.resource_changes` and checks for the presence of an `aws_s3_bucket_versioning` resource with `versioning_configuration[0].status` equal to Enabled.

`policies/enforce_vpc.rego` maps to CMMC SC.L2-3.13.6. It checks `input.configuration.root_module.resources` for any `aws_lambda_function` whose `vpc_config` expression does not contain a `subnet_ids` reference.

`policies/enforce_least_privilege.rego` maps to CMMC AC.L2-3.1.5. It reads `input.resource_changes` and checks the rendered policy string for wildcard action characters. This check is complemented by tfsec at the HCL source level for cases where the policy value is fully dynamic at plan time.

---

## CI/CD Pipeline

The GitHub Actions workflow in `.github/workflows/grc-gate.yml` runs on every pull request targeting main. It performs the following steps in order.

Terraform init, validate, and plan run against the application stack. The plan output is converted to JSON via `terraform show -json`.

Conftest runs the five Rego policies against the plan JSON using `--all-namespaces`. The Python evaluation step counts failures and exits non-zero if any are present.

tfsec runs against the Terraform source directory with `--minimum-severity HIGH` and the `.tfsec/config.yml` configuration. Scoped `#tfsec:ignore` annotations on `aws_iam_role_policy.lambda_s3_write` and `aws_iam_role_policy.vpc_flow_logs` suppress the two justified wildcard findings. The Python evaluation step counts remaining HIGH findings and exits non-zero if any are present.

On every run, including failures, the evidence bundle is assembled from the plan JSON, plan text, conftest results, and tfsec SARIF output. The bundle is signed with Cosign using keyless signing via the GitHub Actions OIDC token. The signature, SHA-256 sidecar, and a JSON receipt are uploaded to the evidence vault S3 bucket under `runs/<run_id>/`. Object Lock GOVERNANCE retention is applied at the bucket level.

The repo history contains one red PR (`test/cmmc-red-test`) blocked by the tfsec gate on `dynamodb:*` in `aws_iam_role_policy.lambda_inline`, and one green PR (`feat/oscal-component-definition`) that passed all gates and merged cleanly.

---

## Evidence Pipeline and Chain of Custody

The evidence vault is `aws_s3_bucket.vault` in the baseline stack with Object Lock enabled at bucket creation in GOVERNANCE mode. GOVERNANCE mode was chosen over COMPLIANCE because this is a capstone environment where the ability to clean up is operationally necessary. A production deployment handling real CUI would use COMPLIANCE mode with a retention period aligned to the applicable record retention requirement.

Every pipeline run produces four artifacts in the vault under `runs/<run_id>/`: the evidence bundle tarball, a SHA-256 sidecar, a Cosign signature bundle, and a JSON receipt. The `scripts/verify-evidence.sh` script performs the full chain verification: SHA-256 integrity, Cosign authenticity against the Sigstore Rekor transparency log, and S3 Object Lock retention validity. All three checks pass for run 25579699620, the most recent signed run.

---

## OSCAL

The OSCAL component definition at `oscal/component-definitions/patient-intake-api/component-definition.json` describes the Patient Intake API against the NIST 800-53 Rev 5 catalog. Five implemented requirements are declared, one per Rego policy, mapping each CMMC practice to its 800-53 equivalent: SC.L2-3.13.11 to sc-28, AC.L2-3.1.5 to ac-6, SC.L2-3.13.8 to sc-8, MP.L2-3.8.9 to cp-9, and SC.L2-3.13.6 to sc-7. Each implemented requirement includes props referencing the specific Terraform resource addresses that satisfy it, and a link to the signed evidence receipt in the vault.

The profile at `oscal/profiles/cmmc-level-2/profile.json` selects the five controls from the NIST 800-53 Rev 5 catalog. Both files validate cleanly under `trestle validate`. The trestle validation output is captured at `evidence/trestle-validate.txt`.

---

## Design Trade-offs


The conftest policies for TLS and KMS use structural checks against `input.configuration` rather than value checks against `input.resource_changes` because the relevant values are fully dynamic at plan time. This means the policies verify the presence of required resource relationships rather than the correctness of runtime values. The tfsec gate and the AWS Config rules provide the complementary runtime and post-deploy verification layers.

The least privilege enforcement relies on a split between conftest and tfsec. This is a known limitation of plan-time policy evaluation when policies use `jsonencode()` with dynamic references. The correct long-term fix is to migrate IAM policies to `aws_iam_policy_document` data sources, which are evaluated at plan time and produce readable JSON in `planned_values`. That migration is documented as a known gap.

GAP-08 is addressed at the infrastructure level with API Gateway access logging but is not enforced by a Rego policy. Adding a conftest policy for API Gateway logging would require checking `input.configuration.root_module.resources` for `aws_apigatewayv2_stage` resources missing an `access_log_settings` block. That policy is a natural extension of the current suite and is documented as a follow-on item.

---

## What Was Not Completed

GAP-06 partial: reserved concurrency was not configured. The DLQ and X-Ray tracing address the monitoring and flaw remediation requirements, but concurrency limits would add availability protection. This is a known gap.

GAP-08 partial: a Rego policy for API Gateway logging enforcement does not exist. The infrastructure remediation is in place and verified via `terraform state list`, but the policy gate does not fail a plan that omits the access log configuration.

No SSP was authored. The OSCAL layer covers the component definition and profile only. A System Security Plan would require describing the full authorization boundary, interconnections, and all system components including the baseline stack resources. That is out of scope for this submission but the component definition is structured to be importable into an SSP.

Patient data lifecycle controls (deletion, export, retention policy) are not addressed. These require organizational process controls in addition to technical enforcement and are beyond the scope of the Terraform and Rego layers.