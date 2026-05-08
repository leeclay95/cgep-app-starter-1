package main

import rego.v1

# METADATA
# framework: CMMC-L2
# control_id: SC.L2-3.13.11
# severity: CRITICAL
# remediation: Add aws_s3_bucket_server_side_encryption_configuration referencing a CMK (sse_algorithm = aws:kms).
#              Add server_side_encryption block with kms_key_arn to aws_dynamodb_table.

metadata_kms := {
	"framework":   "CMMC-L2",
	"control_id":  "SC.L2-3.13.11",
	"severity":    "CRITICAL",
	"remediation": "Resource must use aws:kms encryption with a customer-managed key.",
}

# Deny S3 buckets that have no matching SSE-KMS configuration resource.
deny contains msg if {
	some bucket in input.resource_changes
	bucket.type == "aws_s3_bucket"
	not has_s3_kms_encryption
	msg := sprintf(
		"CMMC Violation [%s]: S3 bucket '%s' must use CMK (aws:kms) encryption.",
		[metadata_kms.control_id, bucket.address],
	)
}

# Deny DynamoDB tables that do not have server_side_encryption with enabled=true.
deny contains msg if {
	some table in input.resource_changes
	table.type == "aws_dynamodb_table"
	not has_dynamodb_kms_encryption(table)
	msg := sprintf(
		"CMMC Violation [%s]: DynamoDB table '%s' must use CMK encryption (server_side_encryption.enabled = true).",
		[metadata_kms.control_id, table.address],
	)
}

# S3: a matching aws_s3_bucket_server_side_encryption_configuration exists with sse_algorithm = aws:kms.
# Does NOT check a specific ARN — the key is managed by Terraform via local.cmmc_key_arn.
has_s3_kms_encryption if {
	some enc in input.resource_changes
	enc.type == "aws_s3_bucket_server_side_encryption_configuration"
	rule := enc.change.after.rule[0]
	rule.apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"
}

# DynamoDB: server_side_encryption block present with enabled = true.
has_dynamodb_kms_encryption(table) if {
	table.change.after.server_side_encryption[0].enabled == true
}