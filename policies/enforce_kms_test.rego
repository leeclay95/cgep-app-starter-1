package main

import rego.v1

# Negative: S3 bucket with no SSE config at all → deny fires.
test_deny_unencrypted_bucket if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.bad_bucket"},
    ]}
    res := deny with input as mock
    count(res) > 0
}

# Negative: S3 bucket with AES256 (not KMS) → deny fires.
test_deny_s3_sse_s3_not_kms if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.weak_bucket"},
        {"type": "aws_s3_bucket_server_side_encryption_configuration", "change": {"after": {
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
        }}},
    ]}
    res := deny with input as mock
    count(res) > 0
}

# Positive: S3 bucket fully compliant (all policies satisfied) → no deny.
# Must include SSE-KMS, versioning, TLS policy to satisfy all deny rules in package main.
test_allow_s3_kms_encrypted if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.good_bucket"},
        {"type": "aws_s3_bucket_server_side_encryption_configuration", "change": {"after": {
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        }}},
        {"type": "aws_s3_bucket_versioning", "change": {"after": {
            "versioning_configuration": [{"status": "Enabled"}],
        }}},
        {"type": "aws_s3_bucket_policy", "change": {"after": {
            "policy": "{\"Statement\": [{\"Effect\": \"Deny\", \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}]}",
        }}},
    ]}
    res := deny with input as mock
    count(res) == 0
}

# Negative: DynamoDB with no server_side_encryption → deny fires.
test_deny_dynamodb_no_encryption if {
    mock := {"resource_changes": [
        {"type": "aws_dynamodb_table", "address": "aws_dynamodb_table.bad",
            "change": {"after": {"server_side_encryption": []}}},
    ]}
    res := deny with input as mock
    count(res) > 0
}

# Negative: DynamoDB with SSE disabled → deny fires.
test_deny_dynamodb_sse_disabled if {
    mock := {"resource_changes": [
        {"type": "aws_dynamodb_table", "address": "aws_dynamodb_table.bad",
            "change": {"after": {"server_side_encryption": [{"enabled": false, "kms_key_arn": null}]}}},
    ]}
    res := deny with input as mock
    count(res) > 0
}

# Positive: DynamoDB with SSE enabled → no deny.
test_allow_dynamodb_kms_encrypted if {
    mock := {"resource_changes": [
        {"type": "aws_dynamodb_table", "address": "aws_dynamodb_table.good",
            "change": {"after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/test"}]}}},
    ]}
    res := deny with input as mock
    count(res) == 0
}

# Positive: Full compliant plan — all resource types present and correct → zero denies.
test_allow_full_compliant_plan if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads"},
        {"type": "aws_s3_bucket_server_side_encryption_configuration", "change": {"after": {
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        }}},
        {"type": "aws_s3_bucket_versioning", "change": {"after": {
            "versioning_configuration": [{"status": "Enabled"}],
        }}},
        {"type": "aws_s3_bucket_policy", "change": {"after": {
            "policy": "{\"Statement\": [{\"Effect\": \"Deny\", \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}]}",
        }}},
        {"type": "aws_dynamodb_table", "address": "aws_dynamodb_table.intake",
            "change": {"after": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/test"}]}}},
        {"type": "aws_lambda_function", "address": "aws_lambda_function.intake",
            "change": {"after": {"vpc_config": [{"subnet_ids": ["subnet-111"]}]}}},
        {"type": "aws_iam_role_policy", "address": "aws_iam_role_policy.lambda_inline",
            "change": {"after": {"policy": "{\"Statement\": [{\"Action\": [\"dynamodb:PutItem\", \"s3:PutObject\"], \"Effect\": \"Allow\"}]}"}}},
    ]}
    res := deny with input as mock
    count(res) == 0
}
