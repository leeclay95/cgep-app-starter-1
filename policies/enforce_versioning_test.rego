package main

import rego.v1

test_deny_s3_no_versioning if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "name": "uploads"},
        {"type": "aws_s3_bucket_server_side_encryption_configuration", "change": {"after": {
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        }}},
    ]}
    res := deny with input as mock
    count(res) > 0
}

test_deny_s3_versioning_suspended if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "name": "uploads"},
        {"type": "aws_s3_bucket_versioning", "change": {"after": {
            "versioning_configuration": [{"status": "Suspended"}],
        }}},
        {"type": "aws_s3_bucket_server_side_encryption_configuration", "change": {"after": {
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        }}},
    ]}
    res := deny with input as mock
    count(res) > 0
}

test_allow_s3_versioning_enabled if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "name": "uploads"},
        {"type": "aws_s3_bucket_versioning", "change": {"after": {
            "versioning_configuration": [{"status": "Enabled"}],
        }}},
        {"type": "aws_s3_bucket_server_side_encryption_configuration", "change": {"after": {
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        }}},
        {"type": "aws_s3_bucket_policy", "change": {"after": {
            "policy": "{\"Statement\": [{\"Effect\": \"Deny\", \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}]}",
        }}},
    ]}
    res := deny with input as mock
    count(res) == 0
}
