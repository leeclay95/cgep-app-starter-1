package main

import rego.v1

test_deny_s3_no_policy if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "name": "uploads"},
    ]}
    res := deny with input as mock
    count(res) > 0
}

test_deny_s3_policy_missing_secure_transport if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "name": "uploads"},
        {"type": "aws_s3_bucket_policy", "change": {"after": {
            "policy": "{\"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"s3:GetObject\"}]}",
        }}},
    ]}
    res := deny with input as mock
    count(res) > 0
}

test_allow_s3_tls_enforced if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads", "name": "uploads"},
        {"type": "aws_s3_bucket_policy", "change": {"after": {
            "policy": "{\"Statement\": [{\"Effect\": \"Deny\", \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}]}",
        }}},
        {"type": "aws_s3_bucket_server_side_encryption_configuration", "change": {"after": {
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        }}},
        {"type": "aws_s3_bucket_versioning", "change": {"after": {
            "versioning_configuration": [{"status": "Enabled"}],
        }}},
    ]}
    res := deny with input as mock
    count(res) == 0
}
