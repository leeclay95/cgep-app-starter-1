package kms
import rego.v1

test_deny_unencrypted_bucket if {
    mock := {"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.bad"}]}
    res := data.kms.deny with input as mock
    count(res) > 0
}

test_allow_dynamodb_kms if {
    mock := {"resource_changes": [{"type": "aws_dynamodb_table", "address": "aws_dynamodb_table.good", "change": {"after": {"server_side_encryption": [{"enabled": true}]}}}]}
    res := data.kms.deny with input as mock
    count(res) == 0
}
