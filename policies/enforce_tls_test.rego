package tls
import rego.v1

test_deny_s3_no_policy if {
    mock := {"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads"}]}
    res := data.tls.deny with input as mock
    count(res) > 0
}

test_allow_s3_tls_enforced if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.uploads"},
        {"type": "aws_s3_bucket_policy", "change": {"after": {"bucket": "aws_s3_bucket.uploads", "policy": "{\"Statement\": [{\"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}]}"}}}
    ]}
    res := data.tls.deny with input as mock
    count(res) == 0
}
