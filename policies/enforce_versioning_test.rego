package versioning
import rego.v1

test_deny_no_versioning if {
    mock := {"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.bad"}]}
    res := data.versioning.deny with input as mock
    count(res) > 0
}

test_allow_versioning if {
    mock := {"resource_changes": [
        {"type": "aws_s3_bucket", "address": "aws_s3_bucket.good"},
        {"type": "aws_s3_bucket_versioning", "change": {"after": {"versioning_configuration": [{"status": "Enabled"}]}}}
    ]}
    res := data.versioning.deny with input as mock
    count(res) == 0
}
