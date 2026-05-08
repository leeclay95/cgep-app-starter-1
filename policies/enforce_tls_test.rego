package tls

import rego.v1
import data.tls.deny

test_deny_bucket_no_policy if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_s3_bucket.unprotected",
            "type": "aws_s3_bucket",
            "expressions": {}
        }
    ]}}}
    count(deny) > 0 with input as mock_input
}

test_allow_bucket_with_policy if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_s3_bucket.protected",
            "type": "aws_s3_bucket",
            "expressions": {}
        },
        {
            "address": "aws_s3_bucket_policy.tls",
            "type": "aws_s3_bucket_policy",
            "expressions": {
                "bucket": {"references": ["aws_s3_bucket.protected.id", "aws_s3_bucket.protected"]}
            }
        }
    ]}}}
    count(deny) == 0 with input as mock_input
}