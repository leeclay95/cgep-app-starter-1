package kms

import rego.v1
import data.kms.deny

test_deny_unencrypted_s3 if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_s3_bucket.bad",
            "type": "aws_s3_bucket",
            "expressions": {}
        }
    ]}}}
    count(deny) > 0 with input as mock_input
}

test_allow_s3_kms if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_s3_bucket.good",
            "type": "aws_s3_bucket",
            "expressions": {}
        },
        {
            "address": "aws_s3_bucket_server_side_encryption_configuration.good_kms",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "expressions": {
                "bucket": {"references": ["aws_s3_bucket.good.id", "aws_s3_bucket.good"]},
                "rule": [{"apply_server_side_encryption_by_default": [
                    {"sse_algorithm": {"constant_value": "aws:kms"}}
                ]}]
            }
        }
    ]}}}
    count(deny) == 0 with input as mock_input
}

test_allow_dynamodb_kms if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_dynamodb_table.good",
            "type": "aws_dynamodb_table",
            "expressions": {
                "server_side_encryption": [{"enabled": {"constant_value": true}}]
            }
        }
    ]}}}
    count(deny) == 0 with input as mock_input
}

test_deny_dynamodb_no_kms if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_dynamodb_table.bad",
            "type": "aws_dynamodb_table",
            "expressions": {}
        }
    ]}}}
    count(deny) > 0 with input as mock_input
}