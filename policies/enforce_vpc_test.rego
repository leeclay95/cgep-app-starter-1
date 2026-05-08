package main
import rego.v1

# VPC Isolation Tests (SC.L2-3.13.1)
test_deny_lambda_no_vpc if {
    mock_input := {"resource_changes": [{"type": "aws_lambda_function", "address": "aws_lambda_function.bad", "change": {"after": {"vpc_config": []}}}]}
    res := deny with input as mock_input
    count(res) > 0
}

test_allow_lambda_with_vpc if {
    mock_input := {"resource_changes": [{"type": "aws_lambda_function", "address": "aws_lambda_function.good", "change": {"after": {"vpc_config": [{"subnet_ids": ["subnet-123"]}]}}}]}
    res := deny with input as mock_input
    count(res) == 0
}

# TLS Enforcement Tests (SC.L2-3.13.8)
test_deny_s3_no_tls if {
    mock_input := {"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.bad", "name": "bad-bucket"}]}
    res := deny with input as mock_input
    count(res) > 0
}

# Least Privilege Tests (AC.L2-3.1.5)
test_deny_iam_wildcard if {
    mock_input := {"resource_changes": [{
        "type": "aws_iam_role_policy",
        "address": "aws_iam_role_policy.bad",
        "change": {"after": {"policy": "{\"Statement\": [{\"Action\": \"s3:*\", \"Effect\": \"Allow\"}]}"}}
    }]}
    res := deny with input as mock_input
    count(res) > 0
}