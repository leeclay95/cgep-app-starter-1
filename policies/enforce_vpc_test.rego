package vpc
import rego.v1

test_deny_no_vpc if {
    mock := {"resource_changes": [{"type": "aws_lambda_function", "address": "aws_lambda.bad", "change": {"after": {"vpc_config": []}}}]}
    res := data.vpc.deny with input as mock
    count(res) > 0
}

test_allow_vpc if {
    mock := {"resource_changes": [{"type": "aws_lambda_function", "address": "aws_lambda.good", "change": {"after": {"vpc_config": [{"subnet_ids": ["subnet-123"]}]}}}]}
    res := data.vpc.deny with input as mock
    count(res) == 0
}
