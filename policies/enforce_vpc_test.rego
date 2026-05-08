package vpc

import rego.v1
import data.vpc.deny

test_deny_no_vpc if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_lambda_function.bad",
            "type": "aws_lambda_function",
            "expressions": {"vpc_config": {"constant_value": "{}"}}
        }
    ]}}}
    count(deny) > 0 with input as mock_input
}

test_allow_vpc if {
    mock_input := {"configuration": {"root_module": {"resources": [
        {
            "address": "aws_lambda_function.good",
            "type": "aws_lambda_function",
            "expressions": {"vpc_config": {"subnet_ids": ["subnet-123"]}}
        }
    ]}}}
    count(deny) == 0 with input as mock_input
}