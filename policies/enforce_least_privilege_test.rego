package main

import rego.v1

test_deny_wildcard_string if {
    mock := {"resource_changes": [{
        "type": "aws_iam_role_policy",
        "address": "aws_iam_role_policy.bad",
        "change": {"after": {"policy": "{\"Statement\": [{\"Action\": \"s3:*\", \"Effect\": \"Allow\"}]}"}},
    }]}
    res := deny with input as mock
    count(res) > 0
}

test_deny_wildcard_array if {
    mock := {"resource_changes": [{
        "type": "aws_iam_role_policy",
        "address": "aws_iam_role_policy.bad",
        "change": {"after": {"policy": "{\"Statement\": [{\"Action\": [\"dynamodb:*\"], \"Effect\": \"Allow\"}]}"}},
    }]}
    res := deny with input as mock
    count(res) > 0
}

test_deny_bare_wildcard if {
    mock := {"resource_changes": [{
        "type": "aws_iam_role_policy",
        "address": "aws_iam_role_policy.bad",
        "change": {"after": {"policy": "{\"Statement\": [{\"Action\": \"*\", \"Effect\": \"Allow\"}]}"}},
    }]}
    res := deny with input as mock
    count(res) > 0
}

test_allow_scoped_actions if {
    mock := {"resource_changes": [{
        "type": "aws_iam_role_policy",
        "address": "aws_iam_role_policy.lambda_inline",
        "change": {"after": {"policy": "{\"Statement\": [{\"Action\": [\"dynamodb:PutItem\", \"dynamodb:DescribeTable\", \"s3:PutObject\", \"kms:GenerateDataKey\"], \"Effect\": \"Allow\"}]}"}},
    }]}
    res := deny with input as mock
    count(res) == 0
}
