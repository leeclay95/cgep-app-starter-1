package least_privilege

import rego.v1
import data.least_privilege.deny

test_deny_wildcard_string if {
    mock_input := {"resource_changes": [
        {
            "address": "aws_iam_role_policy.violation",
            "type": "aws_iam_role_policy",
            "change": {"after": {"policy": "{\"Action\": \"*\"}"}}
        }
    ]}
    count(deny) > 0 with input as mock_input
}

test_deny_wildcard_array if {
    mock_input := {"resource_changes": [
        {
            "address": "aws_iam_role_policy.violation_array",
            "type": "aws_iam_role_policy",
            "change": {"after": {"policy": "{\"Action\": [\"s3:GetObject\", \"*\"]}"}}
        }
    ]}
    count(deny) > 0 with input as mock_input
}

test_deny_service_wildcard if {
    mock_input := {"resource_changes": [
        {
            "address": "aws_iam_role_policy.violation_svc",
            "type": "aws_iam_role_policy",
            "change": {"after": {"policy": "{\"Action\": [\"dynamodb:*\"]}"}}
        }
    ]}
    count(deny) > 0 with input as mock_input
}

test_allow_scoped_actions if {
    mock_input := {"resource_changes": [
        {
            "address": "aws_iam_role_policy.compliant",
            "type": "aws_iam_role_policy",
            "change": {"after": {"policy": "{\"Action\": [\"dynamodb:PutItem\", \"dynamodb:DescribeTable\"]}"}}
        }
    ]}
    count(deny) == 0 with input as mock_input
}