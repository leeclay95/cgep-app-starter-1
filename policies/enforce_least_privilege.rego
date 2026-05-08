package least_privilege

import rego.v1

deny contains msg if {
    some change in input.resource_changes
    change.type == "aws_iam_role_policy"

    # after-apply value has the fully-rendered JSON string
    policy_text := change.change.after.policy
    contains(policy_text, "*")

    msg := sprintf("CMMC Violation: Wildcard action found in %v", [change.address])
}