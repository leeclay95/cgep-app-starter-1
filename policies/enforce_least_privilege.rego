package main

import rego.v1

metadata_lp := {
    "framework":   "CMMC-L2",
    "control_id":  "AC.L2-3.1.5",
    "severity":    "HIGH",
    "remediation": "Replace wildcards (*) in IAM policies with specific, named actions.",
}

deny contains msg if {
    some p in input.resource_changes
    p.type == "aws_iam_role_policy"
    policy_doc := json.unmarshal(p.change.after.policy)
    some statement in policy_doc.Statement
    is_wildcard(statement.Action)
    msg := sprintf(
        "CMMC Violation [%s]: IAM policy '%s' contains forbidden wildcard actions.",
        [metadata_lp.control_id, p.address],
    )
}

is_wildcard(action) if {
    is_string(action)
    contains(action, "*")
}

is_wildcard(action) if {
    is_array(action)
    some a in action
    contains(a, "*")
}
