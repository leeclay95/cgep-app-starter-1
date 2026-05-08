package least_privilege
import rego.v1

deny contains msg if {
    some p in input.resource_changes
    p.type == "aws_iam_role_policy"
    policy_doc := json.unmarshal(p.change.after.policy)
    some statement in policy_doc.Statement
    
    # Check if the Action contains a wildcard
    has_wildcard(statement.Action)
    
    msg := sprintf("CMMC Violation: IAM policy contains forbidden wildcard actions.", [])
}

# Rule 1: Handle single string actions (Exact *)
has_wildcard(action) if {
    is_string(action)
    action == "*"
}

# Rule 1b: Handle single string actions (Prefix :*)
has_wildcard(action) if {
    is_string(action)
    endswith(action, ":*")
}

# Rule 2: Handle arrays (Exact *)
has_wildcard(action) if {
    is_array(action)
    some a in action
    a == "*"
}

# Rule 2b: Handle arrays (Prefix :*)
has_wildcard(action) if {
    is_array(action)
    some a in action
    endswith(a, ":*")
}
