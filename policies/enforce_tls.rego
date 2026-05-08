package main

import rego.v1

metadata_tls := {
    "framework":   "CMMC-L2",
    "control_id":  "SC.L2-3.13.8",
    "severity":    "MEDIUM",
    "remediation": "Attach an aws_s3_bucket_policy that denies s3:* when aws:SecureTransport is false.",
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    not has_tls_enforcement
    msg := sprintf(
        "CMMC Violation [%s]: S3 bucket '%s' is missing a TLS-enforcement policy.",
        [metadata_tls.control_id, resource.address],
    )
}

has_tls_enforcement if {
    some p in input.resource_changes
    p.type == "aws_s3_bucket_policy"
    contains(p.change.after.policy, "aws:SecureTransport")
    contains(p.change.after.policy, "false")
}
