package main
import rego.v1

metadata_tls := {
    "framework": "CMMC-L2",
    "control_id": "SC.L2-3.13.8",
    "severity": "MEDIUM",
}

deny contains msg if {
    some bucket in input.resource_changes
    bucket.type == "aws_s3_bucket"
    not has_policy_for(bucket.address)
    msg := sprintf("CMMC Violation [%s]: S3 bucket '%s' is missing a TLS-enforcement policy.",
        [metadata_tls.control_id, bucket.address])
}


bucket_name(bucket_addr) := name if {
    some r in input.resource_changes
    r.address == bucket_addr
    name := r.change.after.bucket
}

has_policy_for(bucket_addr) if {
    planned_name := bucket_name(bucket_addr)

    some p in input.resource_changes
    p.type == "aws_s3_bucket_policy"
    p.change.after != null

    
    p.change.after.bucket == planned_name

    contains(p.change.after.policy, "aws:SecureTransport")
    contains(p.change.after.policy, "false")
}