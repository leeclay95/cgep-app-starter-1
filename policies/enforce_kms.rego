package kms

import rego.v1

# ── DynamoDB ────────────────────────────────────────────────────────────────
deny contains msg if {
    some res in input.configuration.root_module.resources
    res.type == "aws_dynamodb_table"
    not dynamodb_has_kms(res)
    msg := sprintf("CMMC Violation: DynamoDB %v must have KMS encryption enabled", [res.address])
}

dynamodb_has_kms(res) if {
    sse := res.expressions.server_side_encryption
    # constant_value path
    sse[_].enabled.constant_value == true
}

dynamodb_has_kms(res) if {
    # handles list-wrapped block: server_side_encryption is array of objects
    some block in res.expressions.server_side_encryption
    block.enabled.constant_value == true
}

# ── S3 ───────────────────────────────────────────────────────────────────────
# Use configuration: sse_algorithm has a constant_value we CAN read,
# and bucket linkage is in references.

# Set of bucket addresses that have a KMS SSE config resource pointing at them
buckets_with_kms := {bucket_addr |
    some sse_res in input.configuration.root_module.resources
    sse_res.type == "aws_s3_bucket_server_side_encryption_configuration"

    # confirm sse_algorithm is aws:kms
    some rule in sse_res.expressions.rule
    some apply in rule.apply_server_side_encryption_by_default
    apply.sse_algorithm.constant_value == "aws:kms"

    # link back to bucket via references
    some ref in sse_res.expressions.bucket.references
    some bucket_res in input.configuration.root_module.resources
    bucket_res.type == "aws_s3_bucket"
    bucket_res.address == ref
    bucket_addr := bucket_res.address
}

deny contains msg if {
    some res in input.configuration.root_module.resources
    res.type == "aws_s3_bucket"
    not buckets_with_kms[res.address]
    msg := sprintf("CMMC Violation: S3 bucket %v missing KMS encryption", [res.address])
}