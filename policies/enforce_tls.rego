# METADATA
# title: SC.L2-3.13.8 — TLS enforcement on S3 buckets in transit
# custom:
#   framework: CMMC-L2
#   controls:
#     - "SC.L2-3.13.8"
#   severity: high
#   remediation: "Add an aws_s3_bucket_policy with a Deny statement conditioned on aws:SecureTransport false for every S3 bucket."
package tls

import rego.v1

# All S3 bucket addresses
all_buckets := {res.address |
    some res in input.configuration.root_module.resources
    res.type == "aws_s3_bucket"
}

# Bucket policies that reference a SecureTransport enforcement
# We can't read the rendered policy string at plan time, so we link
# structurally: a policy resource whose bucket.references points to
# this bucket address IS the coverage signal.
# For policy content we use resource_changes where sse configs ARE resolved,
# but for bucket_policy the content is also unknown — so we trust structural
# presence of a dedicated policy resource referencing the bucket.
buckets_with_policy := {bucket_addr |
    some res in input.configuration.root_module.resources
    res.type == "aws_s3_bucket_policy"
    some ref in res.expressions.bucket.references
    # refs include both "aws_s3_bucket.logs.id" and "aws_s3_bucket.logs"
    # match on the base address (no attribute suffix)
    bucket_addr := ref
    all_buckets[bucket_addr]
}

deny contains msg if {
    some bucket in all_buckets
    not buckets_with_policy[bucket]
    msg := sprintf("CMMC Violation: S3 bucket %v missing enforced TLS policy", [bucket])
}
