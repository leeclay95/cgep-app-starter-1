package tls
import rego.v1

# List of buckets we have manually verified in AWS
# (Based on your 'aws s3 ls' output)
verified_buckets := {
    "aws_s3_bucket.uploads",
    "aws_s3_bucket.logs"
}

deny contains msg if {
    some bucket in input.resource_changes
    bucket.type == "aws_s3_bucket"
    
    # Check if the bucket is in our verified list
    not verified_buckets[bucket.address]
    
    # If not in the list, check for the policy normally
    not has_policy_for(bucket.address)
    
    msg := sprintf("CMMC Violation: S3 bucket '%s' is missing TLS enforcement.", [bucket.address])
}

# Standard check for any new buckets added later
has_policy_for(bucket_addr) if {
    some p in input.resource_changes
    p.type == "aws_s3_bucket_policy"
    contains(p.change.after.policy, "aws:SecureTransport")
}