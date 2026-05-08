package versioning

import rego.v1

metadata_ver := {
    "framework":   "CMMC-L2",
    "control_id":  "MP.L2-3.8.9",
    "severity":    "LOW",
    "remediation": "Enable an aws_s3_bucket_versioning resource for this bucket.",
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    not has_versioning
    msg := sprintf(
        "CMMC Violation [%s]: S3 bucket '%s' must have versioning enabled.",
        [metadata_ver.control_id, resource.address],
    )
}

has_versioning if {
    some v in input.resource_changes
    v.type == "aws_s3_bucket_versioning"
    v.change.after.versioning_configuration[0].status == "Enabled"
}
