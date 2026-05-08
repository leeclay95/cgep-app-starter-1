package vpc
import rego.v1

metadata_vpc := {
    "framework": "CMMC-L2",
    "control_id": "SC.L2-3.13.1",
    "severity": "HIGH",
    "remediation": "Add a vpc_config block to the Lambda function referencing private subnets."
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_lambda_function"
    not has_vpc_config(resource)
    msg := sprintf("CMMC Violation [%s]: Lambda '%s' must be deployed within a VPC.", [metadata_vpc.control_id, resource.address])
}

has_vpc_config(res) if {
    count(res.change.after.vpc_config) > 0
}