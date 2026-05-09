# METADATA
# title: SC.L2-3.13.6 — Lambda VPC placement for network segmentation
# custom:
#   framework: CMMC-L2
#   controls:
#     - "SC.L2-3.13.6"
#   severity: high
#   remediation: "Add a vpc_config block to aws_lambda_function referencing private subnets and a security group."
package vpc

import rego.v1

deny contains msg if {
    some res in input.configuration.root_module.resources
    res.type == "aws_lambda_function"
    not contains(sprintf("%v", [res.expressions.vpc_config]), "subnet_ids")
    msg := sprintf("CMMC Violation: Lambda %v must be associated with a VPC", [res.address])
}
