package vpc

import rego.v1

deny contains msg if {
    some res in input.configuration.root_module.resources
    res.type == "aws_lambda_function"
    not contains(sprintf("%v", [res.expressions.vpc_config]), "subnet_ids")
    msg := sprintf("CMMC Violation: Lambda %v must be associated with a VPC", [res.address])
}