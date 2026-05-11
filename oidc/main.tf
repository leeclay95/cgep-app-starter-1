###
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

variable "github_org" {
  type    = string
  default = "leeclay95"
}
variable "github_repo" {
  type    = string
  default = "cgep-app-starter-1"
}



resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}


resource "aws_iam_role" "grc_gate" {
  name = "acme-grc-gate-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*" }
      }
    }]
  })
}

output "role_arn" { value = aws_iam_role.grc_gate.arn }


resource "aws_iam_role_policy" "grc_gate_s3_write" {
  name = "GRCGateVaultWrite"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {

        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectRetention",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = [
          "arn:aws:s3:::acme-health-evidence-vault-969958573430",
          "arn:aws:s3:::acme-health-evidence-vault-969958573430/*"
        ]
      },
      {

        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]

        Resource = "arn:aws:kms:us-east-1:969958573430:key/401bbf35-f910-4e85-9ac4-323dccde8027"
      }
    ]
  })
}
