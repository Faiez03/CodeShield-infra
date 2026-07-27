variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-2"
}

variable "bucket_name" {
  description = "S3 bucket the app stack manages, granted to the CI role"
  type        = string
  default     = "faiez-codeshield"
}

variable "state_bucket_name" {
  description = "S3 bucket holding Terraform state for both stacks"
  type        = string
  default     = "faiez-codeshield-tfstate"
}

variable "github_repo" {
  description = "GitHub repository allowed to assume the deploy role, as owner/name"
  type        = string
  default     = "Faiez03/CodeShield-infra"
}

variable "github_repo_immutable" {
  description = "Same repository in GitHub's immutable owner@id/repo@id form"
  type        = string
  default     = "Faiez03@203034156/CodeShield-infra@1303290433"
}
