variable "bucket_name" {
  description = "S3 bucket name for CodeShield frontend"
  type        = string
  default     = "faiez-codeshield"
}

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-2"
}