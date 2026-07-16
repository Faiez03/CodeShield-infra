variable "bucket_name" {
  description = "S3 bucket name for CodeShield frontend"
  type        = string
}

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-2"
}