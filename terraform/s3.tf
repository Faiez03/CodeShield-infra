resource "aws_s3_bucket" "frontend" {
  bucket = var.bucket_name

  # Site content is owned by the deploy workflow, not Terraform, so Terraform
  # cannot know the bucket is empty at destroy time.
  force_destroy = true
}


resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = data.aws_iam_policy_document.frontend_oac.json
}
