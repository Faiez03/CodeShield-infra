resource "aws_s3_bucket" "frontend" {
  bucket = var.bucket_name
}


resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.frontend.id
  key          = "index.html"
  source       = "../index.html"
  etag         = filemd5("../index.html")
  content_type = "text/html"
}

resource "aws_s3_object" "css" {
  bucket       = aws_s3_bucket.frontend.id
  key          = "index.css"
  source       = "../index.css"
  etag         = filemd5("../index.css")
  content_type = "text/css"
}

resource "aws_s3_object" "main" {
  bucket       = aws_s3_bucket.frontend.id
  key          = "main.js"
  source       = "../main.js"
  etag         = filemd5("../main.js")
  content_type = "application/javascript"
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = data.aws_iam_policy_document.frontend_oac.json
}
