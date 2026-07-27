resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}


data "aws_iam_policy_document" "github_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:Faiez03@*/CodeShield-infra@*:*"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name               = "github-actions-codeshield-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_trust.json
}


resource "aws_iam_role_policy" "deploy_perms" {
  name = "codeshield-deploy-policy"
  role = aws_iam_role.github_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # --- Frontend + tfstate S3 buckets: full lifecycle ---
      {
        Sid    = "S3BucketLifecycle"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket", "s3:DeleteBucket",
          "s3:GetBucketAcl", "s3:PutBucketAcl",
          "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
          "s3:GetBucketVersioning", "s3:GetBucketLocation", "s3:GetBucketTagging",
          "s3:GetBucketCORS", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration",
          "s3:GetBucketWebsite", "s3:GetAccelerateConfiguration", "s3:GetBucketLogging",
          "s3:GetReplicationConfiguration", "s3:GetBucketRequestPayment",
          "s3:GetBucketObjectLockConfiguration", "s3:GetBucketNotification",
          "s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock"
        ]
        Resource = [
          "arn:aws:s3:::${var.bucket_name}",
          "arn:aws:s3:::faiez-codeshield-tfstate"
        ]
      },
      # --- Objects inside both buckets ---
      {
        Sid    = "S3ObjectLifecycle"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.bucket_name}/*",
          "arn:aws:s3:::faiez-codeshield-tfstate/*"
        ]
      },
      # --- CloudFront: distribution + OAC + cache invalidation ---
      {
        Sid    = "CloudFrontManagement"
        Effect = "Allow"
        Action = [
          "cloudfront:GetDistribution", "cloudfront:CreateDistribution",
          "cloudfront:UpdateDistribution", "cloudfront:DeleteDistribution",
          "cloudfront:ListDistributions", "cloudfront:CreateInvalidation",
          "cloudfront:GetOriginAccessControl", "cloudfront:CreateOriginAccessControl",
          "cloudfront:UpdateOriginAccessControl", "cloudfront:DeleteOriginAccessControl",
          "cloudfront:TagResource"
        ]
        Resource = "*"
      },
      # --- OIDC trust provider ---
      {
        Sid    = "OIDCProviderManagement"
        Effect = "Allow"
        Action = [
          "iam:GetOpenIDConnectProvider", "iam:CreateOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProviderThumbprint", "iam:DeleteOpenIDConnectProvider"
        ]
        Resource = aws_iam_openid_connect_provider.github.arn
      },
      # --- The role + its own inline policy ---
      {
        Sid    = "SelfRoleManagement"
        Effect = "Allow"
        Action = [
          "iam:GetRole", "iam:CreateRole", "iam:UpdateRole", "iam:DeleteRole", "iam:TagRole",
          "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
          "iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy"
        ]
        Resource = aws_iam_openid_connect_provider.github.arn
      }
    ]
  })
}

output "github_role_arn" {
  value = aws_iam_role.github_deploy.arn
}

output "cloudfront_distribution_id" { 
  value = aws_cloudfront_distribution.frontend.id
}