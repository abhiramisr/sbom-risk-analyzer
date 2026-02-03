# Input bucket - where SBOMs are uploaded
resource "aws_s3_bucket" "input" {
  bucket = "${var.project_name}-input-${data.aws_caller_identity.current.account_id}"

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "SBOM input"
  }
}

# Output bucket - where reports are written
resource "aws_s3_bucket" "output" {
  bucket = "${var.project_name}-output-${data.aws_caller_identity.current.account_id}"

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "Risk reports"
  }
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# Block all public access - input bucket
resource "aws_s3_bucket_public_access_block" "input" {
  bucket = aws_s3_bucket.input.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Block all public access - output bucket
resource "aws_s3_bucket_public_access_block" "output" {
  bucket = aws_s3_bucket.output.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning - input bucket
resource "aws_s3_bucket_versioning" "input" {
  bucket = aws_s3_bucket.input.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable versioning - output bucket
resource "aws_s3_bucket_versioning" "output" {
  bucket = aws_s3_bucket.output.id

  versioning_configuration {
    status = "Enabled"
  }
}

# KMS encryption - input bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "input" {
  bucket = aws_s3_bucket.input.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.sbom_encryption.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# KMS encryption - output bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "output" {
  bucket = aws_s3_bucket.output.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.sbom_encryption.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Enforce TLS - input bucket
resource "aws_s3_bucket_policy" "input_tls" {
  bucket = aws_s3_bucket.input.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.input.arn,
          "${aws_s3_bucket.input.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# Enforce TLS - output bucket
resource "aws_s3_bucket_policy" "output_tls" {
  bucket = aws_s3_bucket.output.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.output.arn,
          "${aws_s3_bucket.output.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}