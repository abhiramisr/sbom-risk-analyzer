resource "aws_kms_key" "sbom_encryption" {
  description             = "KMS key for SBOM bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_kms_alias" "sbom_encryption" {
  name          = "alias/${var.project_name}-${var.environment}"
  target_key_id = aws_kms_key.sbom_encryption.key_id
}