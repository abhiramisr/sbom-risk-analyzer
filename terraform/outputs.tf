output "input_bucket_name" {
  description = "Name of the SBOM input bucket"
  value       = aws_s3_bucket.input.id
}

output "output_bucket_name" {
  description = "Name of the report output bucket"
  value       = aws_s3_bucket.output.id
}

output "kms_key_arn" {
  description = "ARN of the KMS encryption key"
  value       = aws_kms_key.sbom_encryption.arn
}