# IAM role that Lambda assumes when running
resource "aws_iam_role" "lambda_execution" {
  name = "${var.project_name}-lambda-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# Policy: Read from input bucket
resource "aws_iam_role_policy" "lambda_s3_read" {
  name = "s3-read-input"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.input.arn}/*"
      }
    ]
  })
}

# Policy: Write to output bucket
resource "aws_iam_role_policy" "lambda_s3_write" {
  name = "s3-write-output"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.output.arn}/*"
      }
    ]
  })
}

# Policy: Use KMS key for encryption/decryption
resource "aws_iam_role_policy" "lambda_kms" {
  name = "kms-access"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.sbom_encryption.arn
      }
    ]
  })
}

# Policy: Write CloudWatch logs
resource "aws_iam_role_policy" "lambda_logs" {
  name = "cloudwatch-logs"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
      }
    ]
  })
}

# Policy: Invoke Bedrock model
resource "aws_iam_role_policy" "lambda_bedrock" {
  name = "bedrock-invoke"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "arn:aws:bedrock:*::foundation-model/anthropic.*"
      },
      {
        Effect   = "Allow"
        Action   = "bedrock:ApplyGuardrail"
        Resource = "arn:aws:bedrock:us-east-1:${data.aws_caller_identity.current.account_id}:guardrail/*"
      }
    ]
  })
}

# Policy: AWS Marketplace permissions for Bedrock models
resource "aws_iam_role_policy" "lambda_marketplace" {
  name = "marketplace-access"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "aws-marketplace:ViewSubscriptions",
          "aws-marketplace:Subscribe"
        ]
        Resource = "*"
      }
    ]
  })
}

# Policy: SQS access for Lambda
# 
# resource "aws_iam_role_policy" "lambda_sqs" {
#   name = "sqs-access"
#   role = aws_iam_role.lambda_execution.id
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect = "Allow"
#         Action = [
#           "sqs:ReceiveMessage",
#           "sqs:DeleteMessage",
#           "sqs:GetQueueAttributes"
#         ]
#         Resource = [
#           aws_sqs_queue.processing.arn,
#           aws_sqs_queue.dlq.arn
#         ]
#       }
#     ]
#   })
# }