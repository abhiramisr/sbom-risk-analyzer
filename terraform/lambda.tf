# Zip the Lambda code for deployment
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  excludes    = ["test-sbom.json", "handler.zip"]
  output_path = "${path.module}/../lambda/handler.zip"
}

# Lambda function
resource "aws_lambda_function" "sbom_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-processor-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "handler.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      OUTPUT_BUCKET = aws_s3_bucket.output.id
      LOG_LEVEL     = "INFO"
    }
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# Allow S3 to invoke Lambda
resource "aws_lambda_permission" "s3_trigger" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sbom_processor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.input.arn
}

# S3 event trigger - runs Lambda when file uploaded
resource "aws_s3_bucket_notification" "sbom_upload" {
  bucket = aws_s3_bucket.input.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.sbom_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.s3_trigger]
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.sbom_processor.function_name}"
  retention_in_days = 14

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}