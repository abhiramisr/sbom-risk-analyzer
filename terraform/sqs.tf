# =============================================================================
# SQS + DLQ Configuration (Disabled - Enable for production resilience)
# =============================================================================
# 
# This configuration adds:
# - Main processing queue with long polling
# - Dead Letter Queue (DLQ) for failed messages after 3 retries
# - S3 → SQS → Lambda flow (instead of S3 → Lambda direct)
#
# Benefits:
# - Messages persist if Lambda fails
# - Automatic retry with backoff
# - Failed messages preserved in DLQ for debugging
# - Better handling of traffic spikes
#
# To enable: Uncomment all resources below and update s3.tf notification
# =============================================================================

# # Dead Letter Queue - failed messages go here
# resource "aws_sqs_queue" "dlq" {
#   name                      = "sbom-analyzer-dlq-${var.environment}"
#   message_retention_seconds = 1209600  # 14 days
#   
#   tags = {
#     Project     = var.project_name
#     Environment = var.environment
#   }
# }

# # Main processing queue
# resource "aws_sqs_queue" "processing" {
#   name                       = "sbom-analyzer-queue-${var.environment}"
#   visibility_timeout_seconds = 900  # 15 min (6x Lambda timeout)
#   message_retention_seconds  = 86400  # 1 day
#   receive_wait_time_seconds  = 20  # Long polling
#   
#   redrive_policy = jsonencode({
#     deadLetterTargetArn = aws_sqs_queue.dlq.arn
#     maxReceiveCount     = 3  # Send to DLQ after 3 failures
#   })
#   
#   tags = {
#     Project     = var.project_name
#     Environment = var.environment
#   }
# }

# # Allow S3 to send messages to SQS
# resource "aws_sqs_queue_policy" "s3_to_sqs" {
#   queue_url = aws_sqs_queue.processing.id
#   
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect    = "Allow"
#         Principal = { Service = "s3.amazonaws.com" }
#         Action    = "sqs:SendMessage"
#         Resource  = aws_sqs_queue.processing.arn
#         Condition = {
#           ArnLike = {
#             "aws:SourceArn" = aws_s3_bucket.input.arn
#           }
#         }
#       }
#     ]
#   })
# }

# # Lambda triggered by SQS
# resource "aws_lambda_event_source_mapping" "sqs_trigger" {
#   event_source_arn                   = aws_sqs_queue.processing.arn
#   function_name                      = aws_lambda_function.processor.arn
#   batch_size                         = 1
#   maximum_batching_window_in_seconds = 0
#   
#   depends_on = [aws_iam_role_policy.lambda_sqs]
# }

