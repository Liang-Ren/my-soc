###############################
# Semi-automatic triage helper
# Security Hub HIGH/CRITICAL findings -> Lambda -> SNS email
###############################

data "archive_file" "triage_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/triage_links_handler.py"
  output_path = "${path.module}/lambda/triage_links_handler.zip"
}

resource "aws_cloudwatch_log_group" "triage_lambda" {
  name              = "/aws/lambda/${var.project_prefix}-triage-links"
  retention_in_days = 7
}

resource "aws_iam_role" "triage_lambda" {
  name = "${var.project_prefix}-triage-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "lambda.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "triage_lambda" {
  name = "${var.project_prefix}-triage-lambda-policy"
  role = aws_iam_role.triage_lambda.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_prefix}-triage-links:*"
      },
      {
        Effect   = "Allow",
        Action   = ["sns:Publish"],
        Resource = aws_sns_topic.triage.arn
      }
    ]
  })
}

resource "aws_sns_topic" "triage" {
  name = "${var.project_prefix}-triage-topic"
}

resource "aws_sns_topic_subscription" "triage_email" {
  topic_arn = aws_sns_topic.triage.arn
  protocol  = "email"
  endpoint  = "liang.ren@live.ca"
}

resource "aws_lambda_function" "triage_links" {
  function_name = "${var.project_prefix}-triage-links"
  role          = aws_iam_role.triage_lambda.arn
  handler       = "triage_links_handler.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.triage_lambda.output_path
  source_code_hash = data.archive_file.triage_lambda.output_base64sha256

  timeout     = 10
  memory_size = 128

  environment {
    variables = {
      TRIAGE_SNS_TOPIC_ARN = aws_sns_topic.triage.arn
      PROJECT_PREFIX       = var.project_prefix
      IAM_ROLLBACK_API_ID  = aws_apigatewayv2_api.iam_rollback_api.id
    }
  }

  depends_on = [aws_cloudwatch_log_group.triage_lambda]
}

# Allow EventBridge Security Hub rule to invoke the triage Lambda
resource "aws_lambda_permission" "triage_allow_events" {
  statement_id  = "AllowExecutionFromEventBridgeSecurityHubHigh"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage_links.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_high.arn
}

# Add Lambda as an additional target on the existing Security Hub HIGH/CRITICAL rule
resource "aws_cloudwatch_event_target" "securityhub_to_triage_lambda" {
  rule      = aws_cloudwatch_event_rule.securityhub_high.name
  target_id = "triage-lambda"
  arn       = aws_lambda_function.triage_links.arn
}

###############################
# ML auto-triage helper
# All Security Hub imported findings -> Lambda -> SageMaker endpoint
###############################

data "archive_file" "ml_auto_triage_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/ml_auto_triage.py"
  output_path = "${path.module}/lambda/ml_auto_triage.zip"
}

resource "aws_cloudwatch_event_rule" "securityhub_all_for_ml" {
  name        = "${var.project_prefix}-securityhub-all-findings-ml"
  description = "Send all Security Hub imported findings to ML auto-triage Lambda"

  event_pattern = <<EOF
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"]
}
EOF
}

resource "aws_cloudwatch_log_group" "ml_auto_triage_lambda" {
  name              = "/aws/lambda/${var.project_prefix}-ml-auto-triage"
  retention_in_days = 7
}

resource "aws_iam_role" "ml_auto_triage_lambda" {
  name = "${var.project_prefix}-ml-auto-triage-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "lambda.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ml_auto_triage_lambda" {
  name = "${var.project_prefix}-ml-auto-triage-policy"
  role = aws_iam_role.ml_auto_triage_lambda.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_prefix}-ml-auto-triage:*"
      },
      {
        Effect = "Allow",
        Action = [
          "sagemaker:InvokeEndpoint"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "securityhub:BatchUpdateFindings"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "ml_auto_triage" {
  function_name = "${var.project_prefix}-ml-auto-triage"
  role          = aws_iam_role.ml_auto_triage_lambda.arn
  handler       = "ml_auto_triage.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.ml_auto_triage_lambda.output_path
  source_code_hash = data.archive_file.ml_auto_triage_lambda.output_base64sha256

  timeout     = 20
  memory_size = 256

  environment {
    variables = {
      PROJECT_PREFIX        = var.project_prefix
      SAGEMAKER_ENDPOINT_NAME = var.sagemaker_endpoint_name
    }
  }

  depends_on = [aws_cloudwatch_log_group.ml_auto_triage_lambda]
}

resource "aws_lambda_permission" "ml_auto_triage_allow_events" {
  statement_id  = "AllowExecutionFromEventBridgeSecurityHubHighMLAutoTriage"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ml_auto_triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_all_for_ml.arn
}

resource "aws_cloudwatch_event_target" "securityhub_to_ml_auto_triage" {
  rule      = aws_cloudwatch_event_rule.securityhub_all_for_ml.name
  target_id = "ml-auto-triage"
  arn       = aws_lambda_function.ml_auto_triage.arn
}
