###############################
# Kill-chain incidents table + daily aggregator (host + tactics over time)
###############################

resource "aws_dynamodb_table" "killchain_incidents" {
  name         = "${var.project_prefix}-killchain-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  tags = {
    Project = var.project_prefix
  }
}

###############################
# Daily kill-chain aggregator (host + tactics over time)
###############################

data "archive_file" "killchain_daily_aggregator_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/killchain_daily_aggregator.py"
  output_path = "${path.module}/lambda/killchain_daily_aggregator.zip"
}

resource "aws_iam_role" "killchain_daily_aggregator_lambda" {
  name = "${var.project_prefix}-killchain-daily-aggregator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "killchain_daily_aggregator_lambda" {
  name = "${var.project_prefix}-killchain-daily-aggregator-policy"
  role = aws_iam_role.killchain_daily_aggregator_lambda.id

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
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_prefix}-killchain-daily-aggregator:*"
      },
      {
        Effect = "Allow",
        Action = [
          "securityhub:GetFindings"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ],
        Resource = aws_dynamodb_table.killchain_incidents.arn
      },
      {
        Effect = "Allow",
        Action = [
          "sns:Publish"
        ],
        Resource = aws_sns_topic.killchain.arn
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "killchain_daily_aggregator_lambda" {
  name              = "/aws/lambda/${var.project_prefix}-killchain-daily-aggregator"
  retention_in_days = 7
}

resource "aws_lambda_function" "killchain_daily_aggregator" {
  function_name = "${var.project_prefix}-killchain-daily-aggregator"
  role          = aws_iam_role.killchain_daily_aggregator_lambda.arn
  handler       = "killchain_daily_aggregator.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.killchain_daily_aggregator_lambda.output_path
  source_code_hash = data.archive_file.killchain_daily_aggregator_lambda.output_base64sha256

  timeout     = 300
  memory_size = 512

  environment {
    variables = {
      PROJECT_PREFIX          = var.project_prefix
      INCIDENT_TABLE_NAME     = aws_dynamodb_table.killchain_incidents.name
      KILLCHAIN_SNS_TOPIC_ARN = aws_sns_topic.killchain.arn
      DAYS_LOOKBACK           = "30"
    }
  }

  depends_on = [aws_cloudwatch_log_group.killchain_daily_aggregator_lambda]
}

resource "aws_cloudwatch_event_rule" "killchain_daily_aggregator" {
  name                = "${var.project_prefix}-killchain-daily-aggregator"
  description         = "Daily job to aggregate Security Hub findings into kill-chain incidents by host and MITRE tactic"
  schedule_expression = "cron(0 3 * * ? *)" # 03:00 UTC daily
}

resource "aws_cloudwatch_event_target" "killchain_daily_aggregator" {
  rule      = aws_cloudwatch_event_rule.killchain_daily_aggregator.name
  target_id = "killchain-daily-aggregator"
  arn       = aws_lambda_function.killchain_daily_aggregator.arn
}

resource "aws_lambda_permission" "allow_events_killchain_daily_aggregator" {
  statement_id  = "AllowExecutionFromEventBridgeKillchainDailyAggregator"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.killchain_daily_aggregator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.killchain_daily_aggregator.arn
}
