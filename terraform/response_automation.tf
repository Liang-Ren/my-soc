###############################
# Response automation (playbook actions)
# - Scenario 2: IAM privilege abuse (semi-auto via approve link → API GW/Lambda stub)
# - Scenario 3: Public S3 bucket auto-remediation
# - Scenario 4: EC2 quarantine via Security Hub custom action
###############################

locals {
  quarantine_sg_name = "${var.project_prefix}-quarantine-sg"
}

###############################
# Shared: EC2 quarantine security group
###############################

resource "aws_security_group" "quarantine" {
  name        = local.quarantine_sg_name
  description = "Isolation SG for quarantined instances"
  vpc_id      = aws_vpc.main.id

  # No ingress rules = default deny all inbound

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = local.quarantine_sg_name
    Project = var.project_prefix
  }
}

###############################
# Scenario 3 – Public S3 bucket auto-remediation Lambda
###############################

data "archive_file" "s3_remediate_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/s3_public_auto_remediate.py"
  output_path = "${path.module}/lambda/s3_public_auto_remediate.zip"
}

resource "aws_iam_role" "s3_remediate_lambda" {
  name = "${var.project_prefix}-s3-remediate-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_remediate_lambda" {
  name = "${var.project_prefix}-s3-remediate-policy"
  role = aws_iam_role.s3_remediate_lambda.id

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
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_prefix}-s3-remediate:*"
      },
      {
        Effect = "Allow",
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock"
        ],
        Resource = "arn:${data.aws_partition.current.partition}:s3:::*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "s3_remediate_lambda" {
  name              = "/aws/lambda/${var.project_prefix}-s3-remediate"
  retention_in_days = 7
}

resource "aws_lambda_function" "s3_public_auto_remediate" {
  function_name = "${var.project_prefix}-s3-remediate"
  role          = aws_iam_role.s3_remediate_lambda.arn
  handler       = "s3_public_auto_remediate.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.s3_remediate_lambda.output_path
  source_code_hash = data.archive_file.s3_remediate_lambda.output_base64sha256

  timeout     = 30
  memory_size = 128

  depends_on = [aws_cloudwatch_log_group.s3_remediate_lambda]
}

# EventBridge rule: Security Hub / Config findings for public S3 buckets → auto-remediation Lambda
resource "aws_cloudwatch_event_rule" "s3_public_auto_remediate" {
  name        = "${var.project_prefix}-s3-public-auto-remediate"
  description = "Auto-remediate public S3 buckets based on Security Hub findings"

  event_pattern = jsonencode({
    "source" : ["aws.securityhub"],
    "detail-type" : ["Security Hub Findings - Imported"],
    "detail" : {
      "findings" : {
        "Resources" : {
          "Type" : ["AwsS3Bucket"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_public_auto_remediate" {
  rule      = aws_cloudwatch_event_rule.s3_public_auto_remediate.name
  target_id = "s3-public-auto-remediate"
  arn       = aws_lambda_function.s3_public_auto_remediate.arn
}

resource "aws_lambda_permission" "allow_events_s3_public_auto_remediate" {
  statement_id  = "AllowExecutionFromEventBridgeS3PublicAutoRemediate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_public_auto_remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_auto_remediate.arn
}

###############################
# Scenario 4 – EC2 quarantine via Security Hub custom action
###############################

resource "aws_securityhub_action_target" "quarantine_ec2" {
  # Security Hub action target name must be 1-20 chars; identifier must be 1-20 alphanumeric
  name        = "${var.project_prefix}-q-ec2"
  description = "Quarantine EC2 instance by moving it to isolation SG"
  identifier  = "QuarantineEC2"

  # Ensure Security Hub is enabled in this account/region before creating the custom action
  depends_on = [aws_securityhub_account.main]
}

data "archive_file" "quarantine_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/quarantine_ec2.py"
  output_path = "${path.module}/lambda/quarantine_ec2.zip"
}

resource "aws_iam_role" "quarantine_lambda" {
  name = "${var.project_prefix}-quarantine-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "quarantine_lambda" {
  name = "${var.project_prefix}-quarantine-lambda-policy"
  role = aws_iam_role.quarantine_lambda.id

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
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_prefix}-quarantine-ec2:*"
      },
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:ModifyInstanceAttribute"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "quarantine_lambda" {
  name              = "/aws/lambda/${var.project_prefix}-quarantine-ec2"
  retention_in_days = 7
}

resource "aws_lambda_function" "quarantine_ec2" {
  function_name = "${var.project_prefix}-quarantine-ec2"
  role          = aws_iam_role.quarantine_lambda.arn
  handler       = "quarantine_ec2.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.quarantine_lambda.output_path
  source_code_hash = data.archive_file.quarantine_lambda.output_base64sha256

  timeout     = 30
  memory_size = 128

  environment {
    variables = {
      QUARANTINE_SG_ID = aws_security_group.quarantine.id
    }
  }

  depends_on = [aws_cloudwatch_log_group.quarantine_lambda]
}

# EventBridge rule: Security Hub custom action "quarantine-ec2" → quarantine lambda
resource "aws_cloudwatch_event_rule" "securityhub_quarantine_ec2" {
  name        = "${var.project_prefix}-securityhub-quarantine-ec2"
  description = "Invoke quarantine EC2 lambda from Security Hub custom action"

  event_pattern = jsonencode({
    "source" : ["aws.securityhub"],
    "detail-type" : ["Security Hub Findings - Custom Action"],
    "detail" : {
      "actionName" : [aws_securityhub_action_target.quarantine_ec2.name]
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_quarantine_ec2" {
  rule      = aws_cloudwatch_event_rule.securityhub_quarantine_ec2.name
  target_id = "quarantine-ec2"
  arn       = aws_lambda_function.quarantine_ec2.arn
}

resource "aws_lambda_permission" "allow_events_quarantine_ec2" {
  statement_id  = "AllowExecutionFromEventBridgeSecurityHubQuarantineEC2"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.quarantine_ec2.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_quarantine_ec2.arn
}

###############################
# Scenario 2 – IAM privilege abuse approve-rollback plumbing (stub)
###############################

# NOTE: This is a minimal stub: API Gateway HTTP API + Lambda that will be
# invoked when the "Approve rollback" link in triage emails is clicked.
# For now it just logs the approval; IAM rollback logic can be extended later.

data "archive_file" "iam_rollback_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/iam_privilege_rollback_stub.py"
  output_path = "${path.module}/lambda/iam_privilege_rollback_stub.zip"
}

resource "aws_iam_role" "iam_rollback_lambda" {
  name = "${var.project_prefix}-iam-rollback-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "iam_rollback_lambda" {
  name = "${var.project_prefix}-iam-rollback-policy"
  role = aws_iam_role.iam_rollback_lambda.id

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
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_prefix}-iam-rollback:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "iam_rollback_lambda" {
  name              = "/aws/lambda/${var.project_prefix}-iam-rollback"
  retention_in_days = 7
}

resource "aws_lambda_function" "iam_privilege_rollback" {
  function_name = "${var.project_prefix}-iam-rollback"
  role          = aws_iam_role.iam_rollback_lambda.arn
  handler       = "iam_privilege_rollback_stub.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.iam_rollback_lambda.output_path
  source_code_hash = data.archive_file.iam_rollback_lambda.output_base64sha256

  timeout     = 15
  memory_size = 128

  depends_on = [aws_cloudwatch_log_group.iam_rollback_lambda]
}

resource "aws_apigatewayv2_api" "iam_rollback_api" {
  name          = "${var.project_prefix}-iam-rollback-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "iam_rollback_integration" {
  api_id                 = aws_apigatewayv2_api.iam_rollback_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.iam_privilege_rollback.arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "iam_rollback_route" {
  api_id    = aws_apigatewayv2_api.iam_rollback_api.id
  route_key = "GET /approve-iam-rollback"
  target    = "integrations/${aws_apigatewayv2_integration.iam_rollback_integration.id}"
}

resource "aws_apigatewayv2_stage" "iam_rollback_stage" {
  api_id      = aws_apigatewayv2_api.iam_rollback_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "allow_apigw_iam_rollback" {
  statement_id  = "AllowExecutionFromAPIGatewayIamRollback"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_privilege_rollback.function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "arn:${data.aws_partition.current.partition}:execute-api:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${aws_apigatewayv2_api.iam_rollback_api.id}/*/*/approve-iam-rollback"
}
