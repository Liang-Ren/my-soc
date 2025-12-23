###############################
# CloudWatch Agent on web servers (OS/app logs)
###############################

resource "aws_cloudwatch_log_group" "web_os" {
  name              = "/aws/${var.project_prefix}/web-os"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "web_app" {
  name              = "/aws/${var.project_prefix}/web-app"
  retention_in_days = 7
}

resource "aws_iam_role" "web_instance" {
  name = "${var.project_prefix}-web-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action   = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "web_instance_cwagent" {
  role       = aws_iam_role.web_instance.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "web_instance_ssm" {
  role       = aws_iam_role.web_instance.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "web_instance" {
  name = "${var.project_prefix}-web-instance-profile"
  role = aws_iam_role.web_instance.name
}

###############################
# Route 53 Resolver query logging
###############################

resource "aws_cloudwatch_log_group" "route53_resolver" {
  name              = "/aws/${var.project_prefix}/route53-resolver"
  retention_in_days = 7
}

resource "aws_route53_resolver_query_log_config" "vpc" {
  name            = "${var.project_prefix}-resolver-query-logs"
  destination_arn = aws_cloudwatch_log_group.route53_resolver.arn
}

resource "aws_route53_resolver_query_log_config_association" "vpc" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.vpc.id
  resource_id                  = aws_vpc.main.id
}

###############################
# Athena/Glue for log correlation
###############################

# Glue database that Athena will use for security logs (CloudTrail, Config, etc.)
resource "aws_glue_catalog_database" "security_logs" {
  name = "${var.project_prefix}_security_logs"

  description = "Glue Catalog DB for my-soc security logs (CloudTrail, Config, etc.)"
}

# Athena workgroup with results stored in the existing logs bucket
resource "aws_athena_workgroup" "my_soc" {
  name = "${var.project_prefix}-wg"

  configuration {
    enforce_workgroup_configuration = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.logs.bucket}/athena-results/"
    }
  }
}

###############################
# Glue crawler to create CloudTrail tables in my-soc_security_logs
###############################

resource "aws_iam_role" "glue_crawler" {
  name = "${var.project_prefix}-glue-crawler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action   = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "glue_crawler" {
  role       = aws_iam_role.glue_crawler.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_crawler_s3" {
  name = "${var.project_prefix}-glue-crawler-s3"
  role = aws_iam_role.glue_crawler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.logs.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/*"
      }
    ]
  })
}

resource "aws_glue_crawler" "cloudtrail" {
  name         = "${var.project_prefix}-cloudtrail-crawler"
  role         = aws_iam_role.glue_crawler.arn
  database_name = aws_glue_catalog_database.security_logs.name
  table_prefix  = "cloudtrail_"

  s3_target {
    # Crawl CloudTrail logs written by this lab's trail
    path = "s3://${aws_s3_bucket.logs.bucket}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/"
  }

  configuration = jsonencode({
    Version = 1.0
    CrawlerOutput = {
      Partitions = { AddOrUpdateBehavior = "InheritFromTable" }
    }
  })

  schedule = null # run on-demand from console when you want to refresh tables
}
