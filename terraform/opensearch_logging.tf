###############################
# OpenSearch domain for log search/visualization
###############################

resource "aws_opensearch_domain" "logs" {
  domain_name    = "${var.project_prefix}-logs-os"
  engine_version = "OpenSearch_2.7"

  cluster_config {
    instance_type          = "t3.small.search"
    instance_count         = 1
    zone_awareness_enabled = false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 20
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "es:*"
        Resource = "arn:${data.aws_partition.current.partition}:es:${var.aws_region}:${data.aws_caller_identity.current.account_id}:domain/*"
      }
    ]
  })

  tags = {
    Name    = "${var.project_prefix}-opensearch"
    Project = var.project_prefix
  }
}

###############################
# Firehose: CloudWatch Logs -> OpenSearch
###############################

resource "aws_iam_role" "firehose_to_opensearch" {
  name = "${var.project_prefix}-firehose-to-os-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "firehose_to_opensearch" {
  name = "${var.project_prefix}-firehose-to-os-policy"
  role = aws_iam_role.firehose_to_opensearch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "es:DescribeDomain",
          "es:DescribeDomains",
          "es:DescribeDomainConfig",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = [
          aws_opensearch_domain.logs.arn,
          "${aws_opensearch_domain.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "cloudwatch_to_opensearch" {
  name        = "${var.project_prefix}-cw-to-os"
  destination = "opensearch"

  opensearch_configuration {
    domain_arn = aws_opensearch_domain.logs.arn
    role_arn   = aws_iam_role.firehose_to_opensearch.arn
    index_name = "cloudwatch-logs"

    buffering_interval = 60
    buffering_size     = 5

    s3_backup_mode = "FailedDocumentsOnly"

    s3_configuration {
      role_arn           = aws_iam_role.firehose_to_opensearch.arn
      bucket_arn         = aws_s3_bucket.logs.arn
      prefix             = "firehose-opensearch-backup/"
      buffering_interval = 300
      buffering_size     = 5
      compression_format = "GZIP"
    }
  }
}

###############################
# CloudWatch Logs -> Firehose subscription filters
###############################

resource "aws_iam_role" "cloudwatch_logs_to_firehose" {
  name = "${var.project_prefix}-cw-to-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudwatch_logs_to_firehose" {
  name = "${var.project_prefix}-cw-to-firehose-policy"
  role = aws_iam_role.cloudwatch_logs_to_firehose.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch",
          "firehose:DescribeDeliveryStream",
          "firehose:ListDeliveryStreams",
          "firehose:ListTagsForDeliveryStream"
        ],
        Resource = aws_kinesis_firehose_delivery_stream.cloudwatch_to_opensearch.arn
      }
    ]
  })
}

# Stream selected my-soc log groups into OpenSearch via Firehose

resource "aws_cloudwatch_log_subscription_filter" "web_os_to_opensearch" {
  name            = "${var.project_prefix}-web-os-to-os"
  log_group_name  = aws_cloudwatch_log_group.web_os.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_to_opensearch.arn
  role_arn        = aws_iam_role.cloudwatch_logs_to_firehose.arn
}

resource "aws_cloudwatch_log_subscription_filter" "web_app_to_opensearch" {
  name            = "${var.project_prefix}-web-app-to-os"
  log_group_name  = aws_cloudwatch_log_group.web_app.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_to_opensearch.arn
  role_arn        = aws_iam_role.cloudwatch_logs_to_firehose.arn
}

resource "aws_cloudwatch_log_subscription_filter" "route53_to_opensearch" {
  name            = "${var.project_prefix}-route53-to-os"
  log_group_name  = aws_cloudwatch_log_group.route53_resolver.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_to_opensearch.arn
  role_arn        = aws_iam_role.cloudwatch_logs_to_firehose.arn
}
