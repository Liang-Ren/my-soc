###############################
# SageMaker RandomForest training
###############################

# This file defines the infrastructure needed to run a one-off
# SageMaker training job that trains a real RandomForestClassifier
# on synthetic data and exports the model artifact to S3.

resource "aws_s3_bucket" "ml_models" {
  bucket = "${var.project_prefix}-ml-models-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "${var.project_prefix}-ml-models"
    Project = var.project_prefix
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ml_models" {
  bucket = aws_s3_bucket.ml_models.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ml_models" {
  bucket                  = aws_s3_bucket.ml_models.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############################
# Upload local training code to S3
###############################

resource "aws_s3_object" "ml_training_code" {
  bucket = aws_s3_bucket.ml_models.id
  key    = "code/train_random_forest.tar.gz"

  # Path is relative to the Terraform working directory (terraform/)
  # We expect the user-provided tar.gz to live in ../ml
  source = "../ml/train_random_forest.tar.gz"

  etag = filemd5("../ml/train_random_forest.tar.gz")
}

###############################
# SageMaker execution role
###############################

resource "aws_iam_role" "sagemaker_execution" {
  name = "${var.project_prefix}-sagemaker-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sagemaker.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "sagemaker_execution" {
  name = "${var.project_prefix}-sagemaker-execution-policy"
  role = aws_iam_role.sagemaker_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.ml_models.arn,
          "${aws_s3_bucket.ml_models.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/sagemaker/*"
      }
    ]
  })
}

###############################
# RandomForest training job (started outside Terraform)
###############################

# NOTE:
# The aws_sagemaker_training_job resource is not available in the
# AWS provider version 6.x that this lab uses. To keep things simple
# and avoid relying on deprecated/removed resources, Terraform only
# provisions:
#   - The ML models S3 bucket (aws_s3_bucket.ml_models)
#   - The SageMaker execution role (aws_iam_role.sagemaker_execution)
#   - The training code object in S3 (aws_s3_object.ml_training_code)
#
# You can then start the real SageMaker training job manually using
# AWS CLI or the console, for example (CLI, PowerShell):
#
#   $jobName = "${var.project_prefix}-rf-classifier"
#   $region  = "${var.aws_region}"
#   $roleArn = "${aws_iam_role.sagemaker_execution.arn}"
#   $image   = "683313688378.dkr.ecr.${var.aws_region}.amazonaws.com/sagemaker-scikit-learn:1.0-1-cpu-py3"
#   $bucket  = "${aws_s3_bucket.ml_models.id}"
#   $codeKey = "${aws_s3_object.ml_training_code.key}"
#
#   aws sagemaker create-training-job `
#     --region $region `
#     --training-job-name $jobName `
#     --role-arn $roleArn `
#     --algorithm-specification TrainingImage=$image,TrainingInputMode=File `
#     --resource-config InstanceType=ml.m5.large,InstanceCount=1,VolumeSizeInGB=10 `
#     --stopping-condition MaxRuntimeInSeconds=3600 `
#     --input-data-config "[{`"ChannelName`":`"training`",`"DataSource`":{`"S3DataSource`":{`"S3DataType`":`"S3Prefix`",`"S3Uri`":`"s3://$bucket/input/`",`"S3DataDistributionType`":`"FullyReplicated`"}}}]" `
#     --output-data-config "{`"S3OutputPath`":`"s3://$bucket/artifacts/`"}" `
#     --hyper-parameters "{`"n-estimators`":`"100`",`"max-depth`":`"5`",`"sagemaker_program`":`"train_random_forest.py`",`"sagemaker_submit_directory`":`"s3://$bucket/$codeKey`"}"
#
# SageMaker will then train on synthetic data (the script generates it)
# and export the model artifact to s3://$bucket/artifacts/...
