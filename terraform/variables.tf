variable "aws_region" {
  description = "AWS region to deploy my-soc lab"
  type        = string
  default     = "us-east-1"
}

variable "project_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "my-soc"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.10.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDRs"
  type        = list(string)
  default     = ["10.10.1.0/24", "10.10.2.0/24"]
}

variable "instance_type" {
  description = "Instance type for web servers"
  type        = string
  default     = "t3.micro"
}

variable "allowed_http_cidr" {
  description = "CIDR allowed to access ALB (HTTP)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "sagemaker_endpoint_name" {
  description = "Name of the SageMaker endpoint used for ML auto-triage"
  type        = string
  default     = "my-soc-rf-endpoint"
}
