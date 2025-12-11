output "alb_dns_name" {
  description = "Public DNS name of the ALB (web entry point)"
  value       = aws_lb.web.dns_name
}

output "logs_bucket_name" {
  description = "S3 bucket where CloudTrail / Config logs are stored"
  value       = aws_s3_bucket.logs.id
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "securityhub_killchain_topic_arn" {
  description = "SNS topic ARN for Security Hub high/critical findings (kill-chain notifications)"
  value       = aws_sns_topic.killchain.arn
}
