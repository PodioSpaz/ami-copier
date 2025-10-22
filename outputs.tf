output "lambda_function_arn" {
  description = "ARN of the Lambda function that copies AMIs"
  value       = aws_lambda_function.ami_copier.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.ami_copier.function_name
}

output "lambda_role_arn" {
  description = "ARN of the IAM role used by the Lambda function"
  value       = aws_iam_role.lambda.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule that triggers AMI copying"
  value       = aws_cloudwatch_event_rule.ami_shared.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.ami_shared.name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "redhat_api_secret_arn" {
  description = "ARN of the Secrets Manager secret containing Red Hat API credentials (only set if enable_redhat_api is true)"
  value       = var.enable_redhat_api ? aws_secretsmanager_secret.redhat_api[0].arn : null
}
