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
  description = "ARN of the EventBridge scheduled rule for AMI discovery"
  value       = aws_cloudwatch_event_rule.ami_discovery.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge scheduled rule"
  value       = aws_cloudwatch_event_rule.ami_discovery.name
}

output "schedule_expression" {
  description = "Schedule expression for automated AMI discovery"
  value       = var.schedule_expression
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Log Group for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "redhat_api_secret_arn" {
  description = "ARN of the Secrets Manager secret containing Red Hat API credentials (only set if enable_redhat_api is true and redhat_credential_store is 'secretsmanager')"
  value       = var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" ? local.redhat_secret_arn : null
}

output "redhat_ssm_parameter_arns" {
  description = "ARNs of SSM Parameter Store parameters containing Red Hat API credentials (only set if enable_redhat_api is true and redhat_credential_store is 'ssm')"
  value = var.enable_redhat_api && var.redhat_credential_store == "ssm" ? {
    client_id     = local.client_id_param_arn
    client_secret = local.client_secret_param_arn
  } : null
}
