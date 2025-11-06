output "state_machine_arn" {
  description = "ARN of the Step Functions state machine that orchestrates AMI copy workflow"
  value       = aws_sfn_state_machine.ami_copier.arn
}

output "state_machine_name" {
  description = "Name of the Step Functions state machine"
  value       = aws_sfn_state_machine.ami_copier.name
}

output "initiator_lambda_arn" {
  description = "ARN of the initiator Lambda function (discovers AMIs and starts copy)"
  value       = aws_lambda_function.initiator.arn
}

output "initiator_lambda_name" {
  description = "Name of the initiator Lambda function"
  value       = aws_lambda_function.initiator.function_name
}

output "status_checker_lambda_arn" {
  description = "ARN of the status checker Lambda function (checks AMI copy status)"
  value       = aws_lambda_function.status_checker.arn
}

output "status_checker_lambda_name" {
  description = "Name of the status checker Lambda function"
  value       = aws_lambda_function.status_checker.function_name
}

output "finalizer_lambda_arn" {
  description = "ARN of the finalizer Lambda function (re-registers with gp3 and applies tags)"
  value       = aws_lambda_function.finalizer.arn
}

output "finalizer_lambda_name" {
  description = "Name of the finalizer Lambda function"
  value       = aws_lambda_function.finalizer.function_name
}

output "lambda_role_arn" {
  description = "ARN of the IAM role used by the Lambda functions"
  value       = aws_iam_role.lambda.arn
}

output "step_functions_role_arn" {
  description = "ARN of the IAM role used by Step Functions"
  value       = aws_iam_role.step_functions.arn
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

output "cloudwatch_log_group_names" {
  description = "Names of the CloudWatch Log Groups for Lambda and Step Functions logs"
  value = {
    initiator      = aws_cloudwatch_log_group.initiator.name
    status_checker = aws_cloudwatch_log_group.status_checker.name
    finalizer      = aws_cloudwatch_log_group.finalizer.name
    step_functions = aws_cloudwatch_log_group.step_functions.name
  }
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
