terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Basic usage - single RHEL version
# When using this module from GitHub, pin to a specific version:
# source = "git::https://github.com/PodioSpaz/ami-copier.git?ref=v1.0.0"
module "ami_copier" {
  source = "../.." # Local path for testing

  name_prefix       = "rhel"
  ami_name_template = "rhel-{uuid}-encrypted-gp3" # UUID ensures uniqueness

  # Optional: Customize polling schedule (default: rate(12 hours))
  # schedule_expression = "rate(6 hours)"  # Run every 6 hours
  # schedule_expression = "cron(0 2 * * ? *)"  # Run daily at 2 AM UTC

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Project     = "rhel-automation"
  }
}

# Example: Separate modules for RHEL 9 and RHEL 10
# Production usage - pin to same version for consistency:
# source = "git::https://github.com/PodioSpaz/ami-copier.git?ref=v1.0.0"
module "rhel9_copier" {
  source = "../.." # Local path for testing

  name_prefix       = "rhel9"
  ami_name_template = "rhel-9-{uuid}-encrypted"

  tags = {
    OS          = "RHEL"
    Version     = "9"
    Environment = "production"
  }

  lambda_timeout = 600 # 10 minutes for large AMIs or API integration
}

module "rhel10_copier" {
  source = "../.." # Local path for testing

  name_prefix       = "rhel10"
  ami_name_template = "rhel-10-{uuid}-encrypted"

  # Custom schedule - check for new AMIs daily at 3 AM UTC
  schedule_expression = "cron(0 3 * * ? *)"

  tags = {
    OS          = "RHEL"
    Version     = "10"
    Environment = "production"
  }
}

# Example: With Red Hat API integration for enhanced tagging
# Uncomment and configure to enable
# module "rhel9_with_api" {
#   source = "../.."
#
#   name_prefix       = "rhel9"
#   ami_name_template = "rhel-9-{uuid}-encrypted"
#
#   # Enable Red Hat Image Builder API integration (using SSM Parameter Store)
#   enable_redhat_api     = true
#   redhat_credential_store = "ssm"  # or "secretsmanager"
#   redhat_client_id      = var.redhat_client_id      # Set in terraform.tfvars
#   redhat_client_secret  = var.redhat_client_secret  # Set in terraform.tfvars
#
#   lambda_timeout = 600  # Increased timeout for API calls
#
#   tags = {
#     OS          = "RHEL"
#     Version     = "9"
#     Environment = "production"
#   }
# }

# Outputs
output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = module.ami_copier.lambda_function_arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge scheduled rule"
  value       = module.ami_copier.eventbridge_rule_name
}

output "schedule_expression" {
  description = "Schedule expression for AMI discovery"
  value       = module.ami_copier.schedule_expression
}

output "log_group" {
  description = "CloudWatch Log Group for Lambda logs"
  value       = module.ami_copier.cloudwatch_log_group_name
}
