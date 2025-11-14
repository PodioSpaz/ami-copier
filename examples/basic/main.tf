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
#   enable_redhat_api       = true
#   redhat_credential_store = "ssm"  # or "secretsmanager"
#   redhat_client_id        = var.redhat_client_id      # Set in terraform.tfvars
#   redhat_client_secret    = var.redhat_client_secret  # Set in terraform.tfvars
#
#   # Optional: Set a custom Name tag using Distribution from API
#   ami_name_tag_template = "prod-{distribution}"  # Results in "prod-rhel-9"
#
#   lambda_timeout = 600  # Increased timeout for API calls
#
#   tags = {
#     OS          = "RHEL"
#     Version     = "9"
#     Environment = "production"
#   }
# }

# Example: With custom KMS key for cross-account AMI sharing
# Use this when you need to share encrypted AMIs with other AWS accounts
# Uncomment and configure to enable
# module "rhel9_with_kms" {
#   source = "../.."
#
#   name_prefix       = "rhel9"
#   ami_name_template = "rhel-9-{uuid}-encrypted"
#
#   # Specify customer-managed KMS key for encryption
#   # The KMS key policy must grant permissions to this account and any target accounts
#   # You can provide: full ARN, key ID (UUID), or alias
#   kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
#   # kms_key_id = "12345678-1234-1234-1234-123456789012"  # Key ID format also works
#   # kms_key_id = "alias/my-ami-encryption-key"           # Alias format also works
#
#   tags = {
#     OS          = "RHEL"
#     Version     = "9"
#     Environment = "production"
#   }
# }
#
# # Example KMS key policy for cross-account sharing:
# # The KMS key must grant the following permissions:
# # 1. This account (AMI copier account) - encrypt, decrypt, create grants
# # 2. Target account(s) - decrypt, describe key
# #
# # See AWS documentation for KMS key policy examples:
# # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html

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
