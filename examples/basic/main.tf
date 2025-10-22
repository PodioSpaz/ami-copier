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
module "ami_copier" {
  source = "../.."

  name_prefix       = "rhel"
  ami_name_template = "rhel-encrypted-gp3-{date}"

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Project     = "rhel-automation"
  }
}

# Example: Separate modules for RHEL 9 and RHEL 10
module "rhel9_copier" {
  source = "../.."

  name_prefix       = "rhel9"
  ami_name_template = "rhel-9-encrypted-{date}"

  tags = {
    OS          = "RHEL"
    Version     = "9"
    Environment = "production"
  }

  lambda_timeout = 600 # 10 minutes for large AMIs
}

module "rhel10_copier" {
  source = "../.."

  name_prefix       = "rhel10"
  ami_name_template = "rhel-10-encrypted-{date}"

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
#   ami_name_template = "rhel-9-encrypted-{date}"
#
#   # Enable Red Hat Image Builder API integration
#   enable_redhat_api    = true
#   redhat_offline_token = var.redhat_offline_token  # Set in terraform.tfvars
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
  description = "Name of the EventBridge rule"
  value       = module.ami_copier.eventbridge_rule_name
}

output "log_group" {
  description = "CloudWatch Log Group for Lambda logs"
  value       = module.ami_copier.cloudwatch_log_group_name
}
