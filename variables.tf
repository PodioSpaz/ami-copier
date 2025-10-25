variable "name_prefix" {
  description = "Prefix for naming resources (e.g., Lambda function, EventBridge rule)"
  type        = string
  default     = "rhel"
}

variable "ami_name_template" {
  description = <<-EOT
    Template for naming copied AMIs. Available placeholders:
    - {source_name}: Name of the source AMI
    - {date}: Current date/time in format YYYYMMDD-HHMMSS
    - {timestamp}: Unix timestamp

    Example: 'rhel-{date}-encrypted-gp3' or '{source_name}-encrypted'
  EOT
  type        = string
  default     = "{source_name}-encrypted-gp3-{date}"
}

variable "tags" {
  description = "Tags to apply to copied AMIs and module resources. Tags will also include SourceAMI, CopiedBy, and CopyDate automatically."
  type        = map(string)
  default     = {}
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds. AMI copy operations may take several minutes."
  type        = number
  default     = 300

  validation {
    condition     = var.lambda_timeout >= 60 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 60 and 900 seconds (15 minutes)."
  }
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory size must be between 128 and 10240 MB."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 7

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch Logs retention value."
  }
}

variable "enable_redhat_api" {
  description = "Enable Red Hat Image Builder API integration for enhanced tagging. Requires Red Hat Service Account credentials (redhat_client_id and redhat_client_secret) or legacy offline token."
  type        = bool
  default     = false
}

variable "redhat_credential_store" {
  description = <<-EOT
    Where to store Red Hat API credentials:
    - 'ssm' (default): AWS Systems Manager Parameter Store (SecureString)
    - 'secretsmanager': AWS Secrets Manager

    SSM Parameter Store is recommended for most use cases (simpler, lower cost).
  EOT
  type        = string
  default     = "ssm"

  validation {
    condition     = contains(["ssm", "secretsmanager"], var.redhat_credential_store)
    error_message = "Must be 'ssm' or 'secretsmanager'."
  }
}

variable "redhat_client_id" {
  description = <<-EOT
    Red Hat Service Account Client ID for API authentication.
    Create a service account at https://console.redhat.com (Settings > Service Accounts).
    Only required if enable_redhat_api is true.
    Will be stored securely in SSM Parameter Store or Secrets Manager based on redhat_credential_store.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}

variable "redhat_client_secret" {
  description = <<-EOT
    Red Hat Service Account Client Secret for API authentication.
    Obtained when creating the service account (shown only once).
    Only required if enable_redhat_api is true.
    Will be stored securely in SSM Parameter Store or Secrets Manager based on redhat_credential_store.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}

variable "redhat_offline_token" {
  description = <<-EOT
    [DEPRECATED - Use redhat_client_id and redhat_client_secret instead]

    Red Hat offline token for API authentication (legacy). Get one from https://access.redhat.com/management/api.
    Only required if enable_redhat_api is true and using legacy authentication.
    Will be stored securely in AWS Secrets Manager.

    NOTE: Offline tokens are tied to user accounts. Service accounts (redhat_client_id/redhat_client_secret)
    are recommended for automation as they provide better security and are not tied to individual users.
  EOT
  type        = string
  default     = ""
  sensitive   = true
}
