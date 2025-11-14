variable "name_prefix" {
  description = "Prefix for naming resources (e.g., Lambda function, EventBridge rule)"
  type        = string
  default     = "rhel"
}

variable "ami_name_template" {
  description = <<-EOT
    Template for naming copied AMIs. Available placeholders:
    - {source_name}: Name of the source AMI
    - {uuid}: UUID extracted from Red Hat AMI name (composer-api-{uuid})
    - {date}: Current date/time in format YYYYMMDD-HHMMSS
    - {timestamp}: Unix timestamp

    Example: 'rhel-{uuid}-encrypted-gp3' or '{source_name}-{uuid}-{date}'

    Note: Including {uuid} ensures uniqueness and prevents duplicate copies.
  EOT
  type        = string
  default     = "rhel-{uuid}-encrypted-gp3-{date}"
}

variable "ami_name_tag_template" {
  description = <<-EOT
    Template for the Name tag applied to copied AMIs. Available placeholders:
    - {distribution}: RHEL version from Red Hat API (e.g., 'rhel-9')
    - {source_name}: Name of the source AMI
    - {uuid}: UUID extracted from Red Hat AMI name (composer-api-{uuid})
    - {date}: Current date/time in format YYYYMMDD-HHMMSS
    - {timestamp}: Unix timestamp

    Example: 'prod-{distribution}' produces 'prod-rhel-9'
             'myprefix-{distribution}-{date}' produces 'myprefix-rhel-9-20251105-143022'

    Note: Name tag is only applied when Distribution tag is available (requires Red Hat API integration
    with enable_redhat_api = true). If left empty (default), no Name tag will be applied.
  EOT
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to copied AMIs and module resources. Tags will also include SourceAMI, CopiedBy, and CopyDate automatically."
  type        = map(string)
  default     = {}
}

variable "status_check_wait_time" {
  description = "Time in seconds to wait between AMI copy status checks in Step Functions. Default is 300 seconds (5 minutes)."
  type        = number
  default     = 300

  validation {
    condition     = var.status_check_wait_time >= 60 && var.status_check_wait_time <= 3600
    error_message = "Status check wait time must be between 60 and 3600 seconds (1 minute to 1 hour)."
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

variable "kms_key_id" {
  description = <<-EOT
    KMS key ID or ARN to use for encrypting AMI copies.

    - If not specified (default), uses AWS-managed key (aws/ebs)
    - Required for cross-account AMI sharing (AWS-managed keys cannot be shared)
    - Must be a customer-managed KMS key with appropriate key policy granting permissions to this account

    Examples:
    - "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    - "12345678-1234-1234-1234-123456789012"
    - "alias/my-ami-encryption-key"

    For cross-account sharing, the KMS key policy must grant the target account permission to use the key.
  EOT
  type        = string
  default     = ""

  validation {
    condition = (
      var.kms_key_id == "" ||
      can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[a-f0-9-]+$", var.kms_key_id)) ||
      can(regex("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", var.kms_key_id)) ||
      can(regex("^alias/.+$", var.kms_key_id))
    )
    error_message = "KMS key ID must be a valid ARN, key ID (UUID format), or alias (alias/...)."
  }
}

variable "schedule_expression" {
  description = <<-EOT
    EventBridge schedule expression for automated AMI discovery.
    Uses rate() or cron() syntax.

    Examples:
    - 'rate(12 hours)' - Every 12 hours (default)
    - 'rate(1 day)' - Once per day
    - 'cron(0 */12 * * ? *)' - Every 12 hours using cron syntax
    - 'cron(0 2 * * ? *)' - Daily at 2 AM UTC

    See: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html
  EOT
  type        = string
  default     = "rate(12 hours)"
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

# Variables for using existing secrets/parameters instead of creating new ones

variable "existing_redhat_secret_arn" {
  description = <<-EOT
    ARN of an existing AWS Secrets Manager secret containing Red Hat credentials.
    If provided, the module will use this secret instead of creating a new one.

    The secret must contain JSON with either:
    - Service account: {"client_id": "...", "client_secret": "..."}
    - Legacy offline token: {"offline_token": "..."}

    Use this to keep credentials out of Terraform state. Only applicable when
    redhat_credential_store = "secretsmanager".

    Note: Provide either existing_redhat_secret_arn OR existing_redhat_secret_name, not both.
  EOT
  type        = string
  default     = ""
}

variable "existing_redhat_secret_name" {
  description = <<-EOT
    Name of an existing AWS Secrets Manager secret containing Red Hat credentials.
    If provided, the module will use this secret instead of creating a new one.

    The secret must contain JSON with either:
    - Service account: {"client_id": "...", "client_secret": "..."}
    - Legacy offline token: {"offline_token": "..."}

    Use this to keep credentials out of Terraform state. Only applicable when
    redhat_credential_store = "secretsmanager".

    Note: Provide either existing_redhat_secret_arn OR existing_redhat_secret_name, not both.
  EOT
  type        = string
  default     = ""
}

variable "existing_redhat_client_id_param_arn" {
  description = <<-EOT
    ARN of an existing SSM Parameter Store parameter containing the Red Hat Service Account Client ID.
    If provided, the module will use this parameter instead of creating a new one.

    The parameter should be type SecureString and contain the client_id value.

    Use this to keep credentials out of Terraform state. Only applicable when
    redhat_credential_store = "ssm".

    Note: Provide either existing_redhat_client_id_param_arn OR existing_redhat_client_id_param_name, not both.
    Must also provide corresponding client_secret parameter reference.
  EOT
  type        = string
  default     = ""
}

variable "existing_redhat_client_id_param_name" {
  description = <<-EOT
    Name of an existing SSM Parameter Store parameter containing the Red Hat Service Account Client ID.
    If provided, the module will use this parameter instead of creating a new one.

    The parameter should be type SecureString and contain the client_id value.

    Use this to keep credentials out of Terraform state. Only applicable when
    redhat_credential_store = "ssm".

    Note: Provide either existing_redhat_client_id_param_arn OR existing_redhat_client_id_param_name, not both.
    Must also provide corresponding client_secret parameter reference.
  EOT
  type        = string
  default     = ""
}

variable "existing_redhat_client_secret_param_arn" {
  description = <<-EOT
    ARN of an existing SSM Parameter Store parameter containing the Red Hat Service Account Client Secret.
    If provided, the module will use this parameter instead of creating a new one.

    The parameter should be type SecureString and contain the client_secret value.

    Use this to keep credentials out of Terraform state. Only applicable when
    redhat_credential_store = "ssm".

    Note: Provide either existing_redhat_client_secret_param_arn OR existing_redhat_client_secret_param_name, not both.
    Must also provide corresponding client_id parameter reference.
  EOT
  type        = string
  default     = ""
}

variable "existing_redhat_client_secret_param_name" {
  description = <<-EOT
    Name of an existing SSM Parameter Store parameter containing the Red Hat Service Account Client Secret.
    If provided, the module will use this parameter instead of creating a new one.

    The parameter should be type SecureString and contain the client_secret value.

    Use this to keep credentials out of Terraform state. Only applicable when
    redhat_credential_store = "ssm".

    Note: Provide either existing_redhat_client_secret_param_arn OR existing_redhat_client_secret_param_name, not both.
    Must also provide corresponding client_id parameter reference.
  EOT
  type        = string
  default     = ""
}
