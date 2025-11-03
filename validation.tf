# Validation for Red Hat API credential configuration

locals {
  # Determine if inline credentials are provided
  inline_credentials_provided = var.redhat_client_id != "" && var.redhat_client_secret != "" || var.redhat_offline_token != ""

  # Validation: When using Secrets Manager, can't specify both ARN and name
  validate_secret_arn_or_name = (
    var.existing_redhat_secret_arn != "" && var.existing_redhat_secret_name != "" ?
    tobool("ERROR: Provide either existing_redhat_secret_arn OR existing_redhat_secret_name, not both") :
    true
  )

  # Validation: When using SSM for client_id, can't specify both ARN and name
  validate_client_id_arn_or_name = (
    var.existing_redhat_client_id_param_arn != "" && var.existing_redhat_client_id_param_name != "" ?
    tobool("ERROR: Provide either existing_redhat_client_id_param_arn OR existing_redhat_client_id_param_name, not both") :
    true
  )

  # Validation: When using SSM for client_secret, can't specify both ARN and name
  validate_client_secret_arn_or_name = (
    var.existing_redhat_client_secret_param_arn != "" && var.existing_redhat_client_secret_param_name != "" ?
    tobool("ERROR: Provide either existing_redhat_client_secret_param_arn OR existing_redhat_client_secret_param_name, not both") :
    true
  )

  # Validation: When using existing SSM parameters, must provide both client_id and client_secret
  validate_ssm_params_together = (
    local.using_existing_ssm && !(
      (var.existing_redhat_client_id_param_arn != "" || var.existing_redhat_client_id_param_name != "") &&
      (var.existing_redhat_client_secret_param_arn != "" || var.existing_redhat_client_secret_param_name != "")
    ) ?
    tobool("ERROR: When using existing SSM parameters, must provide both client_id and client_secret parameter references") :
    true
  )

  # Validation: When enable_redhat_api is true, must provide credentials via one method
  validate_credentials_when_api_enabled = (
    var.enable_redhat_api && !local.inline_credentials_provided && !local.using_existing_secret && !local.using_existing_ssm ?
    tobool("ERROR: When enable_redhat_api=true, must provide either inline credentials (redhat_client_id/redhat_client_secret or redhat_offline_token) OR external secret/parameter references") :
    true
  )

  # Validation: Can't mix inline credentials with external references
  validate_no_credential_mixing = (
    var.enable_redhat_api && local.inline_credentials_provided && (local.using_existing_secret || local.using_existing_ssm) ?
    tobool("ERROR: Cannot provide both inline credentials (redhat_client_id/redhat_client_secret/redhat_offline_token) AND external secret/parameter references. Choose one method.") :
    true
  )

  # Validation: External Secrets Manager references only valid with secretsmanager credential store
  validate_secret_store_type = (
    local.using_existing_secret && var.redhat_credential_store != "secretsmanager" ?
    tobool("ERROR: existing_redhat_secret_arn/existing_redhat_secret_name can only be used when redhat_credential_store='secretsmanager'") :
    true
  )

  # Validation: External SSM parameter references only valid with ssm credential store
  validate_ssm_store_type = (
    local.using_existing_ssm && var.redhat_credential_store != "ssm" ?
    tobool("ERROR: existing_redhat_client_id_param_* and existing_redhat_client_secret_param_* can only be used when redhat_credential_store='ssm'") :
    true
  )

  # Validation: External references require enable_redhat_api to be true
  validate_api_enabled_for_external = (
    (local.using_existing_secret || local.using_existing_ssm) && !var.enable_redhat_api ?
    tobool("ERROR: External secret/parameter references require enable_redhat_api=true") :
    true
  )
}

# Null resource to enforce validations at plan time
resource "null_resource" "validate_credentials" {
  count = var.enable_redhat_api || local.using_existing_secret || local.using_existing_ssm ? 1 : 0

  lifecycle {
    precondition {
      condition     = local.validate_secret_arn_or_name
      error_message = "Provide either existing_redhat_secret_arn OR existing_redhat_secret_name, not both"
    }

    precondition {
      condition     = local.validate_client_id_arn_or_name
      error_message = "Provide either existing_redhat_client_id_param_arn OR existing_redhat_client_id_param_name, not both"
    }

    precondition {
      condition     = local.validate_client_secret_arn_or_name
      error_message = "Provide either existing_redhat_client_secret_param_arn OR existing_redhat_client_secret_param_name, not both"
    }

    precondition {
      condition     = local.validate_ssm_params_together
      error_message = "When using existing SSM parameters, must provide both client_id and client_secret parameter references"
    }

    precondition {
      condition     = local.validate_credentials_when_api_enabled
      error_message = "When enable_redhat_api=true, must provide either inline credentials (redhat_client_id/redhat_client_secret or redhat_offline_token) OR external secret/parameter references"
    }

    precondition {
      condition     = local.validate_no_credential_mixing
      error_message = "Cannot provide both inline credentials AND external secret/parameter references. Choose one method."
    }

    precondition {
      condition     = local.validate_secret_store_type
      error_message = "existing_redhat_secret_arn/existing_redhat_secret_name can only be used when redhat_credential_store='secretsmanager'"
    }

    precondition {
      condition     = local.validate_ssm_store_type
      error_message = "existing_redhat_client_id_param_* and existing_redhat_client_secret_param_* can only be used when redhat_credential_store='ssm'"
    }

    precondition {
      condition     = local.validate_api_enabled_for_external
      error_message = "External secret/parameter references require enable_redhat_api=true"
    }
  }
}
