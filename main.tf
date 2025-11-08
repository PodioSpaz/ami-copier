locals {
  lambda_function_name = "${var.name_prefix}-ami-copier"
  tags_json            = jsonencode(var.tags)
  secret_name          = "${var.name_prefix}-redhat-api-credentials"

  # Determine if using existing secrets/parameters (imported from validation.tf but also useful here)
  using_existing_secret = var.existing_redhat_secret_arn != "" || var.existing_redhat_secret_name != ""
  using_existing_ssm    = var.existing_redhat_client_id_param_arn != "" || var.existing_redhat_client_id_param_name != "" || var.existing_redhat_client_secret_param_arn != "" || var.existing_redhat_client_secret_param_name != ""

  # Construct full KMS key ARN for IAM policy (if KMS key is specified)
  # Handles three input formats: full ARN, key ID (UUID), or alias
  kms_key_arn = var.kms_key_id == "" ? "" : (
    startswith(var.kms_key_id, "arn:aws:kms:") ? var.kms_key_id :
    startswith(var.kms_key_id, "alias/") ? "arn:aws:kms:${data.aws_region.current[0].id}:${data.aws_caller_identity.current[0].account_id}:${var.kms_key_id}" :
    "arn:aws:kms:${data.aws_region.current[0].id}:${data.aws_caller_identity.current[0].account_id}:key/${var.kms_key_id}"
  )

  # Resolve Secrets Manager secret ARN and name
  # Priority: provided value > data source lookup > created resource
  redhat_secret_arn = (
    var.existing_redhat_secret_arn != "" ? var.existing_redhat_secret_arn :
    var.existing_redhat_secret_name != "" ? data.aws_secretsmanager_secret.existing_redhat_by_name[0].arn :
    var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" && !local.using_existing_secret ? aws_secretsmanager_secret.redhat_api[0].arn :
    ""
  )

  redhat_secret_name = (
    var.existing_redhat_secret_name != "" ? var.existing_redhat_secret_name :
    var.existing_redhat_secret_arn != "" ? data.aws_secretsmanager_secret.existing_redhat_by_arn[0].name :
    var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" && !local.using_existing_secret ? aws_secretsmanager_secret.redhat_api[0].name :
    ""
  )

  # Resolve SSM Parameter Store parameter ARNs and names for client_id
  # When using existing params, data source provides both ARN and name
  client_id_param_arn = (
    local.using_existing_ssm ? data.aws_ssm_parameter.existing_client_id[0].arn :
    var.enable_redhat_api && var.redhat_credential_store == "ssm" ? aws_ssm_parameter.redhat_client_id[0].arn :
    ""
  )

  client_id_param_name = (
    local.using_existing_ssm ? data.aws_ssm_parameter.existing_client_id[0].name :
    var.enable_redhat_api && var.redhat_credential_store == "ssm" ? aws_ssm_parameter.redhat_client_id[0].name :
    ""
  )

  # Resolve SSM Parameter Store parameter ARNs and names for client_secret
  # When using existing params, data source provides both ARN and name
  client_secret_param_arn = (
    local.using_existing_ssm ? data.aws_ssm_parameter.existing_client_secret[0].arn :
    var.enable_redhat_api && var.redhat_credential_store == "ssm" ? aws_ssm_parameter.redhat_client_secret[0].arn :
    ""
  )

  client_secret_param_name = (
    local.using_existing_ssm ? data.aws_ssm_parameter.existing_client_secret[0].name :
    var.enable_redhat_api && var.redhat_credential_store == "ssm" ? aws_ssm_parameter.redhat_client_secret[0].name :
    ""
  )
}

# Archive the Lambda Layer code (shared_utils.py)
data "archive_file" "lambda_layer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_layer"
  output_path = "${path.module}/.terraform/lambda_layer.zip"

  depends_on = [
    null_resource.prepare_lambda_layer
  ]
}

# Prepare Lambda Layer directory structure
resource "null_resource" "prepare_lambda_layer" {
  triggers = {
    shared_utils_hash = filemd5("${path.module}/lambda/shared_utils.py")
    module_path       = path.module
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p ${path.module}/lambda_layer/python
      cp ${path.module}/lambda/shared_utils.py ${path.module}/lambda_layer/python/
    EOT
  }
}

# Archive individual Lambda functions
data "archive_file" "initiator" {
  type        = "zip"
  source_file = "${path.module}/lambda/initiator.py"
  output_path = "${path.module}/.terraform/initiator.zip"
}

data "archive_file" "status_checker" {
  type        = "zip"
  source_file = "${path.module}/lambda/status_checker.py"
  output_path = "${path.module}/.terraform/status_checker.zip"
}

data "archive_file" "finalizer" {
  type        = "zip"
  source_file = "${path.module}/lambda/finalizer.py"
  output_path = "${path.module}/.terraform/finalizer.zip"
}

# Data sources for current AWS account and region (needed for KMS ARN construction)
data "aws_caller_identity" "current" {
  count = var.kms_key_id != "" ? 1 : 0
}

data "aws_region" "current" {
  count = var.kms_key_id != "" ? 1 : 0
}

# Data sources to look up existing secrets/parameters
# We need both ARN and name for each resource (name for Lambda env vars, ARN for IAM policies)

# Secrets Manager: Can look up by either name or ARN
data "aws_secretsmanager_secret" "existing_redhat_by_name" {
  count = var.existing_redhat_secret_name != "" ? 1 : 0
  name  = var.existing_redhat_secret_name
}

data "aws_secretsmanager_secret" "existing_redhat_by_arn" {
  count = var.existing_redhat_secret_arn != "" && var.existing_redhat_secret_name == "" ? 1 : 0
  arn   = var.existing_redhat_secret_arn
}

# SSM Parameter Store: Look up by name (ARN derivable from result)
# Note: SSM parameter ARN format is arn:aws:ssm:region:account:parameter/param-name
# We extract the parameter name by removing everything up to and including "parameter"
data "aws_ssm_parameter" "existing_client_id" {
  count = var.existing_redhat_client_id_param_name != "" || var.existing_redhat_client_id_param_arn != "" ? 1 : 0
  name = (
    var.existing_redhat_client_id_param_name != "" ? var.existing_redhat_client_id_param_name :
    replace(var.existing_redhat_client_id_param_arn, "/^arn:aws:ssm:[^:]+:[^:]+:parameter/", "")
  )
}

data "aws_ssm_parameter" "existing_client_secret" {
  count = var.existing_redhat_client_secret_param_name != "" || var.existing_redhat_client_secret_param_arn != "" ? 1 : 0
  name = (
    var.existing_redhat_client_secret_param_name != "" ? var.existing_redhat_client_secret_param_name :
    replace(var.existing_redhat_client_secret_param_arn, "/^arn:aws:ssm:[^:]+:[^:]+:parameter/", "")
  )
}

# CloudWatch Log Groups for Lambda functions
resource "aws_cloudwatch_log_group" "initiator" {
  name              = "/aws/lambda/${var.name_prefix}-ami-copier-initiator"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "status_checker" {
  name              = "/aws/lambda/${var.name_prefix}-ami-copier-status-checker"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "finalizer" {
  name              = "/aws/lambda/${var.name_prefix}-ami-copier-finalizer"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# SSM Parameter Store for Red Hat API credentials (default)
# Only create if not using existing parameters
resource "aws_ssm_parameter" "redhat_client_id" {
  count = var.enable_redhat_api && var.redhat_credential_store == "ssm" && !local.using_existing_ssm ? 1 : 0

  name        = "/${var.name_prefix}/redhat/client-id"
  description = "Red Hat Service Account Client ID for Image Builder API"
  type        = "SecureString"
  value       = var.redhat_client_id

  tags = var.tags
}

resource "aws_ssm_parameter" "redhat_client_secret" {
  count = var.enable_redhat_api && var.redhat_credential_store == "ssm" && !local.using_existing_ssm ? 1 : 0

  name        = "/${var.name_prefix}/redhat/client-secret"
  description = "Red Hat Service Account Client Secret for Image Builder API"
  type        = "SecureString"
  value       = var.redhat_client_secret

  tags = var.tags
}

# Secrets Manager Secret for Red Hat API credentials (alternative storage)
# Only create if not using existing secret
resource "aws_secretsmanager_secret" "redhat_api" {
  count = var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" && !local.using_existing_secret ? 1 : 0

  name        = local.secret_name
  description = "Red Hat Image Builder API credentials for AMI metadata enrichment"

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "redhat_api" {
  count = var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" && !local.using_existing_secret ? 1 : 0

  secret_id = aws_secretsmanager_secret.redhat_api[0].id
  secret_string = var.redhat_offline_token != "" ? jsonencode({
    offline_token = var.redhat_offline_token
    }) : jsonencode({
    client_id     = var.redhat_client_id
    client_secret = var.redhat_client_secret
  })
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda" {
  name = "${local.lambda_function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM Policy for Lambda
resource "aws_iam_role_policy" "lambda" {
  name = "${local.lambda_function_name}-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.initiator.arn}:*",
          "${aws_cloudwatch_log_group.status_checker.arn}:*",
          "${aws_cloudwatch_log_group.finalizer.arn}:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeImages",
          "ec2:CopyImage",
          "ec2:CreateTags",
          "ec2:DescribeSnapshots",
          "ec2:RegisterImage",
          "ec2:DeregisterImage"
        ]
        Resource = "*"
      }
      ],
      var.enable_redhat_api && var.redhat_credential_store == "ssm" ? [
        {
          Effect = "Allow"
          Action = [
            "ssm:GetParameter"
          ]
          Resource = [
            local.client_id_param_arn,
            local.client_secret_param_arn
          ]
        }
      ] : [],
      var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" ? [
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue"
          ]
          Resource = local.redhat_secret_arn
        }
      ] : [],
      var.kms_key_id != "" ? [
        {
          Effect = "Allow"
          Action = [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:CreateGrant",
            "kms:DescribeKey"
          ]
          Resource = local.kms_key_arn
        }
    ] : [])
  })
}

# Lambda Layer for shared utilities
resource "aws_lambda_layer_version" "shared_utils" {
  filename            = data.archive_file.lambda_layer.output_path
  layer_name          = "${var.name_prefix}-ami-copier-shared-utils"
  compatible_runtimes = ["python3.12"]
  source_code_hash    = data.archive_file.lambda_layer.output_base64sha256

  description = "Shared utilities for AMI copier Lambda functions"
}

# Lambda Function: Initiator
resource "aws_lambda_function" "initiator" {
  filename         = data.archive_file.initiator.output_path
  function_name    = "${var.name_prefix}-ami-copier-initiator"
  role             = aws_iam_role.lambda.arn
  handler          = "initiator.lambda_handler"
  source_code_hash = data.archive_file.initiator.output_base64sha256
  runtime          = "python3.12"
  timeout          = 600 # 10 minutes for discovery and API calls
  memory_size      = var.lambda_memory_size

  layers = [aws_lambda_layer_version.shared_utils.arn]

  environment {
    variables = merge(
      {
        AMI_NAME_TEMPLATE     = var.ami_name_template
        AMI_NAME_TAG_TEMPLATE = var.ami_name_tag_template
        TAGS                  = local.tags_json
      },
      var.enable_redhat_api ? {
        REDHAT_CREDENTIAL_STORE = var.redhat_credential_store
      } : {},
      var.enable_redhat_api && var.redhat_credential_store == "ssm" ? {
        CLIENT_ID_PARAM     = local.client_id_param_name
        CLIENT_SECRET_PARAM = local.client_secret_param_name
      } : {},
      var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" ? {
        REDHAT_SECRET_NAME = local.redhat_secret_name
      } : {},
      var.kms_key_id != "" ? {
        KMS_KEY_ID = var.kms_key_id
      } : {}
    )
  }

  depends_on = [
    aws_cloudwatch_log_group.initiator,
    aws_iam_role_policy.lambda
  ]

  tags = var.tags
}

# Lambda Function: Status Checker
resource "aws_lambda_function" "status_checker" {
  filename         = data.archive_file.status_checker.output_path
  function_name    = "${var.name_prefix}-ami-copier-status-checker"
  role             = aws_iam_role.lambda.arn
  handler          = "status_checker.lambda_handler"
  source_code_hash = data.archive_file.status_checker.output_base64sha256
  runtime          = "python3.12"
  timeout          = 60 # 1 minute - just checking status
  memory_size      = var.lambda_memory_size

  layers = [aws_lambda_layer_version.shared_utils.arn]

  environment {
    variables = {
      # Status checker doesn't need configuration, just AWS SDK access
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.status_checker,
    aws_iam_role_policy.lambda
  ]

  tags = var.tags
}

# Lambda Function: Finalizer
resource "aws_lambda_function" "finalizer" {
  filename         = data.archive_file.finalizer.output_path
  function_name    = "${var.name_prefix}-ami-copier-finalizer"
  role             = aws_iam_role.lambda.arn
  handler          = "finalizer.lambda_handler"
  source_code_hash = data.archive_file.finalizer.output_base64sha256
  runtime          = "python3.12"
  timeout          = 300 # 5 minutes for re-registration and tagging
  memory_size      = var.lambda_memory_size

  layers = [aws_lambda_layer_version.shared_utils.arn]

  environment {
    variables = {
      # Finalizer receives all config in event from initiator
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.finalizer,
    aws_iam_role_policy.lambda
  ]

  tags = var.tags
}

# EventBridge Scheduled Rule for AMI discovery
resource "aws_cloudwatch_event_rule" "ami_discovery" {
  name                = "${var.name_prefix}-ami-discovery"
  description         = "Scheduled rule to discover and copy shared Red Hat AMIs"
  schedule_expression = var.schedule_expression

  tags = var.tags
}

# EventBridge Target - Step Functions
resource "aws_cloudwatch_event_target" "step_functions" {
  rule      = aws_cloudwatch_event_rule.ami_discovery.name
  target_id = "InvokeStepFunctions"
  arn       = aws_sfn_state_machine.ami_copier.arn
  role_arn  = aws_iam_role.eventbridge.arn
}

# IAM Role for EventBridge to invoke Step Functions
resource "aws_iam_role" "eventbridge" {
  name = "${var.name_prefix}-ami-copier-eventbridge"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM Policy for EventBridge to invoke Step Functions
resource "aws_iam_role_policy" "eventbridge" {
  name = "${var.name_prefix}-ami-copier-eventbridge-policy"
  role = aws_iam_role.eventbridge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "states:StartExecution"
        ]
        Resource = aws_sfn_state_machine.ami_copier.arn
      }
    ]
  })
}
