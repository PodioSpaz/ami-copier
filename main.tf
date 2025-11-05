locals {
  lambda_function_name = "${var.name_prefix}-ami-copier"
  tags_json            = jsonencode(var.tags)
  secret_name          = "${var.name_prefix}-redhat-api-credentials"

  # Determine if using existing secrets/parameters (imported from validation.tf but also useful here)
  using_existing_secret = var.existing_redhat_secret_arn != "" || var.existing_redhat_secret_name != ""
  using_existing_ssm    = var.existing_redhat_client_id_param_arn != "" || var.existing_redhat_client_id_param_name != "" || var.existing_redhat_client_secret_param_arn != "" || var.existing_redhat_client_secret_param_name != ""

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

# Archive the Lambda function code
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/.terraform/lambda.zip"
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

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.lambda_function_name}"
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
        Resource = "${aws_cloudwatch_log_group.lambda.arn}:*"
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
    ] : [])
  })
}

# Lambda Function
resource "aws_lambda_function" "ami_copier" {
  filename         = data.archive_file.lambda.output_path
  function_name    = local.lambda_function_name
  role             = aws_iam_role.lambda.arn
  handler          = "ami_copier.lambda_handler"
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size

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
      } : {}
    )
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
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

# EventBridge Target - Lambda
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.ami_discovery.name
  target_id = "InvokeLambda"
  arn       = aws_lambda_function.ami_copier.arn
}

# Lambda Permission for EventBridge
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ami_copier.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ami_discovery.arn
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}
