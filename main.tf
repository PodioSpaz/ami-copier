locals {
  lambda_function_name = "${var.name_prefix}-ami-copier"
  tags_json            = jsonencode(var.tags)
  secret_name          = "${var.name_prefix}-redhat-api-credentials"
}

# Archive the Lambda function code
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/.terraform/lambda.zip"
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.lambda_function_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# SSM Parameter Store for Red Hat API credentials (default)
resource "aws_ssm_parameter" "redhat_client_id" {
  count = var.enable_redhat_api && var.redhat_credential_store == "ssm" ? 1 : 0

  name        = "/${var.name_prefix}/redhat/client-id"
  description = "Red Hat Service Account Client ID for Image Builder API"
  type        = "SecureString"
  value       = var.redhat_client_id

  tags = var.tags
}

resource "aws_ssm_parameter" "redhat_client_secret" {
  count = var.enable_redhat_api && var.redhat_credential_store == "ssm" ? 1 : 0

  name        = "/${var.name_prefix}/redhat/client-secret"
  description = "Red Hat Service Account Client Secret for Image Builder API"
  type        = "SecureString"
  value       = var.redhat_client_secret

  tags = var.tags
}

# Secrets Manager Secret for Red Hat API credentials (alternative storage)
resource "aws_secretsmanager_secret" "redhat_api" {
  count = var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" ? 1 : 0

  name        = local.secret_name
  description = "Red Hat Image Builder API credentials for AMI metadata enrichment"

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "redhat_api" {
  count = var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" ? 1 : 0

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
          "ec2:DescribeSnapshots"
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
            aws_ssm_parameter.redhat_client_id[0].arn,
            aws_ssm_parameter.redhat_client_secret[0].arn
          ]
        }
      ] : [],
      var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" ? [
        {
          Effect = "Allow"
          Action = [
            "secretsmanager:GetSecretValue"
          ]
          Resource = aws_secretsmanager_secret.redhat_api[0].arn
        }
    ] : [])
  })
}

# Lambda Function
resource "aws_lambda_function" "ami_copier" {
  filename         = data.archive_file.lambda.output_path
  function_name    = local.lambda_function_name
  role            = aws_iam_role.lambda.arn
  handler         = "ami_copier.lambda_handler"
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime         = "python3.12"
  timeout         = var.lambda_timeout
  memory_size     = var.lambda_memory_size

  environment {
    variables = merge(
      {
        AMI_NAME_TEMPLATE = var.ami_name_template
        TAGS              = local.tags_json
      },
      var.enable_redhat_api ? {
        REDHAT_CREDENTIAL_STORE = var.redhat_credential_store
      } : {},
      var.enable_redhat_api && var.redhat_credential_store == "ssm" ? {
        CLIENT_ID_PARAM     = aws_ssm_parameter.redhat_client_id[0].name
        CLIENT_SECRET_PARAM = aws_ssm_parameter.redhat_client_secret[0].name
      } : {},
      var.enable_redhat_api && var.redhat_credential_store == "secretsmanager" ? {
        REDHAT_SECRET_NAME = aws_secretsmanager_secret.redhat_api[0].name
      } : {}
    )
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda
  ]

  tags = var.tags
}

# EventBridge Rule to detect AMI sharing
resource "aws_cloudwatch_event_rule" "ami_shared" {
  name        = "${var.name_prefix}-ami-shared"
  description = "Trigger when an AMI is shared with this account"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["ModifyImageAttribute"]
      requestParameters = {
        launchPermission = {
          add = {
            items = [
              {
                userId = [data.aws_caller_identity.current.account_id]
              }
            ]
          }
        }
      }
    }
  })

  tags = var.tags
}

# EventBridge Target - Lambda
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.ami_shared.name
  target_id = "InvokeLambda"
  arn       = aws_lambda_function.ami_copier.arn
}

# Lambda Permission for EventBridge
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ami_copier.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ami_shared.arn
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}
