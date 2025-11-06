# Step Functions State Machine for Asynchronous AMI Copy

# IAM Role for Step Functions
resource "aws_iam_role" "step_functions" {
  name               = "${var.name_prefix}-ami-copier-sfn"
  assume_role_policy = data.aws_iam_policy_document.step_functions_assume_role.json

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-ami-copier-sfn"
    }
  )
}

data "aws_iam_policy_document" "step_functions_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# IAM Policy for Step Functions to invoke Lambda functions
resource "aws_iam_role_policy" "step_functions" {
  name   = "${var.name_prefix}-ami-copier-sfn-policy"
  role   = aws_iam_role.step_functions.id
  policy = data.aws_iam_policy_document.step_functions_policy.json
}

data "aws_iam_policy_document" "step_functions_policy" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction"
    ]

    resources = [
      aws_lambda_function.initiator.arn,
      aws_lambda_function.status_checker.arn,
      aws_lambda_function.finalizer.arn,
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups"
    ]

    resources = ["*"]
  }
}

# CloudWatch Log Group for Step Functions
resource "aws_cloudwatch_log_group" "step_functions" {
  name              = "/aws/vendedlogs/states/${var.name_prefix}-ami-copier"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-ami-copier-sfn-logs"
    }
  )
}

# Step Functions State Machine
resource "aws_sfn_state_machine" "ami_copier" {
  name     = "${var.name_prefix}-ami-copier"
  role_arn = aws_iam_role.step_functions.arn

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  definition = jsonencode({
    Comment = "Asynchronous AMI copy workflow with Step Functions"
    StartAt = "DiscoverAMIs"

    States = {
      # Step 1: Discover and initiate copies for all AMIs
      DiscoverAMIs = {
        Type       = "Task"
        Resource   = aws_lambda_function.initiator.arn
        ResultPath = "$.discovery_result"
        Next       = "CheckAMIsFound"
        Retry = [
          {
            ErrorEquals = [
              "Lambda.ServiceException",
              "Lambda.AWSLambdaException",
              "Lambda.SdkClientException"
            ]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            ResultPath  = "$.error"
            Next        = "DiscoveryFailed"
          }
        ]
      }

      # Check if any AMIs were found to process
      CheckAMIsFound = {
        Type = "Choice"
        Choices = [
          {
            Variable           = "$.discovery_result.summary.to_process"
            NumericGreaterThan = 0
            Next               = "ProcessAMIs"
          }
        ]
        Default = "NoAMIsToProcess"
      }

      # No AMIs to process - success with no work done
      NoAMIsToProcess = {
        Type = "Pass"
        Result = {
          status  = "success"
          message = "No AMIs to process"
        }
        ResultPath = "$.result"
        Next       = "Success"
      }

      # Process each AMI sequentially
      ProcessAMIs = {
        Type           = "Map"
        ItemsPath      = "$.discovery_result.amis_to_process"
        MaxConcurrency = 1 # Sequential processing
        ResultPath     = "$.processing_results"
        Next           = "AggregateResults"

        Iterator = {
          StartAt = "WaitForCopy"

          States = {
            # Wait before first status check
            WaitForCopy = {
              Type    = "Wait"
              Seconds = var.status_check_wait_time
              Next    = "CheckStatus"
            }

            # Check AMI copy status
            CheckStatus = {
              Type       = "Task"
              Resource   = aws_lambda_function.status_checker.arn
              ResultPath = "$"
              Next       = "IsAMIReady"
              Retry = [
                {
                  ErrorEquals = [
                    "Lambda.ServiceException",
                    "Lambda.AWSLambdaException",
                    "Lambda.SdkClientException"
                  ]
                  IntervalSeconds = 2
                  MaxAttempts     = 3
                  BackoffRate     = 2.0
                }
              ]
              Catch = [
                {
                  ErrorEquals = ["States.ALL"]
                  ResultPath  = "$.error"
                  Next        = "StatusCheckFailed"
                }
              ]
            }

            # Check if AMI is ready or should continue waiting
            IsAMIReady = {
              Type = "Choice"
              Choices = [
                {
                  Variable      = "$.ami_available"
                  BooleanEquals = true
                  Next          = "FinalizeAMI"
                },
                {
                  Variable      = "$.continue_waiting"
                  BooleanEquals = true
                  Next          = "WaitForCopy"
                }
              ]
              Default = "CopyFailed"
            }

            # Finalize AMI (re-register with gp3, apply tags)
            FinalizeAMI = {
              Type       = "Task"
              Resource   = aws_lambda_function.finalizer.arn
              ResultPath = "$"
              Next       = "AMICompleted"
              Retry = [
                {
                  ErrorEquals = [
                    "Lambda.ServiceException",
                    "Lambda.AWSLambdaException",
                    "Lambda.SdkClientException"
                  ]
                  IntervalSeconds = 2
                  MaxAttempts     = 3
                  BackoffRate     = 2.0
                }
              ]
              Catch = [
                {
                  ErrorEquals = ["States.ALL"]
                  ResultPath  = "$.error"
                  Next        = "FinalizationFailed"
                }
              ]
            }

            # AMI processing completed successfully
            AMICompleted = {
              Type = "Pass"
              Result = {
                result = "success"
              }
              ResultPath = "$.processing_result"
              End        = true
            }

            # Copy failed (AMI in failed state or error)
            CopyFailed = {
              Type = "Pass"
              Result = {
                result = "copy_failed"
              }
              ResultPath = "$.processing_result"
              End        = true
            }

            # Status check failed
            StatusCheckFailed = {
              Type = "Pass"
              Result = {
                result = "status_check_failed"
              }
              ResultPath = "$.processing_result"
              End        = true
            }

            # Finalization failed
            FinalizationFailed = {
              Type = "Pass"
              Result = {
                result = "finalization_failed"
              }
              ResultPath = "$.processing_result"
              End        = true
            }
          }
        }
      }

      # Aggregate results from all AMI processing
      AggregateResults = {
        Type = "Pass"
        Parameters = {
          mode    = "$.discovery_result.mode"
          summary = "$.discovery_result.summary"
          results = "$.processing_results"
        }
        ResultPath = "$.final_result"
        Next       = "Success"
      }

      # Success terminal state
      Success = {
        Type = "Succeed"
      }

      # Discovery failed terminal state
      DiscoveryFailed = {
        Type  = "Fail"
        Error = "DiscoveryError"
        Cause = "Failed to discover and initiate AMI copies"
      }
    }
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-ami-copier"
    }
  )
}
