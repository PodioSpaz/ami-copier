# Migration Guide: v0.x to v1.0

## Overview

Version 1.0 introduces a **breaking change** by replacing the synchronous Lambda-based AMI copy process with an asynchronous Step Functions workflow. This eliminates Lambda timeout issues for large AMIs and provides better observability and error handling.

## What Changed

### Architecture

**Before (v0.x):**
```
EventBridge → Lambda → Synchronous AMI Copy (with waiter) → Timeout after 15 min
```

**After (v1.0):**
```
EventBridge → Step Functions State Machine:
  1. Initiator Lambda: Discover AMIs, start copy
  2. Wait: 5 minutes
  3. Status Checker Lambda: Check status
  4. Choice: Repeat wait/check until ready
  5. Finalizer Lambda: Re-register with gp3, tag, cleanup
```

### Breaking Changes

#### 1. Variable Changes

**Removed:**
- `lambda_timeout` - No longer applicable with Step Functions

**Added:**
- `status_check_wait_time` - Time between status checks (default: 300 seconds)

#### 2. Output Changes

**Removed:**
- `lambda_function_arn`
- `lambda_function_name`
- `cloudwatch_log_group_name` (single value)

**Added:**
- `state_machine_arn`
- `state_machine_name`
- `initiator_lambda_arn`
- `initiator_lambda_name`
- `status_checker_lambda_arn`
- `status_checker_lambda_name`
- `finalizer_lambda_arn`
- `finalizer_lambda_name`
- `step_functions_role_arn`
- `cloudwatch_log_group_names` (map with: initiator, status_checker, finalizer, step_functions)

**Unchanged:**
- `lambda_role_arn`
- `eventbridge_rule_arn`
- `eventbridge_rule_name`
- `schedule_expression`
- `redhat_api_secret_arn`
- `redhat_ssm_parameter_arns`

#### 3. Resource Changes

**Infrastructure:**
- Single Lambda function → Three Lambda functions + Lambda Layer
- EventBridge invokes Step Functions instead of Lambda directly
- New IAM role for Step Functions
- New IAM role for EventBridge to invoke Step Functions
- Multiple CloudWatch Log Groups (one per Lambda + one for Step Functions)

## Migration Steps

### Step 1: Update Module Version

Update your module source to reference v1.0:

```hcl
module "rhel9_copier" {
  source  = "path/to/ami-copier"
  # or if using registry:
  # source  = "github.com/YourOrg/ami-copier?ref=v1.0.0"

  # ... your configuration ...
}
```

### Step 2: Update Variables

**Remove this variable if present:**
```hcl
lambda_timeout = 900  # ❌ REMOVE - no longer used
```

**Optionally add (if you want non-default behavior):**
```hcl
status_check_wait_time = 300  # ✅ Optional: Time between status checks (60-3600 seconds)
```

### Step 3: Update Output References

If you reference module outputs in your Terraform code, update them:

**Before:**
```hcl
output "lambda_arn" {
  value = module.rhel9_copier.lambda_function_arn
}

output "log_group" {
  value = module.rhel9_copier.cloudwatch_log_group_name
}
```

**After:**
```hcl
output "state_machine_arn" {
  value = module.rhel9_copier.state_machine_arn
}

output "log_groups" {
  value = module.rhel9_copier.cloudwatch_log_group_names
}
```

### Step 4: Plan and Apply

**Important:** This is a destructive change that will:
1. Destroy the old Lambda function
2. Create three new Lambda functions
3. Create a Step Functions state machine
4. Recreate EventBridge target

```bash
terraform plan
# Review the plan carefully - you should see resources being destroyed and created

terraform apply
```

**Expected Resource Changes:**
- **Destroy:** ~3-4 resources (old Lambda, old EventBridge target, old log group)
- **Create:** ~15-20 resources (3 Lambdas, Lambda layer, Step Functions, new log groups, IAM roles/policies)

### Step 5: Verify Deployment

After applying, verify the deployment:

```bash
# List Step Functions executions
aws stepfunctions list-executions \
  --state-machine-arn $(terraform output -raw state_machine_arn) \
  --max-results 10

# Check Step Functions logs
aws logs tail /aws/vendedlogs/states/<name-prefix>-ami-copier --follow

# Check Lambda logs
aws logs tail /aws/lambda/<name-prefix>-ami-copier-initiator --follow
```

## Testing the Migration

### Manual Invocation

**Before (v0.x):**
```bash
aws lambda invoke \
  --function-name <name-prefix>-ami-copier \
  --payload '{"source_ami_id":"ami-xxxxx"}' \
  response.json
```

**After (v1.0):**
```bash
# Start state machine execution
aws stepfunctions start-execution \
  --state-machine-arn <state-machine-arn> \
  --input '{"source_ami_id":"ami-xxxxx"}' \
  --name "manual-test-$(date +%s)"

# Get execution ARN from output, then check status
aws stepfunctions describe-execution \
  --execution-arn <execution-arn>
```

### Monitoring

**CloudWatch Logs:**
- Before: Single log group `/aws/lambda/<name-prefix>-ami-copier`
- After: Multiple log groups:
  - `/aws/lambda/<name-prefix>-ami-copier-initiator`
  - `/aws/lambda/<name-prefix>-ami-copier-status-checker`
  - `/aws/lambda/<name-prefix>-ami-copier-finalizer`
  - `/aws/vendedlogs/states/<name-prefix>-ami-copier`

**Step Functions Console:**
- Navigate to AWS Console → Step Functions → State machines
- Find `<name-prefix>-ami-copier`
- View execution history with visual workflow

## Rollback

If you need to rollback to v0.x:

1. Update module version back to v0.x
2. Restore removed variables:
   ```hcl
   lambda_timeout = 900
   ```
3. Remove added variables:
   ```hcl
   # status_check_wait_time = 300  # ❌ Remove
   ```
4. Run `terraform apply`

**Note:** Rolling back will destroy the Step Functions state machine and recreate the single Lambda function.

## Benefits of v1.0

✅ **No Lambda Timeouts:** Step Functions can wait indefinitely for AMI copy completion
✅ **Better Observability:** Visual workflow in Step Functions console
✅ **Automatic Retries:** Built-in retry logic for transient failures
✅ **Lower Cost:** Shorter Lambda executions (pay only for active work)
✅ **Proper Cleanup:** Temp AMIs cleaned up even on failures

## Troubleshooting

### Issue: Terraform Plan Shows Many Changes

**Cause:** This is expected - the architecture has fundamentally changed.

**Solution:** Review the plan carefully. You should see old resources being destroyed and new ones created. No data loss will occur (existing copied AMIs are unchanged).

### Issue: State Machine Not Triggered by Schedule

**Check EventBridge rule target:**
```bash
aws events list-targets-by-rule --rule <name-prefix>-ami-discovery
```

Should show target pointing to Step Functions ARN, not Lambda ARN.

### Issue: "Access Denied" When Starting State Machine

**Check IAM permissions:** Ensure your AWS credentials have `states:StartExecution` permission on the state machine.

### Issue: Lambda Functions Can't Access Shared Utils

**Check Lambda Layer:** Ensure `shared_utils` layer is attached to all three Lambda functions.

```bash
aws lambda get-function --function-name <name-prefix>-ami-copier-initiator \
  --query 'Configuration.Layers'
```

## Support

For issues or questions:
- File an issue: https://github.com/PodioSpaz/ami-copier/issues
- Reference: GitHub Issue #26

## Version History

- **v0.3.x**: Synchronous Lambda-based AMI copy
- **v1.0.0**: Step Functions-based asynchronous workflow (breaking change)
