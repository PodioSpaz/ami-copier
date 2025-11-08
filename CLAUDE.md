# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Terraform module that automatically copies AMIs shared by Red Hat Image Builder, converting unencrypted gp2 volumes to encrypted gp3 volumes. The module is designed to be reusable and can be deployed by others.

## Architecture

The module uses a **Step Functions-based asynchronous architecture**:

1. **EventBridge Scheduled Rule** - Triggers Step Functions state machine every 12 hours (configurable) to discover shared AMIs
2. **Step Functions State Machine** (`step_functions.tf`) - Orchestrates the asynchronous AMI copy workflow
3. **Lambda Functions** (`lambda/`)
   - **Initiator** (`initiator.py`) - Discovers Red Hat AMIs, enriches with Red Hat API metadata, initiates encrypted copy
   - **Status Checker** (`status_checker.py`) - Checks AMI copy status
   - **Finalizer** (`finalizer.py`) - Re-registers AMI with gp3 volumes, applies tags, cleans up temp AMI
4. **Lambda Layer** (`shared_utils.py`) - Common utilities shared across Lambda functions
5. **IAM Roles & Policies** - Permissions for Lambda, Step Functions, and EventBridge

**Why polling instead of event-driven?**

The initial design used EventBridge to monitor `ModifyImageAttribute` API calls via CloudTrail. However, these events are generated in the **creator account** (Red Hat's AWS account), not the consumer account where this module is deployed. See [AWS documentation](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/monitor-use-of-a-shared-amazon-machine-image-across-multiple-aws-accounts.html) for details.

**Why Step Functions instead of synchronous Lambda?**

Lambda functions have a maximum timeout of 15 minutes, but large AMI copies can take 30+ minutes. Step Functions decouples the copy initiation from completion polling, eliminating timeout issues and providing better observability through visual workflow execution history.

**Workflow:**

```
EventBridge Scheduled Rule
  ↓
Step Functions State Machine:
  1. Initiator Lambda
     - Discovers shared Red Hat AMIs (DescribeImages with owner 463606842039)
     - Extracts UUID from AMI name pattern: composer-api-{uuid}
     - Checks for duplicates (tag-based deduplication)
     - Enriches tags with Red Hat Image Builder API metadata (optional)
     - Initiates encrypted copy (ec2:CopyImage)
     → Returns array of AMIs to process

  2. For each AMI (sequential processing):
     a. Wait 5 minutes (configurable: status_check_wait_time)
     b. Status Checker Lambda - Check if copy is complete
     c. If still pending → Loop back to wait
     d. If available → Finalizer Lambda
        - Retrieve temp AMI block device mappings
        - Deregister temp AMI (snapshots retained)
        - Re-register with gp3 volumes (ec2:RegisterImage)
        - Apply tags (SourceAMI, UUID, Red Hat metadata, user tags)
        - Clean up temp AMI
     e. If failed → Error handling
```

## Development Commands

### Terraform Operations

```bash
# Format Terraform files
terraform fmt -recursive

# Validate configuration
terraform validate

# Test in examples directory
cd examples/basic
terraform init
terraform plan
terraform apply
```

### Testing the Step Functions Workflow

The Step Functions state machine supports two invocation modes:

**Scheduled Mode** (automatic discovery):
```bash
# Manually trigger the state machine for discovery (scans all Red Hat AMIs)
aws stepfunctions start-execution \
  --state-machine-arn <state-machine-arn> \
  --input '{}' \
  --name "manual-discovery-$(date +%s)"

# Get execution ARN from output, then check status
aws stepfunctions describe-execution \
  --execution-arn <execution-arn>

# View execution history with event details
aws stepfunctions get-execution-history \
  --execution-arn <execution-arn> \
  --max-results 100
```

**Manual Mode** (specific AMI):
```bash
# Process a specific AMI on-demand
aws stepfunctions start-execution \
  --state-machine-arn <state-machine-arn> \
  --input '{"source_ami_id":"ami-xxxxx"}' \
  --name "manual-ami-$(date +%s)"

# Check execution status
aws stepfunctions describe-execution \
  --execution-arn <execution-arn>
```

**View Logs**:
```bash
# Follow Step Functions logs
aws logs tail /aws/vendedlogs/states/<name-prefix>-ami-copier --follow

# Follow individual Lambda function logs
aws logs tail /aws/lambda/<name-prefix>-ami-copier-initiator --follow
aws logs tail /aws/lambda/<name-prefix>-ami-copier-status-checker --follow
aws logs tail /aws/lambda/<name-prefix>-ami-copier-finalizer --follow

# Check recent executions
aws stepfunctions list-executions \
  --state-machine-arn <state-machine-arn> \
  --max-results 10
```

**Testing Individual Lambda Functions** (for development):
```bash
# Test initiator (discovery mode)
aws lambda invoke \
  --function-name <name-prefix>-ami-copier-initiator \
  --payload '{}' \
  response.json

# Test initiator (single AMI mode)
aws lambda invoke \
  --function-name <name-prefix>-ami-copier-initiator \
  --payload '{"source_ami_id":"ami-xxxxx"}' \
  response.json

# Test status checker (requires temp_ami_id from initiator output)
aws lambda invoke \
  --function-name <name-prefix>-ami-copier-status-checker \
  --payload '{"temp_ami_id":"ami-temp-xxxxx"}' \
  response.json
```

### Finding Copied AMIs

```bash
# List all AMIs copied by this module
aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:CopiedBy,Values=ami-copier-lambda"
```

## Key Implementation Details

### Scheduled AMI Discovery

The EventBridge scheduled rule triggers the Step Functions state machine on a configurable schedule (default: every 12 hours). The Initiator Lambda function queries `DescribeImages` filtering by Red Hat's AWS account ID (`463606842039`) to discover shared AMIs.

### Deduplication Strategy

To prevent copying the same AMI multiple times (performed in Initiator Lambda):

1. **UUID Extraction** - Parses Red Hat AMI name pattern: `composer-api-{uuid}` (`shared_utils.py:extract_uuid_from_ami_name()`)
2. **Tag-based Check** - Queries `DescribeImages` (owner: self) for AMIs with matching `SourceAMI` and `SourceAMIUUID` tags
3. **Skip if Found** - Returns status="skipped" in workflow state, AMI not processed further

Using tag-based deduplication (instead of name matching) is robust against timestamp variations in AMI names.

### Lambda Layer Module Version Detection

The Lambda Layer (`shared_utils.py`) is packaged using a `null_resource` that automatically recreates the layer directory structure when needed (`main.tf:67-78`). The resource uses two triggers to detect when recreation is necessary:

1. **Content Changes** - `filemd5("${path.module}/lambda/shared_utils.py")` detects modifications to the shared utilities code
2. **Module Version Changes** - `path.module` detects when the module source or version changes (e.g., switching from `v1.0.0` to `v1.1.0`)

This ensures the `lambda_layer/python/` directory is automatically recreated when:
- Switching between module versions (releases, branches, or commits)
- Upgrading or downgrading the module
- The module is freshly downloaded by Terraform

No manual intervention (e.g., `terraform apply -replace`) is required when changing module versions.

### Lambda Environment Variables

Configuration is passed to Lambda functions via environment variables:

**Initiator Lambda:**
- `AMI_NAME_TEMPLATE` - Template string with placeholders: `{source_name}`, `{uuid}`, `{date}`, `{timestamp}`
- `AMI_NAME_TAG_TEMPLATE` - Optional template for Name tag: `{distribution}`, `{source_name}`, `{uuid}`, `{date}`, `{timestamp}`
- `TAGS` - JSON-encoded map of tags to apply to copied AMIs
- `KMS_KEY_ID` - (Optional) Customer-managed KMS key ID or ARN for encryption. If not set, uses AWS-managed key (`aws/ebs`)
- `REDHAT_CREDENTIAL_STORE` - Storage type for Red Hat API credentials ("ssm" or "secretsmanager")
- `CLIENT_ID_PARAM` / `CLIENT_SECRET_PARAM` - SSM parameter names (if using SSM)
- `REDHAT_SECRET_NAME` - Secrets Manager secret name (if using Secrets Manager)

**Status Checker Lambda:**
- No configuration needed - receives all state from Step Functions

**Finalizer Lambda:**
- No configuration needed - receives all state from Step Functions (including tags and name template from Initiator)

### Block Device Mapping Transformation (Two-Step Process)

The workflow uses a **two-step process** to copy AMIs with gp2→gp3 conversion:

**Why two steps?**
The AWS `copy_image()` API does not accept the `BlockDeviceMappings` parameter. Volume type changes must be applied during AMI registration, not during copy.

**Step 1: Encrypted Copy** (Initiator Lambda - `initiator.py:initiate_ami_copy()`)
- Calls `copy_image()` with `Encrypted=True` (no BlockDeviceMappings)
- Creates encrypted snapshots using either:
  - AWS-managed encryption (`aws/ebs` key) - default
  - Customer-managed KMS key - if `KMS_KEY_ID` environment variable is set (required for cross-account sharing)
- Generates temporary AMI name with timestamp suffix
- Returns temp_ami_id to Step Functions state

**Step 2: Status Polling** (Status Checker Lambda - `status_checker.py`)
- Repeatedly called by Step Functions (every 5 minutes by default)
- Checks AMI state via `describe_images()`
- Returns `continue_waiting=true` if still pending
- Returns `ami_available=true` when ready
- Step Functions loops until available or failed

**Step 3: Re-register with gp3** (Finalizer Lambda - `finalizer.py:finalize_ami_copy()`)
- Retrieves temporary AMI's block device mappings and snapshots
- Modifies mappings to convert gp2→gp3 (`shared_utils.py:build_block_device_mappings_for_registration()`)
- Deregisters temporary AMI (snapshots are retained)
- Re-registers AMI using `register_image()` with modified mappings
- Preserves all AMI attributes: Architecture, RootDeviceName, VirtualizationType, EnaSupport, SriovNetSupport, BootMode, TpmSupport, UefiData, ImdsSupport
- Applies tags (including SourceAMI, SourceAMIUUID, CopiedBy, CopyDate, plus Red Hat API metadata)

The final AMI references the encrypted snapshots from Step 1 with gp3 volume types applied in the block device mappings.

### Automatic Tagging

All copied AMIs receive user-provided tags plus automatic tags:
- `SourceAMI` - Original AMI ID for tracking
- `SourceAMIUUID` - UUID extracted from source AMI name (if available)
- `CopiedBy` - Set to "ami-copier-lambda"
- `CopyDate` - ISO timestamp of copy operation

### Red Hat Image Builder API Integration

When `enable_redhat_api = true`, the Lambda function queries the Red Hat Image Builder API to enrich AMI tags with metadata. This solves the problem of Red Hat AMIs having generic names like `composer-api-{uuid}` with no description.

**Credential Storage Options**:
- **SSM Parameter Store (default)**: Stores client_id and client_secret as SecureString parameters (`main.tf:23-43`)
- **Secrets Manager (alternative)**: Stores credentials as JSON secret (`main.tf:46-65`)

**Authentication Flow** (`ami_copier.py:72-185`):
1. Retrieve Red Hat Service Account credentials from SSM Parameter Store or Secrets Manager
2. Exchange credentials for 15-minute access token via Red Hat SSO using OAuth2 client_credentials grant
3. Use access token for Image Builder API requests

**Service Account vs Offline Token**:
- **Service Account (recommended)**: Uses `client_id` and `client_secret`, not tied to user accounts, supports both SSM and Secrets Manager
  - Requires service account to be added to a User Access group with the **RHEL viewer** role
  - RHEL viewer role grants read-only access to RHEL Insights, including Image Builder API
- **Offline Token (legacy)**: User-based authentication, expires after 30 days of inactivity, only supported via Secrets Manager for backward compatibility

**Compose Lookup** (`ami_copier.py:124-174`):
- Queries `GET /composes?limit=100` to get recent composes
- Iterates through each compose to find one with matching AMI ID
- Returns compose data and status when match found

**Metadata Enrichment** (`ami_copier.py:203-258`):
Tags are enriched with:
- `ComposeId` - UUID of the Image Builder compose
- `ImageBuilderName` - Custom name from compose request
- `Distribution` - RHEL version (e.g., "rhel-9")
- `Architecture` - x86_64 or aarch64
- `ComposeCreatedAt` - ISO timestamp of compose creation
- `BlueprintId/BlueprintVersion` - If built from a blueprint
- `PackageCount` - Number of packages installed

**Graceful Degradation**:
- If credentials not configured, skips API integration
- If access token exchange fails, falls back to basic tagging
- If compose not found in API, uses basic tagging
- AMI copy always proceeds regardless of API availability

**Credential Storage** (`main.tf:22-65`):

*SSM Parameter Store (default)*:
- Created when `enable_redhat_api = true` and `redhat_credential_store = "ssm"`
- Stores two SecureString parameters: `/{name_prefix}/redhat/client-id` and `/{name_prefix}/redhat/client-secret`
- Lambda IAM policy grants `ssm:GetParameter` permission on both parameters
- Lower cost than Secrets Manager for simple credential storage

*Secrets Manager (alternative)*:
- Created when `enable_redhat_api = true` and `redhat_credential_store = "secretsmanager"`
- Stores credentials as JSON:
  - Service account: `{"client_id": "...", "client_secret": "..."}`
  - Legacy offline token: `{"offline_token": "..."}`
- Lambda IAM policy grants `secretsmanager:GetSecretValue` permission
- Better for organizations already using Secrets Manager

**Using Existing Secrets/Parameters** (New in v0.2.0):

To keep credentials out of Terraform state, the module supports referencing existing AWS Secrets Manager secrets or SSM parameters instead of creating new ones.

*Implementation Details*:

**Variables** (`variables.tf:144-248`):
- `existing_redhat_secret_arn` / `existing_redhat_secret_name` - For Secrets Manager
- `existing_redhat_client_id_param_arn` / `existing_redhat_client_id_param_name` - For SSM client ID
- `existing_redhat_client_secret_param_arn` / `existing_redhat_client_secret_param_name` - For SSM client secret
- Users can provide either ARN or name (or both) for flexibility

**Data Sources** (`main.tf:64-95`):
- `data.aws_secretsmanager_secret.existing_redhat_by_name` - Looks up secret by name
- `data.aws_secretsmanager_secret.existing_redhat_by_arn` - Looks up secret by ARN
- `data.aws_ssm_parameter.existing_client_id` - Looks up client ID parameter (extracts name from ARN if needed)
- `data.aws_ssm_parameter.existing_client_secret` - Looks up client secret parameter (extracts name from ARN if needed)
- Data sources only created when external references are provided

**Resource Resolution** (`main.tf:6-54`):
Locals determine which resource to use (priority order):
1. `local.using_existing_secret` / `local.using_existing_ssm` - Flags indicating external references
2. `local.redhat_secret_arn` / `local.redhat_secret_name` - Resolve to either external, data source, or created resource
3. `local.client_id_param_arn` / `local.client_id_param_name` - Same pattern for SSM parameters
4. `local.client_secret_param_arn` / `local.client_secret_param_name`

**Resource Creation Skipping** (`main.tf:104-148`):
- SSM parameters: Only create when `!local.using_existing_ssm`
- Secrets Manager: Only create when `!local.using_existing_secret`
- Prevents conflicts and duplicate resources

**Lambda Integration** (`main.tf:242-248`):
- Environment variables use locals instead of direct resource references
- `CLIENT_ID_PARAM = local.client_id_param_name` (works for both created and existing)
- `CLIENT_SECRET_PARAM = local.client_secret_param_name`
- `REDHAT_SECRET_NAME = local.redhat_secret_name`
- No Lambda code changes needed - function already uses env vars generically

**IAM Permissions** (`main.tf:204-217`):
- IAM policy uses locals for ARNs: `local.client_id_param_arn`, `local.client_secret_param_arn`, `local.redhat_secret_arn`
- Grants access to external resources just like created resources
- Works seamlessly whether resources are created or external

**Validation** (`validation.tf`):
Comprehensive validation ensures:
- Can't provide both ARN and name for the same resource
- When using SSM, must provide both client_id and client_secret references
- When `enable_redhat_api=true`, must provide credentials via one method (inline OR external)
- Can't mix inline credentials with external references
- External Secrets Manager references require `redhat_credential_store="secretsmanager"`
- External SSM references require `redhat_credential_store="ssm"`
- External references require `enable_redhat_api=true`

**Benefits**:
- Credentials never stored in Terraform state
- Supports credential rotation without Terraform changes
- Compatible with centralized secret management
- Maintains full backward compatibility
- Supports both Secrets Manager and SSM Parameter Store

## Module Usage Pattern

This module is designed to be instantiated multiple times for different RHEL versions:

```hcl
module "rhel9_copier" {
  source            = "./ami-copier"
  name_prefix       = "rhel9"
  ami_name_template = "rhel-9-encrypted-{date}"
  tags              = { Version = "9" }
}
```

Each instance creates its own Lambda function and EventBridge rule. The `name_prefix` variable ensures resource name uniqueness.

## Troubleshooting

### Scheduled Rule Not Running

- Check EventBridge rule status: `aws events describe-rule --name ${name_prefix}-ami-discovery`
- Verify rule is enabled: `aws events list-targets-by-rule --rule ${name_prefix}-ami-discovery`
- Check recent executions in CloudWatch Logs: `aws logs tail /aws/lambda/${name_prefix}-ami-copier --since 24h`

### No AMIs Being Discovered

- Verify Red Hat has shared AMIs with your account
- Test manually: `aws ec2 describe-images --owners 463606842039 --filters "Name=state,Values=available"`
- Check Lambda logs for "Found X available AMIs from Red Hat" message

### Lambda Errors

- Check CloudWatch Logs: `/aws/lambda/${name_prefix}-ami-copier`
- Common issues:
  - Source AMI not accessible (wrong region, permissions)
  - Lambda timeout - The two-step copy process waits up to 30 minutes for AMI copy to complete. Increase `lambda_timeout` variable if needed (default: 900 seconds, recommended minimum for large AMIs or API integration: 600-900 seconds)
  - IAM permission errors - Verify Lambda role has `ec2:DescribeImages`, `ec2:CopyImage`, `ec2:CreateTags`, `ec2:RegisterImage`, and `ec2:DeregisterImage` permissions (check inline policy in `main.tf:171-220`)

### Cleaning Up Orphaned Temporary AMIs

The two-step AMI copy process creates temporary AMIs that are normally cleaned up automatically. However, if the Lambda function times out or crashes before cleanup completes, temporary AMIs may be orphaned.

**Note:** The waiter can wait up to 30 minutes for AMI copy completion, but the default Lambda timeout is 15 minutes (900 seconds). This mismatch can cause timeouts for large AMIs.

**Identifying orphaned temporary AMIs:**

```bash
# List temporary AMIs created by ami-copier that should have been cleaned up
aws ec2 describe-images \
  --owners self \
  --filters "Name=name,Values=*-temp-*" \
  --query 'Images[*].[ImageId,Name,CreationDate]' \
  --output table
```

**Manual cleanup process:**

```bash
# 1. Find orphaned temporary AMIs (older than 1 hour)
# macOS (BSD date):
aws ec2 describe-images \
  --owners self \
  --filters "Name=name,Values=*-temp-*" \
  --query "Images[?CreationDate<='$(date -u -v-1H +%Y-%m-%dT%H:%M:%S.000Z)'].[ImageId,Name,CreationDate]" \
  --output table

# Linux (GNU date):
aws ec2 describe-images \
  --owners self \
  --filters "Name=name,Values=*-temp-*" \
  --query "Images[?CreationDate<='$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S.000Z)'].[ImageId,Name,CreationDate]" \
  --output table

# 2. Deregister a specific temporary AMI
aws ec2 deregister-image --image-id ami-xxxxx

# 3. Optionally delete the associated snapshots (if no longer needed)
# CAUTION: Only delete snapshots if you're sure they're not used by other AMIs
aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=description,Values=*temp-*" \
  --query 'Snapshots[*].[SnapshotId,Description,StartTime]' \
  --output table

# Delete snapshot
aws ec2 delete-snapshot --snapshot-id snap-xxxxx
```

**Preventive measures:**

- Increase `lambda_timeout` to 1800 seconds (30 minutes) if processing large AMIs
- Monitor CloudWatch Logs for timeout errors: `aws logs tail /aws/lambda/${name_prefix}-ami-copier --follow --filter-pattern "Task timed out"`
- Consider implementing a periodic cleanup Lambda function to deregister temp AMIs older than 2 hours

### Red Hat API Integration Issues

- **Service account authentication fails**:
  - Verify service account has been added to a User Access group with the **RHEL viewer** role in Red Hat Console
    - Navigate to console.redhat.com → Settings → User Access → Groups
    - Ensure the service account's group has the "RHEL viewer" role assigned
  - Check client_id and client_secret are correct in SSM/Secrets Manager
  - Service account credentials don't expire (unlike offline tokens)
  - Test API access manually: `curl -H "Authorization: Bearer $TOKEN" https://console.redhat.com/api/image-builder/v1/composes?limit=5`

- **Offline token expired** (legacy):
  - Offline tokens expire after 30 days of inactivity
  - Generate a new one at https://access.redhat.com/management/api and update Secrets Manager
  - Consider migrating to service account authentication

- **Compose not found**: AMI might be older than 100 most recent composes, or from a different Red Hat account

- **API timeout**: Increase `lambda_timeout` to 600 seconds when API integration is enabled

- **Credential retrieval fails**:
  - SSM: Check Lambda has `ssm:GetParameter` permission for both client_id and client_secret parameters
  - Secrets Manager: Check Lambda has `secretsmanager:GetSecretValue` permission
  - Verify credential store type matches what's configured (`REDHAT_CREDENTIAL_STORE` env var)

- **Check API calls in logs**:
  ```bash
  aws logs tail /aws/lambda/${name_prefix}-ami-copier --follow --filter-pattern "Image Builder"
  ```

- **Verify authentication method in use**:
  ```bash
  aws logs tail /aws/lambda/${name_prefix}-ami-copier --follow --filter-pattern "service account"
  ```

### Custom KMS Key Issues

- **KMS key permission errors**:
  - Verify Lambda IAM role has KMS permissions: `kms:Encrypt`, `kms:Decrypt`, `kms:ReEncrypt*`, `kms:GenerateDataKey*`, `kms:CreateGrant`, `kms:DescribeKey`
  - Check Lambda IAM policy includes the KMS key ARN in the Resource field
  - KMS key policy must grant permissions to the Lambda execution role

- **Cross-account AMI sharing not working**:
  - Verify you're using a customer-managed KMS key (AWS-managed keys cannot be shared)
  - Check KMS key policy grants permissions to target AWS account(s)
  - Target account needs: `kms:Decrypt`, `kms:DescribeKey`, `kms:CreateGrant` for launching instances
  - See [AWS Documentation: Sharing AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html)

- **Invalid KMS key format**:
  - Module accepts three formats: full ARN, key ID (UUID), or alias
  - ARN example: `arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012`
  - Key ID example: `12345678-1234-1234-1234-123456789012`
  - Alias example: `alias/my-ami-encryption-key`
  - Module automatically constructs full ARN for IAM policy if key ID or alias provided

- **Check KMS key usage in logs**:
  ```bash
  aws logs tail /aws/lambda/${name_prefix}-ami-copier-initiator --follow --filter-pattern "KMS"
  ```

- **Verify KMS key ARN in Terraform state**:
  ```bash
  terraform state show 'module.ami_copier.data.aws_region.current[0]'
  terraform state show 'module.ami_copier.data.aws_caller_identity.current[0]'
  ```
