# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Terraform module that automatically copies AMIs shared by Red Hat Image Builder, converting unencrypted gp2 volumes to encrypted gp3 volumes. The module is designed to be reusable and can be deployed by others.

## Architecture

The module uses a **scheduled polling architecture**:

1. **EventBridge Scheduled Rule** (`main.tf:177-184`) - Triggers Lambda every 12 hours (configurable) to discover shared AMIs
2. **Lambda Function** (`lambda/ami_copier.py`) - Polls for shared Red Hat AMIs and copies them with modified settings
3. **IAM Role & Policies** (`main.tf:67-137`) - Grants Lambda permissions for EC2 operations and CloudWatch logging

**Why polling instead of event-driven?**

The initial design used EventBridge to monitor `ModifyImageAttribute` API calls via CloudTrail. However, these events are generated in the **creator account** (Red Hat's AWS account), not the consumer account where this module is deployed. See [AWS documentation](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/monitor-use-of-a-shared-amazon-machine-image-across-multiple-aws-accounts.html) for details.

The Lambda function:
- Queries `DescribeImages` with owner filter `463606842039` (Red Hat's AWS account ID)
- Extracts UUID from AMI name pattern: `composer-api-{uuid}`
- Checks if AMI already copied (deduplication by name)
- Modifies block device mappings (gp2→gp3)
- Initiates an encrypted AMI copy using `ec2:CopyImage`

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

### Testing the Lambda Function

The Lambda function supports two invocation modes:

**Scheduled Mode** (automatic discovery):
```bash
# Manually trigger the scheduled discovery (scans all Red Hat AMIs)
aws lambda invoke \
  --function-name <function-name> \
  --payload '{}' \
  response.json

# View the response
cat response.json | jq

# Expected response includes summary and results for each AMI found
```

**Manual Mode** (specific AMI):
```bash
# Process a specific AMI on-demand
aws lambda invoke \
  --function-name <function-name> \
  --payload '{"source_ami_id":"ami-xxxxx"}' \
  response.json

# View the response
cat response.json | jq
```

**View Lambda Logs**:
```bash
# Follow logs in real-time
aws logs tail /aws/lambda/<function-name> --follow

# Check scheduled runs
aws logs tail /aws/lambda/<function-name> \
  --since 1h \
  --filter-pattern "Scheduled polling mode"
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

The EventBridge scheduled rule (`main.tf:177-184`) triggers the Lambda function on a configurable schedule (default: every 12 hours). The Lambda queries `DescribeImages` filtering by Red Hat's AWS account ID (`463606842039`) to discover shared AMIs.

### Deduplication Strategy

To prevent copying the same AMI multiple times:

1. **UUID Extraction** - Parses Red Hat AMI name pattern: `composer-api-{uuid}`
2. **Name-based Check** - Generates target AMI name using template (includes UUID)
3. **Existence Check** - Queries `DescribeImages` (owner: self) for AMIs with that name
4. **Skip if Found** - Logs skip message and moves to next AMI

The `{uuid}` placeholder in `ami_name_template` ensures uniqueness across copies.

### Lambda Environment Variables

Configuration is passed to the Lambda function via environment variables:
- `AMI_NAME_TEMPLATE` - Template string with placeholders: `{source_name}`, `{uuid}`, `{date}`, `{timestamp}`
- `TAGS` - JSON-encoded map of tags to apply to copied AMIs

### Block Device Mapping Transformation

The Lambda function (`ami_copier.py:18-61`) retrieves the source AMI's block device mappings and:
1. Changes all `gp2` volumes to `gp3`
2. Removes `SnapshotId` (will be copied from source)
3. Removes `Encrypted` flag (set at top level in CopyImage call)

The actual AMI copy operation uses `Encrypted=True` which applies AWS-managed encryption (`aws/ebs` key) to all volumes.

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
  - Lambda timeout (increase `lambda_timeout` variable for large AMIs or when using API integration)
  - IAM permission errors (check inline policy in `main.tf:61-98`)

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
