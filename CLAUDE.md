# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Terraform module that automatically copies AMIs shared by Red Hat Image Builder, converting unencrypted gp2 volumes to encrypted gp3 volumes. The module is designed to be reusable and can be deployed by others.

## Architecture

The module uses an event-driven architecture:

1. **EventBridge Rule** (`main.tf:98-123`) - Monitors CloudTrail for `ModifyImageAttribute` API calls, which occur when Red Hat Image Builder shares an AMI with the account
2. **Lambda Function** (`lambda/ami_copier.py`) - Triggered by EventBridge, copies the AMI with modified settings
3. **IAM Role & Policies** (`main.tf:21-70`) - Grants Lambda permissions for EC2 operations and CloudWatch logging

The Lambda function receives EventBridge events, extracts the source AMI ID, modifies block device mappings (gp2→gp3), and initiates an encrypted AMI copy using `ec2:CopyImage`.

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

The Lambda function can be tested manually without deploying the full module:

```bash
# Invoke Lambda with test event (after deployment)
aws lambda invoke \
  --function-name <function-name> \
  --payload '{"detail":{"requestParameters":{"imageId":"ami-xxxxx"}}}' \
  response.json

# View Lambda logs
aws logs tail /aws/lambda/<function-name> --follow
```

### Finding Copied AMIs

```bash
# List all AMIs copied by this module
aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:CopiedBy,Values=ami-copier-lambda"
```

## Key Implementation Details

### EventBridge Event Pattern

The module requires AWS CloudTrail to be enabled. The EventBridge rule in `main.tf:103-120` listens for `ModifyImageAttribute` events where launch permissions are added for the current AWS account ID.

### Lambda Environment Variables

Configuration is passed to the Lambda function via environment variables (`main.tf:83-88`):
- `AMI_NAME_TEMPLATE` - Template string with placeholders: `{source_name}`, `{date}`, `{timestamp}`
- `TAGS` - JSON-encoded map of tags to apply to copied AMIs

### Block Device Mapping Transformation

The Lambda function (`ami_copier.py:18-61`) retrieves the source AMI's block device mappings and:
1. Changes all `gp2` volumes to `gp3`
2. Removes `SnapshotId` (will be copied from source)
3. Removes `Encrypted` flag (set at top level in CopyImage call)

The actual AMI copy operation uses `Encrypted=True` which applies AWS-managed encryption (`aws/ebs` key) to all volumes.

### Automatic Tagging

All copied AMIs receive user-provided tags plus three automatic tags (`ami_copier.py:124-127`):
- `SourceAMI` - Original AMI ID for tracking
- `CopiedBy` - Set to "ami-copier-lambda"
- `CopyDate` - ISO timestamp of copy operation

### Red Hat Image Builder API Integration

When `enable_redhat_api = true`, the Lambda function queries the Red Hat Image Builder API to enrich AMI tags with metadata. This solves the problem of Red Hat AMIs having generic names like `composer-api-{uuid}` with no description.

**Authentication Flow** (`ami_copier.py:71-121`):
1. Retrieve Red Hat offline token from AWS Secrets Manager
2. Exchange offline token for 15-minute access token via Red Hat SSO
3. Use access token for Image Builder API requests

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
- If Secrets Manager secret not configured, skips API integration
- If access token exchange fails, falls back to basic tagging
- If compose not found in API, uses basic tagging
- AMI copy always proceeds regardless of API availability

**Secrets Manager** (`main.tf:22-39`):
- Created only when `enable_redhat_api = true`
- Stores offline token as JSON: `{"offline_token": "..."}`
- Lambda IAM policy grants `secretsmanager:GetSecretValue` permission

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

### EventBridge Not Triggering

- Verify CloudTrail is enabled in the region
- Check EventBridge rule status: `aws events describe-rule --name <rule-name>`
- Review CloudTrail events for `ModifyImageAttribute` calls

### Lambda Errors

- Check CloudWatch Logs: `/aws/lambda/${name_prefix}-ami-copier`
- Common issues:
  - Source AMI not accessible (wrong region, permissions)
  - Lambda timeout (increase `lambda_timeout` variable for large AMIs or when using API integration)
  - IAM permission errors (check inline policy in `main.tf:61-98`)

### Red Hat API Integration Issues

- **Token expired**: Offline tokens expire after 30 days of inactivity. Generate a new one and update Secrets Manager
- **Compose not found**: AMI might be older than 100 most recent composes, or from a different Red Hat account
- **API timeout**: Increase `lambda_timeout` to 600 seconds when API integration is enabled
- **Check API calls in logs**:
  ```bash
  aws logs filter-pattern /aws/lambda/${name_prefix}-ami-copier --filter-pattern "Image Builder"
  ```
