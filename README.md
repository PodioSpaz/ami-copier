# AMI Auto-Copier for Red Hat Image Builder

Terraform module that automatically copies AMIs shared by Red Hat Image Builder, converting gp2 volumes to gp3 and enabling encryption.

## Overview

Red Hat Image Builder produces AMIs with unencrypted gp2 root volumes. This module solves that by:

1. Detecting when an AMI is shared with your AWS account (via EventBridge)
2. Automatically triggering a Lambda function
3. Copying the AMI with:
   - All volumes converted from gp2 to gp3
   - Encryption enabled using AWS managed keys
   - Custom naming and tagging

## Architecture

```
Red Hat Image Builder shares AMI
            |
            v
    EventBridge Rule (ModifyImageAttribute)
            |
            v
     Lambda Function
            |
            v
    Copy AMI with gp3 + encryption
            |
            v
    Tagged encrypted AMI
```

## Requirements

- Terraform >= 1.0
- AWS Provider >= 5.0
- AWS CloudTrail must be enabled (for EventBridge to detect AMI sharing events)

## Quick Start

```hcl
module "ami_copier" {
  source = "path/to/ami-copier"

  name_prefix        = "rhel"
  ami_name_template  = "rhel-9-encrypted-{date}"

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    OS          = "RHEL"
  }
}
```

## Usage

### Basic Example

```hcl
module "ami_copier" {
  source = "./ami-copier"

  name_prefix = "rhel"

  tags = {
    Project = "my-project"
  }
}
```

### Custom Naming

The `ami_name_template` variable supports placeholders:

- `{source_name}` - Original AMI name (e.g., "composer-api-5bc3b908...")
- `{date}` - Current date/time (format: YYYYMMDD-HHMMSS)
- `{timestamp}` - Unix timestamp

```hcl
module "ami_copier" {
  source = "./ami-copier"

  ami_name_template = "rhel-{date}-encrypted-gp3"
  # Result: rhel-20250122-143022-encrypted-gp3
}
```

### Multiple RHEL Versions

To differentiate between RHEL 9 and RHEL 10:

```hcl
module "rhel9_ami_copier" {
  source = "./ami-copier"

  name_prefix       = "rhel9"
  ami_name_template = "rhel-9-encrypted-{date}"

  tags = {
    OS      = "RHEL"
    Version = "9"
  }
}

module "rhel10_ami_copier" {
  source = "./ami-copier"

  name_prefix       = "rhel10"
  ami_name_template = "rhel-10-encrypted-{date}"

  tags = {
    OS      = "RHEL"
    Version = "10"
  }
}
```

### Longer Lambda Timeout

For large AMIs that take longer to copy:

```hcl
module "ami_copier" {
  source = "./ami-copier"

  lambda_timeout = 600  # 10 minutes
}
```

### Red Hat Image Builder API Integration (Enhanced Tagging)

By default, Red Hat Image Builder AMIs have generic names like `composer-api-5bc3b908-8cdd-489c-ab2f-cfaff7dc972e` with no description, making it difficult to identify them. Enable API integration to enrich AMI tags with metadata from Red Hat Image Builder:

**Benefits:**
- **ComposeId** - Links AMI to specific Image Builder compose
- **ImageBuilderName** - Custom name from compose request
- **Distribution** - RHEL version (e.g., "rhel-9", "rhel-10")
- **Architecture** - x86_64 or aarch64
- **ComposeCreatedAt** - When the image was built
- **BlueprintId/BlueprintVersion** - If built from a blueprint
- **PackageCount** - Number of packages in the image

**Setup:**

1. Get a Red Hat offline token from https://access.redhat.com/management/api
2. Enable API integration in your module:

```hcl
module "ami_copier" {
  source = "./ami-copier"

  name_prefix       = "rhel9"
  ami_name_template = "rhel-9-encrypted-{date}"

  # Enable Red Hat API integration
  enable_redhat_api   = true
  redhat_offline_token = var.redhat_offline_token  # Store in terraform.tfvars (gitignored)

  tags = {
    Environment = "production"
  }
}
```

3. Store your offline token securely:

```bash
# In terraform.tfvars (add to .gitignore!)
redhat_offline_token = "your-offline-token-here"
```

**How it works:**
- Lambda queries the Image Builder API to find the compose that produced the AMI
- Enriches tags with metadata like distribution, architecture, package count
- Falls back to basic tagging if API is unavailable
- Offline token is stored in AWS Secrets Manager

**Note:** The Lambda timeout may need to be increased to 600 seconds when API integration is enabled, as it makes multiple HTTP requests to Red Hat's API.

## How It Works

### Event Detection

The module creates an EventBridge rule that matches this pattern:

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["ModifyImageAttribute"],
    "requestParameters": {
      "launchPermission": {
        "add": {
          "items": [{
            "userId": ["YOUR_ACCOUNT_ID"]
          }]
        }
      }
    }
  }
}
```

When Red Hat Image Builder shares an AMI with your account, it calls `ModifyImageAttribute` to add your account ID to the AMI's launch permissions. This triggers the EventBridge rule.

### Lambda Function

The Lambda function (`lambda/ami_copier.py`):

1. Receives the EventBridge event with the source AMI ID
2. Describes the source AMI to get block device mappings
3. Converts all gp2 volumes to gp3
4. Copies the AMI with:
   - `Encrypted=True` (using AWS managed key)
   - Modified block device mappings (gp3)
   - Generated name from template
5. Tags the new AMI with:
   - User-provided tags
   - `SourceAMI` - ID of the original AMI
   - `CopiedBy` - Set to "ami-copier-lambda"
   - `CopyDate` - ISO timestamp

### Permissions

The Lambda function requires these IAM permissions:

- `ec2:DescribeImages` - Read source AMI details
- `ec2:CopyImage` - Copy the AMI
- `ec2:CreateTags` - Tag the copied AMI
- `ec2:DescribeSnapshots` - List snapshots
- `logs:*` - CloudWatch Logs

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| name_prefix | Prefix for naming resources | string | "rhel" | no |
| ami_name_template | Template for AMI names (supports {source_name}, {date}, {timestamp}) | string | "{source_name}-encrypted-gp3-{date}" | no |
| tags | Tags to apply to copied AMIs and resources | map(string) | {} | no |
| lambda_timeout | Lambda timeout in seconds (60-900) | number | 300 | no |
| lambda_memory_size | Lambda memory in MB (128-10240) | number | 256 | no |
| log_retention_days | CloudWatch Logs retention period | number | 7 | no |
| enable_redhat_api | Enable Red Hat Image Builder API integration for enhanced tagging | bool | false | no |
| redhat_offline_token | Red Hat offline token for API authentication (required if enable_redhat_api=true) | string (sensitive) | "" | no |

## Outputs

| Name | Description |
|------|-------------|
| lambda_function_arn | ARN of the Lambda function |
| lambda_function_name | Name of the Lambda function |
| lambda_role_arn | ARN of the Lambda IAM role |
| eventbridge_rule_arn | ARN of the EventBridge rule |
| eventbridge_rule_name | Name of the EventBridge rule |
| cloudwatch_log_group_name | CloudWatch Log Group name |
| redhat_api_secret_arn | ARN of the Secrets Manager secret (if API integration enabled) |

## Troubleshooting

### AMI Not Being Copied

1. Check CloudTrail is enabled in your region
2. Check EventBridge rule is enabled:
   ```bash
   aws events describe-rule --name <rule-name>
   ```
3. Check Lambda logs:
   ```bash
   aws logs tail /aws/lambda/<function-name> --follow
   ```

### Lambda Timeout

If copying large AMIs:
- Increase `lambda_timeout` (up to 900 seconds)
- Note: AMI copy is asynchronous - Lambda initiates the copy and completes

### Finding Copied AMIs

```bash
aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:CopiedBy,Values=ami-copier-lambda"
```

## Cost Considerations

- **Lambda**: Free tier covers most usage (1M requests/month, 400,000 GB-seconds)
- **CloudWatch Logs**: Minimal (~$0.50/GB ingested)
- **EBS Snapshots**: You pay for snapshot storage of copied AMIs
- **EventBridge**: Free for AWS service events

The original AMI shared by Red Hat is:
- Owned by Red Hat (not your account)
- Available for 14 days
- Does not incur storage costs to you
- Cannot be deregistered by you

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

## Authors

Created for automating Red Hat Image Builder AMI workflows.
