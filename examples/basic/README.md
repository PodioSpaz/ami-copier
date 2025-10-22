# Basic Example

This example demonstrates how to use the ami-copier module.

## Usage

```bash
terraform init
terraform plan
terraform apply
```

## Testing

After deployment, you can test by:

1. Having Red Hat Image Builder share an AMI with your account
2. Monitoring the Lambda logs:
   ```bash
   aws logs tail /aws/lambda/rhel-ami-copier --follow
   ```
3. Checking for the copied AMI:
   ```bash
   aws ec2 describe-images \
     --owners self \
     --filters "Name=tag:CopiedBy,Values=ami-copier-lambda"
   ```

## Manual Testing

You can also invoke the Lambda function manually with a test event:

```bash
aws lambda invoke \
  --function-name rhel-ami-copier \
  --payload '{
    "detail": {
      "eventName": "ModifyImageAttribute",
      "requestParameters": {
        "imageId": "ami-xxxxxxxxxxxxxxxxx"
      }
    }
  }' \
  response.json

cat response.json
```

Replace `ami-xxxxxxxxxxxxxxxxx` with an actual AMI ID that your account has access to.

## Cleanup

```bash
terraform destroy
```

Note: This will not delete any AMIs that were already copied. To clean those up:

```bash
# List copied AMIs
aws ec2 describe-images \
  --owners self \
  --filters "Name=tag:CopiedBy,Values=ami-copier-lambda" \
  --query 'Images[*].[ImageId,Name,CreationDate]' \
  --output table

# Deregister an AMI (replace with actual AMI ID)
aws ec2 deregister-image --image-id ami-xxxxxxxxxxxxxxxxx

# Delete associated snapshots
aws ec2 describe-snapshots \
  --owner-ids self \
  --filters "Name=tag:CopiedBy,Values=ami-copier-lambda" \
  --query 'Snapshots[*].[SnapshotId,StartTime]' \
  --output table

aws ec2 delete-snapshot --snapshot-id snap-xxxxxxxxxxxxxxxxx
```
