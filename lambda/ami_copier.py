import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib import request, parse
from urllib.error import URLError, HTTPError

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ec2_client = boto3.client('ec2')
secretsmanager_client = boto3.client('secretsmanager')
ssm_client = boto3.client('ssm')


def get_block_device_mappings(source_ami_id: str) -> List[Dict[str, Any]]:
    """
    Get block device mappings from source AMI and convert gp2 to gp3.

    Args:
        source_ami_id: The source AMI ID

    Returns:
        List of modified block device mappings
    """
    try:
        response = ec2_client.describe_images(ImageIds=[source_ami_id])

        if not response['Images']:
            raise ValueError(f"AMI {source_ami_id} not found")

        source_image = response['Images'][0]
        block_device_mappings = source_image.get('BlockDeviceMappings', [])

        # Convert gp2 to gp3 in block device mappings
        modified_mappings = []
        for mapping in block_device_mappings:
            if 'Ebs' in mapping:
                ebs = mapping['Ebs'].copy()

                # Change gp2 to gp3
                if ebs.get('VolumeType') == 'gp2':
                    ebs['VolumeType'] = 'gp3'
                    logger.info(f"Converting volume type from gp2 to gp3 for device {mapping['DeviceName']}")

                # Remove SnapshotId as it will be copied from source
                ebs.pop('SnapshotId', None)
                # Remove Encrypted as we'll set it at the top level
                ebs.pop('Encrypted', None)

                modified_mappings.append({
                    'DeviceName': mapping['DeviceName'],
                    'Ebs': ebs
                })
            else:
                # Keep non-EBS mappings as-is
                modified_mappings.append(mapping)

        return modified_mappings, source_image

    except ClientError as e:
        logger.error(f"Error describing AMI {source_ami_id}: {e}")
        raise


def get_redhat_credentials() -> Optional[Dict[str, str]]:
    """
    Retrieve Red Hat API credentials from SSM Parameter Store or Secrets Manager.

    Returns:
        Dictionary with 'client_id' and 'client_secret' (or legacy 'offline_token') or None if not configured
    """
    credential_store = os.environ.get('REDHAT_CREDENTIAL_STORE', 'ssm')

    try:
        if credential_store == 'ssm':
            # Get credentials from SSM Parameter Store
            client_id_param = os.environ.get('CLIENT_ID_PARAM')
            client_secret_param = os.environ.get('CLIENT_SECRET_PARAM')

            if not client_id_param or not client_secret_param:
                logger.info("SSM parameter names not set, skipping Image Builder API integration")
                return None

            try:
                client_id_response = ssm_client.get_parameter(
                    Name=client_id_param,
                    WithDecryption=True
                )
                client_secret_response = ssm_client.get_parameter(
                    Name=client_secret_param,
                    WithDecryption=True
                )

                return {
                    'client_id': client_id_response['Parameter']['Value'],
                    'client_secret': client_secret_response['Parameter']['Value']
                }
            except Exception as e:
                logger.error(f"Failed to retrieve credentials from SSM Parameter Store: {e}")
                return None

        elif credential_store == 'secretsmanager':
            # Get credentials from Secrets Manager
            secret_name = os.environ.get('REDHAT_SECRET_NAME')
            if not secret_name:
                logger.info("REDHAT_SECRET_NAME not set, skipping Image Builder API integration")
                return None

            try:
                response = secretsmanager_client.get_secret_value(SecretId=secret_name)
                secret = json.loads(response['SecretString'])
                return secret
            except Exception as e:
                logger.error(f"Failed to retrieve credentials from Secrets Manager: {e}")
                return None
        else:
            logger.error(f"Unknown credential store type: {credential_store}")
            return None

    except Exception as e:
        logger.error(f"Failed to retrieve Red Hat credentials: {e}")
        return None


def get_access_token(credentials: Dict[str, str]) -> Optional[str]:
    """
    Get Red Hat API access token from credentials.

    Supports both service account (client_id/client_secret) and legacy offline token authentication.

    Args:
        credentials: Dictionary with either:
                    - 'client_id' and 'client_secret' for service account auth, or
                    - 'offline_token' for legacy user token auth

    Returns:
        Access token or None if authentication fails
    """
    try:
        # Service account authentication (preferred)
        if 'client_id' in credentials and 'client_secret' in credentials:
            logger.info("Using service account authentication")
            data = parse.urlencode({
                'grant_type': 'client_credentials',
                'client_id': credentials['client_id'],
                'client_secret': credentials['client_secret'],
                'scope': 'api.console'
            }).encode('utf-8')

        # Legacy offline token authentication (backward compatibility)
        elif 'offline_token' in credentials:
            logger.info("Using offline token authentication (legacy)")
            data = parse.urlencode({
                'grant_type': 'refresh_token',
                'client_id': 'rhsm-api',
                'refresh_token': credentials['offline_token']
            }).encode('utf-8')

        else:
            logger.error("Invalid credentials format: must contain either (client_id, client_secret) or offline_token")
            return None

        req = request.Request(
            'https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        with request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            access_token = result.get('access_token')
            if access_token:
                logger.info("Successfully obtained access token")
            return access_token

    except (URLError, HTTPError) as e:
        logger.error(f"Failed to get access token: {e}")
        return None


def find_compose_by_ami(ami_id: str, access_token: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """
    Find Image Builder compose by AMI ID.

    Args:
        ami_id: AMI ID to search for
        access_token: Red Hat API access token

    Returns:
        Tuple of (compose_data, compose_status) or None if not found
    """
    base_url = 'https://console.redhat.com/api/image-builder/v1'

    try:
        # Search recent composes (limit to 100 most recent)
        req = request.Request(
            f'{base_url}/composes?limit=100',
            headers={'Authorization': f'Bearer {access_token}'}
        )

        with request.urlopen(req, timeout=30) as response:
            composes_response = json.loads(response.read().decode('utf-8'))
            composes = composes_response.get('data', [])

        # Check each compose for matching AMI
        for compose in composes:
            compose_id = compose['id']

            # Get detailed status
            req = request.Request(
                f'{base_url}/composes/{compose_id}',
                headers={'Authorization': f'Bearer {access_token}'}
            )

            with request.urlopen(req, timeout=10) as response:
                status = json.loads(response.read().decode('utf-8'))

            # Check if this compose produced the AMI we're looking for
            upload_status = status.get('image_status', {}).get('upload_status', {})
            options = upload_status.get('options', {})

            if options.get('ami') == ami_id:
                logger.info(f"Found matching compose: {compose_id}")
                return compose, status

        logger.warning(f"No compose found for AMI {ami_id}")
        return None

    except Exception as e:
        logger.error(f"Error searching for compose: {e}")
        return None


def get_compose_metadata(compose_id: str, access_token: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed metadata for a compose.

    Args:
        compose_id: Compose UUID
        access_token: Red Hat API access token

    Returns:
        Metadata dictionary or None if retrieval fails
    """
    try:
        req = request.Request(
            f'https://console.redhat.com/api/image-builder/v1/composes/{compose_id}/metadata',
            headers={'Authorization': f'Bearer {access_token}'}
        )

        with request.urlopen(req, timeout=10) as response:
            metadata = json.loads(response.read().decode('utf-8'))
            return metadata

    except Exception as e:
        logger.error(f"Error retrieving compose metadata: {e}")
        return None


def enrich_tags_from_compose(tags: Dict[str, str], compose: Dict[str, Any], status: Dict[str, Any], metadata: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Enrich tags with metadata from Image Builder compose.

    Args:
        tags: Base tags
        compose: Compose data from /composes
        status: Compose status from /composes/{id}
        metadata: Compose metadata from /composes/{id}/metadata

    Returns:
        Enriched tags dictionary
    """
    enriched = tags.copy()

    # Add compose ID for reference
    enriched['ComposeId'] = compose.get('id', 'unknown')

    # Add image name from compose request if available
    request_data = status.get('request', {})
    if request_data.get('image_name'):
        enriched['ImageBuilderName'] = request_data['image_name'][:255]  # Tag value limit

    # Add distribution
    distribution = request_data.get('distribution')
    if distribution:
        enriched['Distribution'] = distribution

    # Add architecture
    image_requests = request_data.get('image_requests', [])
    if image_requests:
        arch = image_requests[0].get('architecture')
        if arch:
            enriched['Architecture'] = arch

    # Add creation date
    created_at = compose.get('created_at')
    if created_at:
        enriched['ComposeCreatedAt'] = created_at

    # Add blueprint info if available
    blueprint_id = compose.get('blueprint_id')
    if blueprint_id:
        enriched['BlueprintId'] = str(blueprint_id)

    blueprint_version = compose.get('blueprint_version')
    if blueprint_version:
        enriched['BlueprintVersion'] = str(blueprint_version)

    # Add package count from metadata
    if metadata:
        packages = metadata.get('packages', [])
        if packages:
            enriched['PackageCount'] = str(len(packages))

    return enriched


def generate_ami_name(template: str, source_image: Dict[str, Any]) -> str:
    """
    Generate AMI name from template.

    Args:
        template: Name template with placeholders
        source_image: Source AMI metadata

    Returns:
        Generated AMI name
    """
    source_name = source_image.get('Name', 'unknown')
    creation_date = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

    # Replace placeholders
    name = template.replace('{source_name}', source_name)
    name = name.replace('{date}', creation_date)
    name = name.replace('{timestamp}', str(int(datetime.utcnow().timestamp())))

    return name


def copy_ami(source_ami_id: str, ami_name: str, tags: Dict[str, str]) -> str:
    """
    Copy AMI with encryption and gp3 volumes.

    Args:
        source_ami_id: Source AMI ID to copy
        ami_name: Name for the new AMI
        tags: Tags to apply to the AMI and snapshots

    Returns:
        The new AMI ID
    """
    try:
        # Get source AMI details and modify block device mappings
        block_device_mappings, source_image = get_block_device_mappings(source_ami_id)

        logger.info(f"Copying AMI {source_ami_id} as {ami_name}")

        # Copy the AMI with encryption enabled
        response = ec2_client.copy_image(
            Name=ami_name,
            SourceImageId=source_ami_id,
            SourceRegion=os.environ['AWS_REGION'],
            Encrypted=True,  # Enable encryption with default AWS managed key
            Description=f"Encrypted gp3 copy of {source_image.get('Description', source_ami_id)}",
            BlockDeviceMappings=block_device_mappings
        )

        new_ami_id = response['ImageId']
        logger.info(f"Started AMI copy. New AMI ID: {new_ami_id}")

        # Tag the new AMI
        if tags:
            # Add source AMI ID to tags for tracking
            all_tags = tags.copy()
            all_tags['SourceAMI'] = source_ami_id
            all_tags['CopiedBy'] = 'ami-copier-lambda'
            all_tags['CopyDate'] = datetime.utcnow().isoformat()

            tag_list = [{'Key': k, 'Value': v} for k, v in all_tags.items()]

            ec2_client.create_tags(
                Resources=[new_ami_id],
                Tags=tag_list
            )
            logger.info(f"Applied tags to AMI {new_ami_id}")

            # Wait for the AMI to become available so we can tag the snapshots
            # Note: We do this asynchronously - the Lambda will complete before the AMI is ready
            # But we can tag the AMI itself immediately

        return new_ami_id

    except ClientError as e:
        logger.error(f"Error copying AMI {source_ami_id}: {e}")
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for AMI copy automation.

    Triggered by EventBridge when an AMI is shared with the account.

    Args:
        event: EventBridge event
        context: Lambda context

    Returns:
        Response dictionary
    """
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Extract AMI ID from the event
        # EventBridge event structure for ModifyImageAttribute
        detail = event.get('detail', {})
        request_parameters = detail.get('requestParameters', {})

        source_ami_id = request_parameters.get('imageId')

        if not source_ami_id:
            logger.error("No AMI ID found in event")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No AMI ID in event'})
            }

        # Get configuration from environment variables
        ami_name_template = os.environ.get('AMI_NAME_TEMPLATE', '{source_name}-encrypted-gp3-{date}')
        tags_json = os.environ.get('TAGS', '{}')
        tags = json.loads(tags_json)

        # Get source image details for name generation
        response = ec2_client.describe_images(ImageIds=[source_ami_id])
        if not response['Images']:
            logger.error(f"Source AMI {source_ami_id} not found")
            return {
                'statusCode': 404,
                'body': json.dumps({'error': f'AMI {source_ami_id} not found'})
            }

        source_image = response['Images'][0]
        ami_name = generate_ami_name(ami_name_template, source_image)

        # Try to enrich tags from Image Builder API
        credentials = get_redhat_credentials()
        if credentials:
            logger.info("Attempting to retrieve metadata from Image Builder API")
            access_token = get_access_token(credentials)

            if access_token:
                compose_result = find_compose_by_ami(source_ami_id, access_token)

                if compose_result:
                    compose, status = compose_result
                    metadata = get_compose_metadata(compose['id'], access_token)
                    tags = enrich_tags_from_compose(tags, compose, status, metadata)
                    logger.info(f"Enriched tags with Image Builder metadata: {list(tags.keys())}")
                else:
                    logger.warning("Could not find compose in Image Builder API, using basic tags")
            else:
                logger.warning("Failed to get access token, using basic tags")
        else:
            logger.info("Red Hat API credentials not configured, using basic tags")

        # Copy the AMI
        new_ami_id = copy_ami(source_ami_id, ami_name, tags)

        logger.info(f"Successfully initiated copy of {source_ami_id} to {new_ami_id}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'AMI copy initiated successfully',
                'sourceAMI': source_ami_id,
                'newAMI': new_ami_id,
                'name': ami_name
            })
        }

    except Exception as e:
        logger.error(f"Error processing event: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
