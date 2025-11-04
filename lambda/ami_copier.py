import json
import logging
import os
import re
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

# Red Hat AWS Account ID
REDHAT_ACCOUNT_ID = '463606842039'


def get_source_ami_details(source_ami_id: str) -> Dict[str, Any]:
    """
    Get source AMI details.

    Args:
        source_ami_id: The source AMI ID

    Returns:
        Source AMI metadata
    """
    try:
        response = ec2_client.describe_images(ImageIds=[source_ami_id])

        if not response['Images']:
            raise ValueError(f"AMI {source_ami_id} not found")

        return response['Images'][0]

    except ClientError as e:
        logger.error(f"Error describing AMI {source_ami_id}: {e}")
        raise


def build_block_device_mappings_for_registration(block_device_mappings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build block device mappings for AMI registration with gp2->gp3 conversion.

    This function takes block device mappings from an existing AMI and modifies them
    for re-registration, converting gp2 volumes to gp3.

    Args:
        block_device_mappings: Original block device mappings from copied AMI

    Returns:
        List of modified block device mappings for register_image()
    """
    modified_mappings = []

    for mapping in block_device_mappings:
        if 'Ebs' in mapping:
            ebs = mapping['Ebs'].copy()

            # Change gp2 to gp3
            original_type = ebs.get('VolumeType', 'gp2')
            if original_type == 'gp2':
                ebs['VolumeType'] = 'gp3'
                logger.info(f"Converting volume type from gp2 to gp3 for device {mapping['DeviceName']}")

            # Remove Encrypted flag - encryption is inherited from the snapshot
            # Specifying Encrypted when using existing snapshot IDs causes an error
            ebs.pop('Encrypted', None)

            modified_mappings.append({
                'DeviceName': mapping['DeviceName'],
                'Ebs': ebs
            })
        else:
            # Keep non-EBS mappings as-is
            modified_mappings.append(mapping)

    return modified_mappings


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


def extract_uuid_from_ami_name(ami_name: str) -> Optional[str]:
    """
    Extract UUID from Red Hat AMI name pattern: composer-api-{uuid}

    Args:
        ami_name: AMI name to parse

    Returns:
        UUID string or None if pattern doesn't match
    """
    # Pattern: composer-api-{uuid}
    # UUID format: 8-4-4-4-12 hex characters
    pattern = r'composer-api-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    match = re.search(pattern, ami_name, re.IGNORECASE)

    if match:
        return match.group(1)

    logger.warning(f"Could not extract UUID from AMI name: {ami_name}")
    return None


def generate_ami_name(template: str, source_image: Dict[str, Any], uuid: Optional[str] = None) -> str:
    """
    Generate AMI name from template.

    Args:
        template: Name template with placeholders
        source_image: Source AMI metadata
        uuid: Optional UUID extracted from source AMI name

    Returns:
        Generated AMI name
    """
    source_name = source_image.get('Name', 'unknown')
    creation_date = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

    # Replace placeholders
    name = template.replace('{source_name}', source_name)
    name = name.replace('{date}', creation_date)
    name = name.replace('{timestamp}', str(int(datetime.utcnow().timestamp())))

    # Add UUID placeholder support
    if uuid:
        name = name.replace('{uuid}', uuid)
    else:
        # Remove {uuid} placeholder if no UUID available
        name = name.replace('{uuid}', 'no-uuid')

    return name


def discover_shared_amis() -> List[Dict[str, Any]]:
    """
    Discover AMIs shared by Red Hat Image Builder.

    Returns:
        List of AMI metadata dictionaries
    """
    try:
        logger.info(f"Discovering AMIs shared by Red Hat (account {REDHAT_ACCOUNT_ID})")

        response = ec2_client.describe_images(
            Owners=[REDHAT_ACCOUNT_ID],
            Filters=[
                {
                    'Name': 'state',
                    'Values': ['available']
                }
            ]
        )

        amis = response.get('Images', [])
        logger.info(f"Found {len(amis)} available AMIs from Red Hat")

        return amis

    except ClientError as e:
        logger.error(f"Error discovering shared AMIs: {e}")
        raise


def ami_already_copied(ami_name: str) -> bool:
    """
    Check if an AMI with the given name already exists in this account.

    Args:
        ami_name: Name of the AMI to check

    Returns:
        True if AMI exists, False otherwise
    """
    try:
        response = ec2_client.describe_images(
            Owners=['self'],
            Filters=[
                {
                    'Name': 'name',
                    'Values': [ami_name]
                }
            ]
        )

        exists = len(response.get('Images', [])) > 0

        if exists:
            logger.info(f"AMI with name '{ami_name}' already exists, skipping copy")

        return exists

    except ClientError as e:
        logger.error(f"Error checking for existing AMI: {e}")
        # On error, return False to allow copy attempt (fail safe)
        return False


def copy_ami(source_ami_id: str, ami_name: str, tags: Dict[str, str], uuid: Optional[str] = None) -> str:
    """
    Copy AMI with encryption and gp3 volumes using a two-step process.

    Step 1: Copy the AMI with encryption (creates encrypted snapshots)
    Step 2: Re-register the AMI with modified block device mappings (gp2->gp3)

    This two-step approach is necessary because the EC2 copy_image() API does not
    accept the BlockDeviceMappings parameter.

    Args:
        source_ami_id: Source AMI ID to copy
        ami_name: Name for the new AMI
        tags: Tags to apply to the AMI and snapshots
        uuid: Optional UUID extracted from source AMI name

    Returns:
        The final AMI ID with gp3 volumes
    """
    temp_ami_id = None
    try:
        # Get source AMI details
        source_image = get_source_ami_details(source_ami_id)

        logger.info(f"Starting two-step AMI copy process for {source_ami_id}")
        logger.info(f"Step 1: Copying AMI with encryption (temporary copy)")

        # Step 1: Copy the AMI with encryption (no BlockDeviceMappings parameter)
        temp_ami_name = f"{ami_name}-temp-{int(datetime.utcnow().timestamp())}"
        response = ec2_client.copy_image(
            Name=temp_ami_name,
            SourceImageId=source_ami_id,
            SourceRegion=os.environ['AWS_REGION'],
            Encrypted=True,  # Enable encryption with default AWS managed key
            Description=f"Temporary encrypted copy of {source_image.get('Description', source_ami_id)}"
        )

        temp_ami_id = response['ImageId']
        logger.info(f"Temporary AMI created: {temp_ami_id}. Waiting for copy to complete...")

        # Step 2: Wait for the temporary AMI to become available
        waiter = ec2_client.get_waiter('image_available')
        waiter.wait(
            ImageIds=[temp_ami_id],
            WaiterConfig={
                'Delay': 30,  # Check every 30 seconds
                'MaxAttempts': 60  # 30 minutes maximum (60 * 30s = 1800s)
            }
        )
        logger.info(f"Temporary AMI {temp_ami_id} is now available")

        # Step 3: Get the temporary AMI's details
        temp_image = get_source_ami_details(temp_ami_id)

        # Build modified block device mappings with gp3
        original_mappings = temp_image.get('BlockDeviceMappings', [])
        modified_mappings = build_block_device_mappings_for_registration(original_mappings)

        logger.info(f"Step 2: Deregistering temporary AMI and re-registering with gp3 volumes")

        # Step 4: Deregister the temporary AMI (snapshots are retained)
        ec2_client.deregister_image(ImageId=temp_ami_id)
        logger.info(f"Deregistered temporary AMI {temp_ami_id} (snapshots retained)")

        # Step 5: Re-register the AMI with modified block device mappings
        # Preserve all important attributes from the source/temporary AMI
        register_params = {
            'Name': ami_name,
            'Description': f"Encrypted gp3 copy of {source_image.get('Description', source_ami_id)}",
            'Architecture': temp_image['Architecture'],
            'RootDeviceName': temp_image['RootDeviceName'],
            'BlockDeviceMappings': modified_mappings,
            'VirtualizationType': temp_image.get('VirtualizationType', 'hvm'),
        }

        # Add optional attributes if present
        if temp_image.get('EnaSupport'):
            register_params['EnaSupport'] = True
        if temp_image.get('SriovNetSupport'):
            register_params['SriovNetSupport'] = temp_image['SriovNetSupport']
        if temp_image.get('BootMode'):
            register_params['BootMode'] = temp_image['BootMode']
        if temp_image.get('TpmSupport'):
            register_params['TpmSupport'] = temp_image['TpmSupport']
        if temp_image.get('UefiData'):
            register_params['UefiData'] = temp_image['UefiData']
        if temp_image.get('ImdsSupport'):
            register_params['ImdsSupport'] = temp_image['ImdsSupport']

        register_response = ec2_client.register_image(**register_params)
        final_ami_id = register_response['ImageId']
        logger.info(f"Re-registered AMI with gp3 volumes: {final_ami_id}")

        # Step 6: Tag the final AMI
        if tags:
            # Add source AMI ID and metadata to tags for tracking
            all_tags = tags.copy()
            all_tags['SourceAMI'] = source_ami_id
            all_tags['CopiedBy'] = 'ami-copier-lambda'
            all_tags['CopyDate'] = datetime.utcnow().isoformat()

            # Add UUID if available
            if uuid:
                all_tags['SourceAMIUUID'] = uuid

            tag_list = [{'Key': k, 'Value': v} for k, v in all_tags.items()]

            ec2_client.create_tags(
                Resources=[final_ami_id],
                Tags=tag_list
            )
            logger.info(f"Applied tags to final AMI {final_ami_id}")

        logger.info(f"Successfully completed two-step copy: {source_ami_id} -> {final_ami_id}")
        return final_ami_id

    except ClientError as e:
        logger.error(f"Error copying AMI {source_ami_id}: {e}")
        # If we created a temporary AMI and failed, try to clean it up
        if temp_ami_id:
            try:
                logger.info(f"Attempting to clean up temporary AMI {temp_ami_id}")
                ec2_client.deregister_image(ImageId=temp_ami_id)
                logger.info(f"Cleaned up temporary AMI {temp_ami_id}")
            except Exception as cleanup_error:
                logger.error(f"Failed to clean up temporary AMI {temp_ami_id}: {cleanup_error}")
        raise


def process_ami(source_ami_id: str, ami_name_template: str, base_tags: Dict[str, str]) -> Dict[str, Any]:
    """
    Process a single AMI: extract UUID, check for duplicates, enrich tags, and copy.

    Args:
        source_ami_id: Source AMI ID to process
        ami_name_template: Template for generating AMI name
        base_tags: Base tags to apply

    Returns:
        Dictionary with processing results
    """
    try:
        # Get source AMI details
        response = ec2_client.describe_images(ImageIds=[source_ami_id])
        if not response['Images']:
            logger.error(f"Source AMI {source_ami_id} not found")
            return {
                'source_ami_id': source_ami_id,
                'status': 'error',
                'message': 'AMI not found'
            }

        source_image = response['Images'][0]
        source_ami_name = source_image.get('Name', 'unknown')

        logger.info(f"Processing AMI {source_ami_id} (name: {source_ami_name})")

        # Extract UUID from source AMI name
        uuid = extract_uuid_from_ami_name(source_ami_name)
        if uuid:
            logger.info(f"Extracted UUID: {uuid}")

        # Generate target AMI name
        ami_name = generate_ami_name(ami_name_template, source_image, uuid)
        logger.info(f"Generated target AMI name: {ami_name}")

        # Check for duplicates
        if ami_already_copied(ami_name):
            return {
                'source_ami_id': source_ami_id,
                'status': 'skipped',
                'message': f'AMI already copied with name: {ami_name}',
                'ami_name': ami_name
            }

        # Start with base tags
        tags = base_tags.copy()

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
        new_ami_id = copy_ami(source_ami_id, ami_name, tags, uuid)

        logger.info(f"Successfully initiated copy of {source_ami_id} to {new_ami_id}")

        return {
            'source_ami_id': source_ami_id,
            'new_ami_id': new_ami_id,
            'ami_name': ami_name,
            'uuid': uuid,
            'status': 'copied'
        }

    except Exception as e:
        logger.error(f"Error processing AMI {source_ami_id}: {e}", exc_info=True)
        return {
            'source_ami_id': source_ami_id,
            'status': 'error',
            'message': str(e)
        }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for AMI copy automation.

    Supports two invocation modes:
    1. Scheduled mode (EventBridge scheduled rule) - Discovers and processes all shared Red Hat AMIs
    2. Manual mode (direct invocation) - Processes a specific AMI provided in the event

    Args:
        event: Lambda event with optional 'source_ami_id' for manual mode
        context: Lambda context

    Returns:
        Response dictionary with processing results
    """
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Get configuration from environment variables
        ami_name_template = os.environ.get('AMI_NAME_TEMPLATE', '{source_name}-encrypted-gp3-{uuid}-{date}')
        tags_json = os.environ.get('TAGS', '{}')
        base_tags = json.loads(tags_json)

        # Check if this is a manual invocation with specific AMI ID
        source_ami_id = event.get('source_ami_id')

        if source_ami_id:
            # Manual mode: Process specific AMI
            logger.info(f"Manual invocation mode: Processing AMI {source_ami_id}")

            result = process_ami(source_ami_id, ami_name_template, base_tags)

            return {
                'statusCode': 200 if result['status'] == 'copied' else 400,
                'body': json.dumps({
                    'mode': 'manual',
                    'result': result
                })
            }

        else:
            # Scheduled mode: Discover and process all shared AMIs
            logger.info("Scheduled polling mode: Discovering shared Red Hat AMIs")

            shared_amis = discover_shared_amis()

            if not shared_amis:
                logger.info("No shared AMIs found from Red Hat")
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'mode': 'scheduled',
                        'message': 'No shared AMIs found',
                        'results': []
                    })
                }

            logger.info(f"Processing {len(shared_amis)} shared AMIs")

            results = []
            for ami in shared_amis:
                ami_id = ami['ImageId']
                result = process_ami(ami_id, ami_name_template, base_tags)
                results.append(result)

            # Summarize results
            copied_count = sum(1 for r in results if r['status'] == 'copied')
            skipped_count = sum(1 for r in results if r['status'] == 'skipped')
            error_count = sum(1 for r in results if r['status'] == 'error')

            logger.info(f"Processing complete: {copied_count} copied, {skipped_count} skipped, {error_count} errors")

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'mode': 'scheduled',
                    'summary': {
                        'total': len(shared_amis),
                        'copied': copied_count,
                        'skipped': skipped_count,
                        'errors': error_count
                    },
                    'results': results
                })
            }

    except Exception as e:
        logger.error(f"Error in lambda_handler: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
