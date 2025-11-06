"""
Shared utilities for AMI copier Lambda functions.

This module contains common functions used across the initiator, status checker,
and finalizer Lambda functions.
"""

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


def generate_name_tag(template: str, source_image: Dict[str, Any], uuid: Optional[str], distribution: str) -> str:
    """
    Generate Name tag value from template.

    Args:
        template: Name tag template with placeholders
        source_image: Source AMI metadata
        uuid: Optional UUID extracted from source AMI name
        distribution: Distribution value from Red Hat API (e.g., 'rhel-9')

    Returns:
        Generated Name tag value
    """
    source_name = source_image.get('Name', 'unknown')
    creation_date = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

    # Replace placeholders
    name = template.replace('{distribution}', distribution)
    name = name.replace('{source_name}', source_name)
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


def ami_already_copied(source_ami_id: str, uuid: Optional[str] = None) -> bool:
    """
    Check if an AMI from the given source has already been copied.

    Uses tags to identify duplicates: SourceAMI (always) and SourceAMIUUID (when available).
    This approach is robust against timestamp variations in AMI names.

    Args:
        source_ami_id: Source AMI ID to check
        uuid: Optional UUID extracted from source AMI name

    Returns:
        True if AMI from this source already copied, False otherwise
    """
    try:
        # Build filters - always check SourceAMI tag
        filters = [
            {'Name': 'tag:SourceAMI', 'Values': [source_ami_id]}
        ]

        # If UUID is available, add it for more precise matching
        if uuid:
            filters.append({'Name': 'tag:SourceAMIUUID', 'Values': [uuid]})

        response = ec2_client.describe_images(
            Owners=['self'],
            Filters=filters
        )

        exists = len(response.get('Images', [])) > 0

        if exists:
            uuid_info = f" (UUID: {uuid})" if uuid else ""
            logger.info(f"AMI from source {source_ami_id}{uuid_info} already exists, skipping copy")

        return exists

    except ClientError as e:
        logger.error(f"Error checking for existing AMI: {e}")
        # On error, return False to allow copy attempt (fail safe)
        return False
