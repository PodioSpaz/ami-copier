"""
AMI Copy Initiator Lambda Function.

This Lambda function is the first step in the Step Functions workflow.
It discovers shared Red Hat AMIs, checks for duplicates, enriches tags
with Red Hat Image Builder API metadata, and initiates the encrypted AMI copy.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from shared_utils import (
    discover_shared_amis,
    get_source_ami_details,
    extract_uuid_from_ami_name,
    generate_ami_name,
    ami_already_copied,
    get_redhat_credentials,
    get_access_token,
    find_compose_by_ami,
    get_compose_metadata,
    enrich_tags_from_compose,
    logger
)

# Initialize AWS clients
ec2_client = boto3.client('ec2')


def initiate_ami_copy(
    source_ami_id: str,
    ami_name: str,
    source_image: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Initiate the encrypted AMI copy (Step 1 of two-step process).

    Args:
        source_ami_id: Source AMI ID to copy
        ami_name: Final AMI name (used to generate temp name)
        source_image: Source AMI metadata

    Returns:
        Dictionary with temp_ami_id and copy details
    """
    try:
        # Generate temporary AMI name with timestamp
        temp_ami_name = f"{ami_name}-temp-{int(datetime.utcnow().timestamp())}"

        logger.info(f"Initiating encrypted copy of {source_ami_id}")
        logger.info(f"Temporary AMI name: {temp_ami_name}")

        # Build copy_image parameters
        copy_params = {
            'Name': temp_ami_name,
            'SourceImageId': source_ami_id,
            'SourceRegion': os.environ['AWS_REGION'],
            'Encrypted': True,
            'Description': f"Temporary encrypted copy of {source_image.get('Description', source_ami_id)}"
        }

        # Add KMS key if specified (required for cross-account sharing)
        kms_key_id = os.environ.get('KMS_KEY_ID', '')
        if kms_key_id:
            copy_params['KmsKeyId'] = kms_key_id
            logger.info(f"Using custom KMS key for encryption: {kms_key_id}")
        else:
            logger.info("Using AWS-managed key (aws/ebs) for encryption")

        # Initiate encrypted copy
        response = ec2_client.copy_image(**copy_params)

        temp_ami_id = response['ImageId']
        logger.info(f"Copy initiated successfully: {temp_ami_id}")

        return {
            'temp_ami_id': temp_ami_id,
            'temp_ami_name': temp_ami_name,
            'copy_initiated_at': datetime.utcnow().isoformat()
        }

    except ClientError as e:
        logger.error(f"Error initiating copy for {source_ami_id}: {e}")
        raise


def process_single_ami(
    source_ami_id: str,
    ami_name_template: str,
    base_tags: Dict[str, str],
    name_tag_template: str
) -> Dict[str, Any]:
    """
    Process a single AMI: check duplicates, enrich tags, initiate copy.

    Args:
        source_ami_id: Source AMI ID to process
        ami_name_template: Template for generating AMI name
        base_tags: Base tags to apply
        name_tag_template: Template for generating Name tag

    Returns:
        Dictionary with AMI processing state
    """
    try:
        # Get source AMI details
        source_image = get_source_ami_details(source_ami_id)
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
        if ami_already_copied(source_ami_id, uuid):
            return {
                'source_ami_id': source_ami_id,
                'source_ami_name': source_ami_name,
                'ami_name': ami_name,
                'uuid': uuid,
                'status': 'skipped',
                'reason': 'Already copied',
                'skip': True
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

        # Initiate the AMI copy
        copy_result = initiate_ami_copy(source_ami_id, ami_name, source_image)

        # Return state for Step Functions
        return {
            'source_ami_id': source_ami_id,
            'source_ami_name': source_ami_name,
            'ami_name': ami_name,
            'uuid': uuid,
            'tags': tags,
            'name_tag_template': name_tag_template,
            'temp_ami_id': copy_result['temp_ami_id'],
            'temp_ami_name': copy_result['temp_ami_name'],
            'copy_initiated_at': copy_result['copy_initiated_at'],
            'source_image_metadata': {
                'Description': source_image.get('Description', ''),
                'Architecture': source_image.get('Architecture'),
                'RootDeviceName': source_image.get('RootDeviceName'),
                'VirtualizationType': source_image.get('VirtualizationType', 'hvm'),
                'EnaSupport': source_image.get('EnaSupport'),
                'SriovNetSupport': source_image.get('SriovNetSupport'),
                'BootMode': source_image.get('BootMode'),
                'TpmSupport': source_image.get('TpmSupport'),
                'UefiData': source_image.get('UefiData'),
                'ImdsSupport': source_image.get('ImdsSupport')
            },
            'status': 'copy_initiated',
            'skip': False
        }

    except Exception as e:
        logger.error(f"Error processing AMI {source_ami_id}: {e}", exc_info=True)
        return {
            'source_ami_id': source_ami_id,
            'status': 'error',
            'error': str(e),
            'skip': True
        }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for AMI copy initiator.

    Supports two invocation modes:
    1. Discovery mode (no source_ami_id) - Discovers and processes all shared Red Hat AMIs
    2. Single AMI mode (with source_ami_id) - Processes a specific AMI

    Args:
        event: Lambda event with optional 'source_ami_id' for single AMI mode
        context: Lambda context

    Returns:
        Dictionary with array of AMI states to process
    """
    logger.info(f"Initiator received event: {json.dumps(event)}")

    try:
        # Get configuration from environment variables
        ami_name_template = os.environ.get('AMI_NAME_TEMPLATE', '{source_name}-encrypted-gp3-{uuid}-{date}')
        ami_name_tag_template = os.environ.get('AMI_NAME_TAG_TEMPLATE', '')
        tags_json = os.environ.get('TAGS', '{}')
        base_tags = json.loads(tags_json)

        # Check if this is single AMI mode
        source_ami_id = event.get('source_ami_id')

        if source_ami_id:
            # Single AMI mode
            logger.info(f"Single AMI mode: Processing {source_ami_id}")

            result = process_single_ami(
                source_ami_id,
                ami_name_template,
                base_tags,
                ami_name_tag_template
            )

            return {
                'mode': 'single',
                'amis_to_process': [result] if not result.get('skip') else [],
                'summary': {
                    'total_discovered': 1,
                    'to_process': 0 if result.get('skip') else 1,
                    'skipped': 1 if result.get('skip') else 0
                }
            }

        else:
            # Discovery mode: Find all shared Red Hat AMIs
            logger.info("Discovery mode: Finding shared Red Hat AMIs")

            shared_amis = discover_shared_amis()

            if not shared_amis:
                logger.info("No shared AMIs found from Red Hat")
                return {
                    'mode': 'discovery',
                    'amis_to_process': [],
                    'summary': {
                        'total_discovered': 0,
                        'to_process': 0,
                        'skipped': 0
                    }
                }

            logger.info(f"Found {len(shared_amis)} shared AMIs, processing...")

            # Process each discovered AMI
            results = []
            for ami in shared_amis:
                ami_id = ami['ImageId']
                result = process_single_ami(
                    ami_id,
                    ami_name_template,
                    base_tags,
                    ami_name_tag_template
                )
                results.append(result)

            # Filter out skipped AMIs for processing
            amis_to_process = [r for r in results if not r.get('skip')]
            skipped = [r for r in results if r.get('skip')]

            logger.info(
                f"Initiator complete: {len(amis_to_process)} to process, "
                f"{len(skipped)} skipped"
            )

            return {
                'mode': 'discovery',
                'amis_to_process': amis_to_process,
                'summary': {
                    'total_discovered': len(shared_amis),
                    'to_process': len(amis_to_process),
                    'skipped': len(skipped)
                }
            }

    except Exception as e:
        logger.error(f"Error in initiator lambda_handler: {e}", exc_info=True)
        raise
