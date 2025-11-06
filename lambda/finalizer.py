"""
AMI Copy Finalizer Lambda Function.

This Lambda function is the final step in the Step Functions workflow.
It re-registers the temporary encrypted AMI with gp3 volume types,
applies tags, and cleans up the temporary AMI.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from shared_utils import (
    get_source_ami_details,
    build_block_device_mappings_for_registration,
    generate_name_tag,
    logger
)

# Initialize AWS clients
ec2_client = boto3.client('ec2')


def finalize_ami_copy(
    temp_ami_id: str,
    ami_name: str,
    tags: Dict[str, str],
    source_ami_id: str,
    uuid: str,
    source_image_metadata: Dict[str, Any],
    name_tag_template: str
) -> str:
    """
    Finalize the AMI copy by re-registering with gp3 volumes and applying tags.

    Args:
        temp_ami_id: Temporary encrypted AMI ID
        ami_name: Final AMI name
        tags: Tags to apply (already enriched with Red Hat API metadata)
        source_ami_id: Original source AMI ID
        uuid: UUID extracted from source AMI name
        source_image_metadata: Metadata from source AMI
        name_tag_template: Template for generating Name tag

    Returns:
        Final AMI ID
    """
    try:
        logger.info(f"Finalizing AMI copy for temp AMI {temp_ami_id}")

        # Get the temporary AMI's details
        temp_image = get_source_ami_details(temp_ami_id)

        # Build modified block device mappings with gp3
        original_mappings = temp_image.get('BlockDeviceMappings', [])
        modified_mappings = build_block_device_mappings_for_registration(original_mappings)

        logger.info(f"Deregistering temporary AMI {temp_ami_id} and re-registering with gp3 volumes")

        # Deregister the temporary AMI (snapshots are retained)
        ec2_client.deregister_image(ImageId=temp_ami_id)
        logger.info(f"Deregistered temporary AMI {temp_ami_id} (snapshots retained)")

        # Re-register the AMI with modified block device mappings
        # Use metadata from source AMI (preserved in state)
        register_params = {
            'Name': ami_name,
            'Description': f"Encrypted gp3 copy of {source_image_metadata.get('Description', source_ami_id)}",
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

        # Apply tags to the final AMI
        if tags:
            # Add source AMI ID and metadata to tags for tracking
            all_tags = tags.copy()
            all_tags['SourceAMI'] = source_ami_id
            all_tags['CopiedBy'] = 'ami-copier-lambda'
            all_tags['CopyDate'] = datetime.utcnow().isoformat()

            # Add UUID if available
            if uuid:
                all_tags['SourceAMIUUID'] = uuid

            # Generate and add Name tag if template provided and Distribution available
            if name_tag_template and 'Distribution' in all_tags:
                # Reconstruct source_image dict for generate_name_tag
                source_image = {
                    'Name': source_image_metadata.get('source_name', 'unknown'),
                    'Description': source_image_metadata.get('Description', '')
                }
                name_tag_value = generate_name_tag(
                    name_tag_template,
                    source_image,
                    uuid,
                    all_tags.get('Distribution')
                )
                all_tags['Name'] = name_tag_value
                logger.info(f"Generated Name tag: {name_tag_value}")

            tag_list = [{'Key': k, 'Value': v} for k, v in all_tags.items()]

            ec2_client.create_tags(
                Resources=[final_ami_id],
                Tags=tag_list
            )
            logger.info(f"Applied {len(all_tags)} tags to final AMI {final_ami_id}")

        logger.info(f"Successfully finalized copy: {source_ami_id} -> {final_ami_id}")
        return final_ami_id

    except ClientError as e:
        logger.error(f"Error finalizing AMI copy for {temp_ami_id}: {e}")
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for AMI copy finalizer.

    Args:
        event: Lambda event with all state from previous steps
        context: Lambda context

    Returns:
        Dictionary with finalization results
    """
    logger.info(f"Finalizer received event keys: {list(event.keys())}")

    try:
        # Extract required fields from event
        temp_ami_id = event.get('temp_ami_id')
        ami_name = event.get('ami_name')
        tags = event.get('tags', {})
        source_ami_id = event.get('source_ami_id')
        uuid = event.get('uuid')
        source_image_metadata = event.get('source_image_metadata', {})
        name_tag_template = event.get('name_tag_template', '')

        # Validate required fields
        if not temp_ami_id:
            raise ValueError("temp_ami_id is required")
        if not ami_name:
            raise ValueError("ami_name is required")
        if not source_ami_id:
            raise ValueError("source_ami_id is required")

        # Finalize the AMI copy
        final_ami_id = finalize_ami_copy(
            temp_ami_id,
            ami_name,
            tags,
            source_ami_id,
            uuid,
            source_image_metadata,
            name_tag_template
        )

        # Return final state
        return {
            'source_ami_id': source_ami_id,
            'source_ami_name': event.get('source_ami_name'),
            'final_ami_id': final_ami_id,
            'ami_name': ami_name,
            'uuid': uuid,
            'temp_ami_id': temp_ami_id,
            'status': 'completed',
            'completed_at': datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Error in finalizer lambda_handler: {e}", exc_info=True)
        # Return error state
        return {
            'source_ami_id': event.get('source_ami_id'),
            'temp_ami_id': event.get('temp_ami_id'),
            'status': 'error',
            'error': str(e),
            'failed_at': datetime.utcnow().isoformat()
        }
