"""
AMI Copy Status Checker Lambda Function.

This Lambda function is the second step in the Step Functions workflow.
It checks the status of the temporary encrypted AMI copy to determine
if it's ready for the finalization step.
"""

import json
import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ec2_client = boto3.client('ec2')


def check_ami_status(ami_id: str) -> Dict[str, Any]:
    """
    Check the status of an AMI.

    Args:
        ami_id: AMI ID to check

    Returns:
        Dictionary with status information
    """
    try:
        response = ec2_client.describe_images(ImageIds=[ami_id])

        if not response['Images']:
            logger.error(f"AMI {ami_id} not found")
            return {
                'ami_id': ami_id,
                'state': 'not_found',
                'available': False,
                'continue_waiting': False,
                'error': 'AMI not found'
            }

        image = response['Images'][0]
        state = image.get('State', 'unknown')

        logger.info(f"AMI {ami_id} status: {state}")

        # Determine if we should continue waiting
        continue_waiting = state in ['pending', 'transient']

        return {
            'ami_id': ami_id,
            'state': state,
            'available': state == 'available',
            'continue_waiting': continue_waiting,
            'state_reason': image.get('StateReason', {}).get('Message', '') if state == 'failed' else ''
        }

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')

        # InvalidAMIID.NotFound means the AMI doesn't exist (yet)
        if error_code == 'InvalidAMIID.NotFound':
            logger.warning(f"AMI {ami_id} not found yet, will continue waiting")
            return {
                'ami_id': ami_id,
                'state': 'pending',
                'available': False,
                'continue_waiting': True
            }

        logger.error(f"Error checking AMI status for {ami_id}: {e}")
        return {
            'ami_id': ami_id,
            'state': 'error',
            'available': False,
            'continue_waiting': False,
            'error': str(e)
        }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for AMI copy status checker.

    Args:
        event: Lambda event with 'temp_ami_id' to check
        context: Lambda context

    Returns:
        Dictionary with status check results
    """
    logger.info(f"Status checker received event: {json.dumps(event)}")

    try:
        temp_ami_id = event.get('temp_ami_id')

        if not temp_ami_id:
            logger.error("No temp_ami_id provided in event")
            raise ValueError("temp_ami_id is required")

        # Check the AMI status
        status_result = check_ami_status(temp_ami_id)

        # Pass through all state from the initiator, plus add status check results
        result = event.copy()
        result.update({
            'ami_state': status_result['state'],
            'ami_available': status_result['available'],
            'continue_waiting': status_result['continue_waiting']
        })

        # Add error information if present
        if 'error' in status_result:
            result['status_check_error'] = status_result['error']

        if 'state_reason' in status_result and status_result['state_reason']:
            result['state_reason'] = status_result['state_reason']

        logger.info(
            f"Status check complete: AMI {temp_ami_id} is {status_result['state']}, "
            f"continue_waiting={status_result['continue_waiting']}"
        )

        return result

    except Exception as e:
        logger.error(f"Error in status checker lambda_handler: {e}", exc_info=True)
        # Return state with error flag
        result = event.copy()
        result.update({
            'ami_state': 'error',
            'ami_available': False,
            'continue_waiting': False,
            'status_check_error': str(e)
        })
        return result
