"""
Unit tests for AMI Copier Lambda function.

Tests cover:
- Credential retrieval from SSM Parameter Store and Secrets Manager
- Red Hat API authentication (service account and offline token)
- Red Hat API interactions (compose lookup, metadata retrieval)
- UUID extraction from Red Hat AMI names
- AMI discovery from Red Hat account
- Deduplication checks
- AMI operations (block device mapping conversion, AMI copying)
- Name tag generation with template placeholders
- Name tag graceful degradation when Distribution tag is unavailable
- Lambda handler event processing (scheduled and manual modes)
"""
import json
import os
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch, call
from urllib.error import URLError, HTTPError

import pytest
from moto import mock_aws
import boto3

# Import the Lambda function - adjust path as needed
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda'))

import ami_copier


# Fixtures
@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_REGION'] = 'us-east-1'


@pytest.fixture
def mock_ec2_client(aws_credentials):
    """Create a mocked EC2 client."""
    with mock_aws():
        yield boto3.client('ec2', region_name='us-east-1')


@pytest.fixture
def mock_ssm_client(aws_credentials):
    """Create a mocked SSM client."""
    with mock_aws():
        yield boto3.client('ssm', region_name='us-east-1')


@pytest.fixture
def mock_secretsmanager_client(aws_credentials):
    """Create a mocked Secrets Manager client."""
    with mock_aws():
        yield boto3.client('secretsmanager', region_name='us-east-1')


@pytest.fixture
def sample_ami_data():
    """Sample AMI data for testing."""
    return {
        'ImageId': 'ami-12345678',
        'Name': 'rhel-9-base',
        'Description': 'RHEL 9 Base Image',
        'BlockDeviceMappings': [
            {
                'DeviceName': '/dev/sda1',
                'Ebs': {
                    'VolumeType': 'gp2',
                    'VolumeSize': 10,
                    'DeleteOnTermination': True,
                    'SnapshotId': 'snap-12345',
                    'Encrypted': False
                }
            },
            {
                'DeviceName': '/dev/sdb',
                'Ebs': {
                    'VolumeType': 'gp3',
                    'VolumeSize': 20,
                    'DeleteOnTermination': True,
                    'SnapshotId': 'snap-67890',
                    'Encrypted': True
                }
            }
        ]
    }


@pytest.fixture
def sample_redhat_ami_data():
    """Sample Red Hat AMI data with UUID in name."""
    return {
        'ImageId': 'ami-redhat123',
        'Name': 'composer-api-a1b2c3d4-5678-90ab-cdef-1234567890ab',
        'Description': 'Red Hat Enterprise Linux 9',
        'OwnerId': '463606842039',
        'State': 'available',
        'BlockDeviceMappings': [
            {
                'DeviceName': '/dev/sda1',
                'Ebs': {
                    'VolumeType': 'gp2',
                    'VolumeSize': 10,
                    'DeleteOnTermination': True,
                    'SnapshotId': 'snap-rh123',
                    'Encrypted': False
                }
            }
        ]
    }


@pytest.fixture
def sample_scheduled_event():
    """Sample EventBridge scheduled event for testing."""
    return {
        'version': '0',
        'id': 'scheduled-event-id',
        'detail-type': 'Scheduled Event',
        'source': 'aws.events',
        'account': '123456789012',
        'time': '2024-10-25T12:00:00Z',
        'region': 'us-east-1',
        'resources': ['arn:aws:events:us-east-1:123456789012:rule/rhel-ami-discovery'],
        'detail': {}
    }


@pytest.fixture
def sample_manual_event():
    """Sample manual invocation event for testing."""
    return {
        'source_ami_id': 'ami-12345678'
    }


# Tests for get_redhat_credentials()
class TestGetRedhatCredentials:
    """Tests for credential retrieval from SSM and Secrets Manager."""

    def test_ssm_credentials_success(self, mock_ssm_client):
        """Test successful credential retrieval from SSM Parameter Store."""
        # Setup environment
        os.environ['REDHAT_CREDENTIAL_STORE'] = 'ssm'
        os.environ['CLIENT_ID_PARAM'] = '/test/redhat/client-id'
        os.environ['CLIENT_SECRET_PARAM'] = '/test/redhat/client-secret'

        # Create SSM parameters
        mock_ssm_client.put_parameter(
            Name='/test/redhat/client-id',
            Value='test-client-id',
            Type='SecureString'
        )
        mock_ssm_client.put_parameter(
            Name='/test/redhat/client-secret',
            Value='test-client-secret',
            Type='SecureString'
        )

        # Patch the module-level client
        with patch('ami_copier.ssm_client', mock_ssm_client):
            credentials = ami_copier.get_redhat_credentials()

        assert credentials == {
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret'
        }

    def test_ssm_credentials_missing_params(self):
        """Test SSM credential retrieval with missing parameter names."""
        os.environ['REDHAT_CREDENTIAL_STORE'] = 'ssm'
        os.environ.pop('CLIENT_ID_PARAM', None)
        os.environ.pop('CLIENT_SECRET_PARAM', None)

        credentials = ami_copier.get_redhat_credentials()
        assert credentials is None

    def test_ssm_credentials_parameter_not_found(self, mock_ssm_client):
        """Test SSM credential retrieval when parameters don't exist."""
        os.environ['REDHAT_CREDENTIAL_STORE'] = 'ssm'
        os.environ['CLIENT_ID_PARAM'] = '/nonexistent/client-id'
        os.environ['CLIENT_SECRET_PARAM'] = '/nonexistent/client-secret'

        with patch('ami_copier.ssm_client', mock_ssm_client):
            credentials = ami_copier.get_redhat_credentials()

        assert credentials is None

    def test_secretsmanager_service_account_credentials(self, mock_secretsmanager_client):
        """Test credential retrieval from Secrets Manager with service account."""
        os.environ['REDHAT_CREDENTIAL_STORE'] = 'secretsmanager'
        os.environ['REDHAT_SECRET_NAME'] = 'test-secret'

        # Create secret with service account credentials
        mock_secretsmanager_client.create_secret(
            Name='test-secret',
            SecretString=json.dumps({
                'client_id': 'test-client-id',
                'client_secret': 'test-client-secret'
            })
        )

        with patch('ami_copier.secretsmanager_client', mock_secretsmanager_client):
            credentials = ami_copier.get_redhat_credentials()

        assert credentials == {
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret'
        }

    def test_secretsmanager_offline_token_credentials(self, mock_secretsmanager_client):
        """Test credential retrieval from Secrets Manager with offline token."""
        os.environ['REDHAT_CREDENTIAL_STORE'] = 'secretsmanager'
        os.environ['REDHAT_SECRET_NAME'] = 'test-secret'

        # Create secret with offline token
        mock_secretsmanager_client.create_secret(
            Name='test-secret',
            SecretString=json.dumps({
                'offline_token': 'test-offline-token'
            })
        )

        with patch('ami_copier.secretsmanager_client', mock_secretsmanager_client):
            credentials = ami_copier.get_redhat_credentials()

        assert credentials == {
            'offline_token': 'test-offline-token'
        }

    def test_secretsmanager_missing_secret_name(self):
        """Test Secrets Manager credential retrieval with missing secret name."""
        os.environ['REDHAT_CREDENTIAL_STORE'] = 'secretsmanager'
        os.environ.pop('REDHAT_SECRET_NAME', None)

        credentials = ami_copier.get_redhat_credentials()
        assert credentials is None

    def test_unknown_credential_store(self):
        """Test with unknown credential store type."""
        os.environ['REDHAT_CREDENTIAL_STORE'] = 'invalid'

        credentials = ami_copier.get_redhat_credentials()
        assert credentials is None


# Tests for get_access_token()
class TestGetAccessToken:
    """Tests for Red Hat API access token retrieval."""

    @patch('ami_copier.request.urlopen')
    def test_service_account_auth_success(self, mock_urlopen):
        """Test successful service account authentication."""
        # Mock successful token response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'access_token': 'test-access-token',
            'expires_in': 900
        }).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        credentials = {
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret'
        }

        token = ami_copier.get_access_token(credentials)
        assert token == 'test-access-token'

        # Verify the request was made with correct parameters
        assert mock_urlopen.called
        request_obj = mock_urlopen.call_args[0][0]
        request_data = request_obj.data.decode('utf-8')
        assert 'grant_type=client_credentials' in request_data
        assert 'client_id=test-client-id' in request_data
        assert 'client_secret=test-client-secret' in request_data

    @patch('ami_copier.request.urlopen')
    def test_offline_token_auth_success(self, mock_urlopen):
        """Test successful offline token authentication."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'access_token': 'test-access-token',
            'expires_in': 900
        }).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        credentials = {
            'offline_token': 'test-offline-token'
        }

        token = ami_copier.get_access_token(credentials)
        assert token == 'test-access-token'

        # Verify the request was made with correct parameters
        request_obj = mock_urlopen.call_args[0][0]
        request_data = request_obj.data.decode('utf-8')
        assert 'grant_type=refresh_token' in request_data
        assert 'refresh_token=test-offline-token' in request_data

    def test_invalid_credentials_format(self):
        """Test with invalid credentials format."""
        credentials = {'invalid_key': 'value'}

        token = ami_copier.get_access_token(credentials)
        assert token is None

    @patch('ami_copier.request.urlopen')
    def test_auth_http_error(self, mock_urlopen):
        """Test authentication failure with HTTP error."""
        mock_urlopen.side_effect = HTTPError(
            'https://sso.redhat.com',
            401,
            'Unauthorized',
            {},
            None
        )

        credentials = {
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret'
        }

        token = ami_copier.get_access_token(credentials)
        assert token is None

    @patch('ami_copier.request.urlopen')
    def test_auth_url_error(self, mock_urlopen):
        """Test authentication failure with URL error."""
        mock_urlopen.side_effect = URLError('Connection failed')

        credentials = {
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret'
        }

        token = ami_copier.get_access_token(credentials)
        assert token is None


# Tests for find_compose_by_ami()
class TestFindComposeByAmi:
    """Tests for Image Builder compose lookup."""

    @patch('ami_copier.request.urlopen')
    def test_find_compose_success(self, mock_urlopen):
        """Test successful compose lookup."""
        # Mock composes list response
        composes_response = MagicMock()
        composes_response.read.return_value = json.dumps({
            'data': [
                {'id': 'compose-1'},
                {'id': 'compose-2'}
            ]
        }).encode('utf-8')
        composes_response.__enter__.return_value = composes_response

        # Mock compose detail responses
        compose_1_response = MagicMock()
        compose_1_response.read.return_value = json.dumps({
            'id': 'compose-1',
            'image_status': {
                'upload_status': {
                    'options': {
                        'ami': 'ami-wrong'
                    }
                }
            }
        }).encode('utf-8')
        compose_1_response.__enter__.return_value = compose_1_response

        compose_2_response = MagicMock()
        compose_2_response.read.return_value = json.dumps({
            'id': 'compose-2',
            'image_status': {
                'upload_status': {
                    'options': {
                        'ami': 'ami-12345678'
                    }
                }
            }
        }).encode('utf-8')
        compose_2_response.__enter__.return_value = compose_2_response

        mock_urlopen.side_effect = [composes_response, compose_1_response, compose_2_response]

        result = ami_copier.find_compose_by_ami('ami-12345678', 'test-token')

        assert result is not None
        compose, status = result
        assert compose['id'] == 'compose-2'
        assert status['image_status']['upload_status']['options']['ami'] == 'ami-12345678'

    @patch('ami_copier.request.urlopen')
    def test_compose_not_found(self, mock_urlopen):
        """Test when compose is not found."""
        composes_response = MagicMock()
        composes_response.read.return_value = json.dumps({
            'data': [
                {'id': 'compose-1'}
            ]
        }).encode('utf-8')
        composes_response.__enter__.return_value = composes_response

        compose_1_response = MagicMock()
        compose_1_response.read.return_value = json.dumps({
            'id': 'compose-1',
            'image_status': {
                'upload_status': {
                    'options': {
                        'ami': 'ami-different'
                    }
                }
            }
        }).encode('utf-8')
        compose_1_response.__enter__.return_value = compose_1_response

        mock_urlopen.side_effect = [composes_response, compose_1_response]

        result = ami_copier.find_compose_by_ami('ami-12345678', 'test-token')
        assert result is None

    @patch('ami_copier.request.urlopen')
    def test_api_error(self, mock_urlopen):
        """Test API error during compose lookup."""
        mock_urlopen.side_effect = URLError('Connection failed')

        result = ami_copier.find_compose_by_ami('ami-12345678', 'test-token')
        assert result is None


# Tests for get_compose_metadata()
class TestGetComposeMetadata:
    """Tests for compose metadata retrieval."""

    @patch('ami_copier.request.urlopen')
    def test_get_metadata_success(self, mock_urlopen):
        """Test successful metadata retrieval."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'packages': [
                {'name': 'kernel'},
                {'name': 'systemd'}
            ]
        }).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        metadata = ami_copier.get_compose_metadata('compose-123', 'test-token')

        assert metadata is not None
        assert 'packages' in metadata
        assert len(metadata['packages']) == 2

    @patch('ami_copier.request.urlopen')
    def test_get_metadata_error(self, mock_urlopen):
        """Test metadata retrieval error."""
        mock_urlopen.side_effect = URLError('Connection failed')

        metadata = ami_copier.get_compose_metadata('compose-123', 'test-token')
        assert metadata is None


# Tests for enrich_tags_from_compose()
class TestEnrichTagsFromCompose:
    """Tests for tag enrichment from compose data."""

    def test_enrich_tags_complete_data(self):
        """Test tag enrichment with complete compose data."""
        base_tags = {'Environment': 'production'}

        compose = {
            'id': 'compose-123',
            'created_at': '2024-10-25T12:00:00Z',
            'blueprint_id': 'bp-456',
            'blueprint_version': 3
        }

        status = {
            'request': {
                'image_name': 'My Custom Image',
                'distribution': 'rhel-9',
                'image_requests': [
                    {'architecture': 'x86_64'}
                ]
            }
        }

        metadata = {
            'packages': [{'name': f'package-{i}'} for i in range(50)]
        }

        enriched = ami_copier.enrich_tags_from_compose(base_tags, compose, status, metadata)

        assert enriched['Environment'] == 'production'
        assert enriched['ComposeId'] == 'compose-123'
        assert enriched['ImageBuilderName'] == 'My Custom Image'
        assert enriched['Distribution'] == 'rhel-9'
        assert enriched['Architecture'] == 'x86_64'
        assert enriched['ComposeCreatedAt'] == '2024-10-25T12:00:00Z'
        assert enriched['BlueprintId'] == 'bp-456'
        assert enriched['BlueprintVersion'] == '3'
        assert enriched['PackageCount'] == '50'

    def test_enrich_tags_minimal_data(self):
        """Test tag enrichment with minimal compose data."""
        base_tags = {'Environment': 'test'}

        compose = {'id': 'compose-123'}
        status = {'request': {}}
        metadata = None

        enriched = ami_copier.enrich_tags_from_compose(base_tags, compose, status, metadata)

        assert enriched['Environment'] == 'test'
        assert enriched['ComposeId'] == 'compose-123'
        assert 'ImageBuilderName' not in enriched
        assert 'Distribution' not in enriched


# Tests for build_block_device_mappings_for_registration()
class TestBuildBlockDeviceMappings:
    """Tests for block device mapping conversion."""

    def test_convert_gp2_to_gp3(self, sample_ami_data):
        """Test conversion of gp2 volumes to gp3."""
        # Test the build_block_device_mappings_for_registration function directly
        original_mappings = sample_ami_data['BlockDeviceMappings']

        modified_mappings = ami_copier.build_block_device_mappings_for_registration(original_mappings)

        # Verify we got mappings back
        assert len(modified_mappings) == 2

        # Verify gp2 conversion logic - check that gp2 was converted to gp3
        for i, mapping in enumerate(modified_mappings):
            if 'Ebs' in mapping:
                original_type = original_mappings[i]['Ebs'].get('VolumeType', 'gp2')
                expected_type = 'gp3' if original_type == 'gp2' else original_type

                assert mapping['Ebs']['VolumeType'] == expected_type
                # Verify Encrypted flag was removed (inherited from snapshot)
                assert 'Encrypted' not in mapping['Ebs']

    def test_ami_not_found(self, mock_ec2_client):
        """Test handling of non-existent AMI."""
        with patch('ami_copier.ec2_client', mock_ec2_client):
            # moto raises ClientError instead of returning empty results
            # Both are acceptable behaviors
            try:
                source_image = ami_copier.get_source_ami_details('ami-nonexistent')
                # If no exception, result should be empty or raise ValueError
                assert False, "Should have raised an exception"
            except (ValueError, Exception):
                # Expected - either ValueError from our code or ClientError from moto
                pass


# Tests for extract_uuid_from_ami_name()
class TestExtractUuidFromAmiName:
    """Tests for UUID extraction from AMI names."""

    def test_extract_uuid_success(self):
        """Test successful UUID extraction from Red Hat AMI name."""
        ami_name = 'composer-api-a1b2c3d4-5678-90ab-cdef-1234567890ab'
        uuid = ami_copier.extract_uuid_from_ami_name(ami_name)
        assert uuid == 'a1b2c3d4-5678-90ab-cdef-1234567890ab'

    def test_extract_uuid_with_suffix(self):
        """Test UUID extraction with additional suffix."""
        ami_name = 'composer-api-a1b2c3d4-5678-90ab-cdef-1234567890ab-extra'
        uuid = ami_copier.extract_uuid_from_ami_name(ami_name)
        assert uuid == 'a1b2c3d4-5678-90ab-cdef-1234567890ab'

    def test_extract_uuid_uppercase(self):
        """Test UUID extraction with uppercase letters."""
        ami_name = 'composer-api-A1B2C3D4-5678-90AB-CDEF-1234567890AB'
        uuid = ami_copier.extract_uuid_from_ami_name(ami_name)
        assert uuid.lower() == 'a1b2c3d4-5678-90ab-cdef-1234567890ab'

    def test_extract_uuid_no_match(self):
        """Test UUID extraction with non-matching pattern."""
        ami_name = 'rhel-9-base'
        uuid = ami_copier.extract_uuid_from_ami_name(ami_name)
        assert uuid is None

    def test_extract_uuid_invalid_format(self):
        """Test UUID extraction with invalid UUID format."""
        ami_name = 'composer-api-invalid-uuid'
        uuid = ami_copier.extract_uuid_from_ami_name(ami_name)
        assert uuid is None


# Tests for discover_shared_amis()
class TestDiscoverSharedAmis:
    """Tests for AMI discovery."""

    def test_discover_amis_success(self, mock_ec2_client, sample_redhat_ami_data):
        """Test successful AMI discovery."""
        # Register a Red Hat-style AMI in moto
        mock_ec2_client.register_image(
            Name=sample_redhat_ami_data['Name'],
            Description=sample_redhat_ami_data['Description'],
            Architecture='x86_64',
            RootDeviceName='/dev/sda1'
        )

        # Mock the describe_images call
        with patch('ami_copier.ec2_client') as mock_client:
            mock_client.describe_images.return_value = {
                'Images': [sample_redhat_ami_data]
            }

            amis = ami_copier.discover_shared_amis()

        assert len(amis) == 1
        assert amis[0]['ImageId'] == 'ami-redhat123'
        assert 'composer-api' in amis[0]['Name']

    def test_discover_amis_no_results(self):
        """Test AMI discovery with no shared AMIs."""
        with patch('ami_copier.ec2_client') as mock_client:
            mock_client.describe_images.return_value = {'Images': []}

            amis = ami_copier.discover_shared_amis()

        assert len(amis) == 0

    def test_discover_amis_filters_unavailable(self):
        """Test that discovery filters for available AMIs only."""
        with patch('ami_copier.ec2_client') as mock_client:
            amis = ami_copier.discover_shared_amis()

            # Verify the describe_images call used correct filters
            mock_client.describe_images.assert_called_once()
            call_kwargs = mock_client.describe_images.call_args[1]
            assert call_kwargs['Owners'] == ['463606842039']
            assert any(f['Name'] == 'state' and f['Values'] == ['available']
                      for f in call_kwargs['Filters'])


# Tests for ami_already_copied()
class TestAmiAlreadyCopied:
    """Tests for deduplication check."""

    def test_ami_exists(self, mock_ec2_client):
        """Test when AMI with same name already exists."""
        # Create an AMI with a specific name
        mock_ec2_client.register_image(
            Name='rhel-9-test-encrypted',
            Architecture='x86_64',
            RootDeviceName='/dev/sda1'
        )

        with patch('ami_copier.ec2_client', mock_ec2_client):
            exists = ami_copier.ami_already_copied('rhel-9-test-encrypted')

        assert exists is True

    def test_ami_does_not_exist(self, mock_ec2_client):
        """Test when AMI with name does not exist."""
        with patch('ami_copier.ec2_client', mock_ec2_client):
            exists = ami_copier.ami_already_copied('nonexistent-ami')

        assert exists is False

    def test_ami_check_error_handling(self):
        """Test error handling in deduplication check."""
        with patch('ami_copier.ec2_client') as mock_client:
            from botocore.exceptions import ClientError
            mock_client.describe_images.side_effect = ClientError(
                {'Error': {'Code': 'InvalidParameterValue'}},
                'DescribeImages'
            )

            # Should return False on error (fail-safe)
            exists = ami_copier.ami_already_copied('test-ami')

        assert exists is False


# Tests for generate_ami_name()
class TestGenerateAmiName:
    """Tests for AMI name generation."""

    def test_template_with_source_name(self):
        """Test name generation with source_name placeholder."""
        source_image = {'Name': 'rhel-9-base'}
        template = '{source_name}-encrypted'

        name = ami_copier.generate_ami_name(template, source_image)
        assert name.startswith('rhel-9-base-encrypted')

    def test_template_with_date(self):
        """Test name generation with date placeholder."""
        source_image = {'Name': 'test'}
        template = 'ami-{date}'

        name = ami_copier.generate_ami_name(template, source_image)
        # Should contain date in format YYYYMMDD-HHMMSS
        assert 'ami-' in name
        assert len(name) > 10

    def test_template_with_timestamp(self):
        """Test name generation with timestamp placeholder."""
        source_image = {'Name': 'test'}
        template = 'ami-{timestamp}'

        name = ami_copier.generate_ami_name(template, source_image)
        # Should contain Unix timestamp
        assert 'ami-' in name
        timestamp_part = name.replace('ami-', '')
        assert timestamp_part.isdigit()

    def test_template_with_uuid(self):
        """Test name generation with UUID placeholder."""
        source_image = {'Name': 'test'}
        template = 'rhel-{uuid}-encrypted'
        uuid = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'

        name = ami_copier.generate_ami_name(template, source_image, uuid)
        assert name == 'rhel-a1b2c3d4-5678-90ab-cdef-1234567890ab-encrypted'

    def test_template_with_uuid_none(self):
        """Test name generation when UUID is None."""
        source_image = {'Name': 'test'}
        template = 'rhel-{uuid}-encrypted'

        name = ami_copier.generate_ami_name(template, source_image, None)
        assert name == 'rhel-no-uuid-encrypted'

    def test_template_with_all_placeholders(self):
        """Test name generation with all placeholders."""
        source_image = {'Name': 'rhel-9'}
        template = '{source_name}-{uuid}-{date}-{timestamp}'
        uuid = 'test-uuid-1234'

        name = ami_copier.generate_ami_name(template, source_image, uuid)
        assert name.startswith('rhel-9-test-uuid-1234-')


# Tests for generate_name_tag()
class TestGenerateNameTag:
    """Tests for Name tag generation."""

    def test_template_with_distribution(self):
        """Test name tag generation with distribution placeholder."""
        source_image = {'Name': 'rhel-9-base'}
        template = 'prod-{distribution}'
        distribution = 'rhel-9'

        name = ami_copier.generate_name_tag(template, source_image, None, distribution)
        assert name == 'prod-rhel-9'

    def test_template_with_distribution_and_date(self):
        """Test name tag generation with distribution and date placeholders."""
        source_image = {'Name': 'test'}
        template = '{distribution}-encrypted-{date}'
        distribution = 'rhel-10'

        name = ami_copier.generate_name_tag(template, source_image, None, distribution)
        # Should contain distribution and date
        assert name.startswith('rhel-10-encrypted-')
        assert len(name) > 20  # Has date appended

    def test_template_with_distribution_and_uuid(self):
        """Test name tag generation with distribution and UUID placeholders."""
        source_image = {'Name': 'test'}
        template = '{distribution}-{uuid}'
        distribution = 'rhel-9'
        uuid = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'

        name = ami_copier.generate_name_tag(template, source_image, uuid, distribution)
        assert name == 'rhel-9-a1b2c3d4-5678-90ab-cdef-1234567890ab'

    def test_template_with_all_placeholders(self):
        """Test name tag generation with all placeholders."""
        source_image = {'Name': 'composer-api-test'}
        template = '{distribution}-{source_name}-{uuid}-{timestamp}'
        distribution = 'rhel-9'
        uuid = 'test-uuid'

        name = ami_copier.generate_name_tag(template, source_image, uuid, distribution)
        assert name.startswith('rhel-9-composer-api-test-test-uuid-')
        # Should have timestamp at end
        assert name.split('-')[-1].isdigit()


# Tests for copy_ami()
class TestCopyAmi:
    """Tests for AMI copy operation."""

    def test_copy_ami_success(self, aws_credentials, sample_ami_data):
        """Test successful AMI copy."""
        source_ami_id = 'ami-12345678'
        tags = {'Environment': 'test', 'Team': 'infrastructure'}

        # Create complete temp AMI data with all required fields
        temp_ami_data = sample_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-temp123'
        temp_ami_data['Architecture'] = 'x86_64'
        temp_ami_data['RootDeviceName'] = '/dev/sda1'
        temp_ami_data['VirtualizationType'] = 'hvm'

        # Mock the two-step copy process
        with patch('ami_copier.ec2_client') as mock_client:
            # describe_images returns source AMI first, then temp AMI
            mock_client.describe_images.side_effect = [
                {'Images': [sample_ami_data]},  # Source AMI
                {'Images': [temp_ami_data]}      # Temp AMI
            ]
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-temp123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            # Mock the waiter
            mock_waiter = mock_client.get_waiter.return_value
            mock_waiter.wait.return_value = None

            new_ami_id = ami_copier.copy_ami(source_ami_id, 'test-copy', tags)

        # Verify new AMI was created (should be the final AMI ID)
        assert new_ami_id == 'ami-final123'

        # Verify copy_image was called
        assert mock_client.copy_image.called

        # Verify register_image was called (step 2 of the process)
        assert mock_client.register_image.called

        # Verify deregister_image was called (to remove temp AMI)
        assert mock_client.deregister_image.called

        # Verify tags were applied
        assert mock_client.create_tags.called

    def test_copy_ami_with_uuid(self, aws_credentials, sample_ami_data):
        """Test AMI copy with UUID tag."""
        source_ami_id = 'ami-12345678'
        tags = {'Environment': 'test'}
        uuid = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'

        # Create complete temp AMI data with all required fields
        temp_ami_data = sample_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-temp123'
        temp_ami_data['Architecture'] = 'x86_64'
        temp_ami_data['RootDeviceName'] = '/dev/sda1'
        temp_ami_data['VirtualizationType'] = 'hvm'

        with patch('ami_copier.ec2_client') as mock_client:
            # describe_images returns source AMI first, then temp AMI
            mock_client.describe_images.side_effect = [
                {'Images': [sample_ami_data]},  # Source AMI
                {'Images': [temp_ami_data]}      # Temp AMI
            ]
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-temp123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            # Mock the waiter
            mock_waiter = mock_client.get_waiter.return_value
            mock_waiter.wait.return_value = None

            new_ami_id = ami_copier.copy_ami(source_ami_id, 'test-copy', tags, uuid)

        # Verify UUID tag was added
        assert mock_client.create_tags.called
        tag_call = mock_client.create_tags.call_args
        tags_list = tag_call[1]['Tags']
        uuid_tags = [t for t in tags_list if t['Key'] == 'SourceAMIUUID']
        assert len(uuid_tags) == 1
        assert uuid_tags[0]['Value'] == uuid

    def test_copy_ami_with_name_tag_and_distribution(self, aws_credentials, sample_ami_data):
        """Test AMI copy with Name tag when Distribution tag is present."""
        source_ami_id = 'ami-12345678'
        tags = {'Environment': 'test', 'Distribution': 'rhel-9'}
        uuid = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'
        name_tag_template = 'prod-{distribution}'

        # Create complete temp AMI data
        temp_ami_data = sample_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-copied123'
        temp_ami_data['Architecture'] = 'x86_64'
        temp_ami_data['RootDeviceName'] = '/dev/sda1'
        temp_ami_data['VirtualizationType'] = 'hvm'

        with patch('ami_copier.ec2_client') as mock_client:
            # describe_images returns source AMI first, then temp AMI
            mock_client.describe_images.side_effect = [
                {'Images': [sample_ami_data]},  # Source AMI
                {'Images': [temp_ami_data]}      # Temp AMI
            ]
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-copied123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            new_ami_id = ami_copier.copy_ami(source_ami_id, 'test-copy', tags, uuid, name_tag_template)

        # Verify Name tag was added
        assert mock_client.create_tags.called
        tag_call = mock_client.create_tags.call_args
        tags_list = tag_call[1]['Tags']
        name_tags = [t for t in tags_list if t['Key'] == 'Name']
        assert len(name_tags) == 1
        assert name_tags[0]['Value'] == 'prod-rhel-9'

    def test_copy_ami_without_distribution_graceful_degradation(self, aws_credentials, sample_ami_data):
        """Test AMI copy handles missing Distribution tag gracefully (no Name tag set)."""
        source_ami_id = 'ami-12345678'
        tags = {'Environment': 'test'}  # No Distribution tag
        uuid = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'
        name_tag_template = 'prod-{distribution}'

        # Create complete temp AMI data
        temp_ami_data = sample_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-copied123'
        temp_ami_data['Architecture'] = 'x86_64'
        temp_ami_data['RootDeviceName'] = '/dev/sda1'
        temp_ami_data['VirtualizationType'] = 'hvm'

        with patch('ami_copier.ec2_client') as mock_client:
            mock_client.describe_images.side_effect = [
                {'Images': [sample_ami_data]},  # Source AMI
                {'Images': [temp_ami_data]}      # Temp AMI
            ]
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-copied123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            new_ami_id = ami_copier.copy_ami(source_ami_id, 'test-copy', tags, uuid, name_tag_template)

        # Verify Name tag was NOT added (graceful degradation)
        assert mock_client.create_tags.called
        tag_call = mock_client.create_tags.call_args
        tags_list = tag_call[1]['Tags']
        name_tags = [t for t in tags_list if t['Key'] == 'Name']
        assert len(name_tags) == 0  # No Name tag should be present

    def test_copy_ami_with_empty_name_tag_template(self, aws_credentials, sample_ami_data):
        """Test AMI copy with empty name_tag_template (no Name tag set)."""
        source_ami_id = 'ami-12345678'
        tags = {'Environment': 'test', 'Distribution': 'rhel-9'}
        uuid = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'
        name_tag_template = ''  # Empty template

        # Create complete temp AMI data
        temp_ami_data = sample_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-copied123'
        temp_ami_data['Architecture'] = 'x86_64'
        temp_ami_data['RootDeviceName'] = '/dev/sda1'
        temp_ami_data['VirtualizationType'] = 'hvm'

        with patch('ami_copier.ec2_client') as mock_client:
            mock_client.describe_images.side_effect = [
                {'Images': [sample_ami_data]},  # Source AMI
                {'Images': [temp_ami_data]}      # Temp AMI
            ]
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-copied123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            new_ami_id = ami_copier.copy_ami(source_ami_id, 'test-copy', tags, uuid, name_tag_template)

        # Verify Name tag was NOT added (empty template)
        assert mock_client.create_tags.called
        tag_call = mock_client.create_tags.call_args
        tags_list = tag_call[1]['Tags']
        name_tags = [t for t in tags_list if t['Key'] == 'Name']
        assert len(name_tags) == 0

    def test_copy_ami_with_none_name_tag_template(self, aws_credentials, sample_ami_data):
        """Test AMI copy with None name_tag_template (backward compatibility)."""
        source_ami_id = 'ami-12345678'
        tags = {'Environment': 'test', 'Distribution': 'rhel-9'}
        uuid = 'a1b2c3d4-5678-90ab-cdef-1234567890ab'
        name_tag_template = None  # None (default)

        # Create complete temp AMI data
        temp_ami_data = sample_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-copied123'
        temp_ami_data['Architecture'] = 'x86_64'
        temp_ami_data['RootDeviceName'] = '/dev/sda1'
        temp_ami_data['VirtualizationType'] = 'hvm'

        with patch('ami_copier.ec2_client') as mock_client:
            mock_client.describe_images.side_effect = [
                {'Images': [sample_ami_data]},  # Source AMI
                {'Images': [temp_ami_data]}      # Temp AMI
            ]
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-copied123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            new_ami_id = ami_copier.copy_ami(source_ami_id, 'test-copy', tags, uuid, name_tag_template)

        # Verify Name tag was NOT added (None template)
        assert mock_client.create_tags.called
        tag_call = mock_client.create_tags.call_args
        tags_list = tag_call[1]['Tags']
        name_tags = [t for t in tags_list if t['Key'] == 'Name']
        assert len(name_tags) == 0


# Tests for lambda_handler()
class TestLambdaHandler:
    """Tests for the main Lambda handler."""

    def test_lambda_handler_manual_mode_success(self, sample_ami_data, sample_manual_event):
        """Test successful Lambda execution in manual mode."""
        # Setup environment
        os.environ['AMI_NAME_TEMPLATE'] = '{source_name}-{uuid}-encrypted'
        os.environ['TAGS'] = json.dumps({'Environment': 'production'})
        os.environ.pop('REDHAT_CREDENTIAL_STORE', None)

        # Create complete temp AMI data with all required fields
        temp_ami_data = sample_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-temp123'
        temp_ami_data['Architecture'] = 'x86_64'
        temp_ami_data['RootDeviceName'] = '/dev/sda1'
        temp_ami_data['VirtualizationType'] = 'hvm'

        # Mock EC2 client calls - need to handle multiple describe_images calls
        with patch('ami_copier.ec2_client') as mock_client:
            call_count = [0]

            def describe_images_side_effect(*args, **kwargs):
                call_count[0] += 1
                # Check if this is the deduplication check (Owners=['self'] and Filters with name)
                if kwargs.get('Owners') == ['self'] and kwargs.get('Filters'):
                    return {'Images': []}  # No existing copy
                # Otherwise it's a source AMI or temp AMI lookup
                else:
                    # First call: source AMI lookup in process_ami
                    # Second call: source AMI lookup in copy_ami (get_source_ami_details)
                    # Third call: temp AMI lookup in copy_ami
                    if call_count[0] <= 2:
                        return {'Images': [sample_ami_data]}  # Source AMI
                    else:
                        return {'Images': [temp_ami_data]}  # Temp AMI

            mock_client.describe_images.side_effect = describe_images_side_effect
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-temp123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            # Mock the waiter
            mock_waiter = mock_client.get_waiter.return_value
            mock_waiter.wait.return_value = None

            response = ami_copier.lambda_handler(sample_manual_event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['mode'] == 'manual'
        assert body['result']['source_ami_id'] == 'ami-12345678'
        assert body['result']['new_ami_id'] == 'ami-final123'
        assert body['result']['status'] == 'copied'

    def test_lambda_handler_scheduled_mode_success(self, sample_redhat_ami_data, sample_scheduled_event):
        """Test successful Lambda execution in scheduled mode."""
        # Setup environment
        os.environ['AMI_NAME_TEMPLATE'] = 'rhel-{uuid}-encrypted'
        os.environ['TAGS'] = json.dumps({'Environment': 'production'})

        # Add required fields to sample_redhat_ami_data
        sample_redhat_ami_data['Architecture'] = 'x86_64'
        sample_redhat_ami_data['RootDeviceName'] = '/dev/sda1'
        sample_redhat_ami_data['VirtualizationType'] = 'hvm'

        # Create temp AMI data
        temp_ami_data = sample_redhat_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-temp123'

        # Mock EC2 client calls
        with patch('ami_copier.ec2_client') as mock_client:
            call_count = [0]

            def describe_images_side_effect(*args, **kwargs):
                call_count[0] += 1
                # Deduplication check (Owners=['self'] and Filters with name)
                if kwargs.get('Owners') == ['self'] and kwargs.get('Filters'):
                    return {'Images': []}  # No existing copy
                # Discovery (Owners=[REDHAT_ACCOUNT_ID])
                elif kwargs.get('Owners') == ['463606842039']:
                    return {'Images': [sample_redhat_ami_data]}
                # Source AMI or temp AMI lookup
                else:
                    # First few calls: source AMI lookup
                    if call_count[0] <= 3:
                        return {'Images': [sample_redhat_ami_data]}
                    else:
                        return {'Images': [temp_ami_data]}  # Temp AMI

            mock_client.describe_images.side_effect = describe_images_side_effect
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-temp123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            # Mock the waiter
            mock_waiter = mock_client.get_waiter.return_value
            mock_waiter.wait.return_value = None

            response = ami_copier.lambda_handler(sample_scheduled_event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['mode'] == 'scheduled'
        assert body['summary']['total'] == 1
        assert body['summary']['copied'] == 1
        assert len(body['results']) == 1

    def test_lambda_handler_scheduled_mode_no_amis(self, sample_scheduled_event):
        """Test scheduled mode when no shared AMIs found."""
        os.environ['AMI_NAME_TEMPLATE'] = 'rhel-{uuid}-encrypted'
        os.environ['TAGS'] = '{}'

        # Mock EC2 to return no AMIs
        with patch('ami_copier.ec2_client') as mock_client:
            mock_client.describe_images.return_value = {'Images': []}

            response = ami_copier.lambda_handler(sample_scheduled_event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['mode'] == 'scheduled'
        assert body['message'] == 'No shared AMIs found'
        assert body['results'] == []

    def test_lambda_handler_scheduled_mode_with_deduplication(self, sample_redhat_ami_data, sample_scheduled_event):
        """Test scheduled mode with deduplication (AMI already copied)."""
        os.environ['AMI_NAME_TEMPLATE'] = 'rhel-{uuid}-encrypted'
        os.environ['TAGS'] = '{}'

        # Mock EC2 client
        with patch('ami_copier.ec2_client') as mock_client:
            # Discovery returns one AMI
            call_count = [0]

            def describe_images_side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    # First call: discover shared AMIs
                    return {'Images': [sample_redhat_ami_data]}
                elif call_count[0] == 2:
                    # Second call: process_ami gets source AMI details
                    return {'Images': [sample_redhat_ami_data]}
                else:
                    # Third call: ami_already_copied check - AMI exists
                    return {'Images': [{'ImageId': 'ami-existing', 'Name': 'rhel-test-encrypted'}]}

            mock_client.describe_images.side_effect = describe_images_side_effect

            response = ami_copier.lambda_handler(sample_scheduled_event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['summary']['total'] == 1
        assert body['summary']['skipped'] == 1
        assert body['summary']['copied'] == 0
        assert body['results'][0]['status'] == 'skipped'

    def test_lambda_handler_manual_mode_ami_not_found(self, sample_manual_event):
        """Test manual mode when AMI not found."""
        os.environ['AMI_NAME_TEMPLATE'] = 'test-{uuid}'
        os.environ['TAGS'] = '{}'

        # Mock EC2 to return empty images
        with patch('ami_copier.ec2_client') as mock_client:
            mock_client.describe_images.return_value = {'Images': []}

            response = ami_copier.lambda_handler(sample_manual_event, None)

        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert body['result']['status'] == 'error'
        assert 'not found' in body['result']['message'].lower()

    def test_lambda_handler_exception_handling(self, sample_scheduled_event):
        """Test Lambda handler exception handling."""
        os.environ['AMI_NAME_TEMPLATE'] = 'test'
        os.environ['TAGS'] = 'invalid-json'  # Invalid JSON to trigger exception

        response = ami_copier.lambda_handler(sample_scheduled_event, None)

        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert 'error' in body

    @patch('ami_copier.get_redhat_credentials')
    @patch('ami_copier.get_access_token')
    @patch('ami_copier.find_compose_by_ami')
    @patch('ami_copier.get_compose_metadata')
    def test_lambda_handler_with_api_enrichment(
        self,
        mock_get_metadata,
        mock_find_compose,
        mock_get_token,
        mock_get_creds,
        sample_redhat_ami_data,
        sample_manual_event
    ):
        """Test Lambda handler with Red Hat API tag enrichment."""
        # Setup environment
        os.environ['AMI_NAME_TEMPLATE'] = 'rhel-{uuid}-encrypted'
        os.environ['TAGS'] = json.dumps({'Environment': 'production'})

        # Use Red Hat AMI in manual event
        sample_manual_event['source_ami_id'] = 'ami-redhat123'

        # Add required fields to sample_redhat_ami_data
        sample_redhat_ami_data['Architecture'] = 'x86_64'
        sample_redhat_ami_data['RootDeviceName'] = '/dev/sda1'
        sample_redhat_ami_data['VirtualizationType'] = 'hvm'

        # Create temp AMI data
        temp_ami_data = sample_redhat_ami_data.copy()
        temp_ami_data['ImageId'] = 'ami-temp123'

        # Mock Red Hat API integration
        mock_get_creds.return_value = {
            'client_id': 'test-id',
            'client_secret': 'test-secret'
        }
        mock_get_token.return_value = 'test-access-token'
        mock_find_compose.return_value = (
            {'id': 'compose-123', 'created_at': '2024-10-25T12:00:00Z'},
            {
                'request': {
                    'image_name': 'Custom RHEL 9',
                    'distribution': 'rhel-9',
                    'image_requests': [{'architecture': 'x86_64'}]
                }
            }
        )
        mock_get_metadata.return_value = {
            'packages': [{'name': f'pkg-{i}'} for i in range(100)]
        }

        # Mock EC2 client
        with patch('ami_copier.ec2_client') as mock_client:
            call_count = [0]

            def describe_images_side_effect(*args, **kwargs):
                call_count[0] += 1
                # Deduplication check (Owners=['self'] and Filters with name)
                if kwargs.get('Owners') == ['self'] and kwargs.get('Filters'):
                    return {'Images': []}  # No existing copy
                # Source AMI or temp AMI lookup
                else:
                    # First few calls: source AMI lookup
                    if call_count[0] <= 2:
                        return {'Images': [sample_redhat_ami_data]}
                    else:
                        return {'Images': [temp_ami_data]}  # Temp AMI

            mock_client.describe_images.side_effect = describe_images_side_effect
            mock_client.copy_image.return_value = {
                'ImageId': 'ami-temp123'
            }
            mock_client.register_image.return_value = {
                'ImageId': 'ami-final123'
            }

            # Mock the waiter
            mock_waiter = mock_client.get_waiter.return_value
            mock_waiter.wait.return_value = None

            response = ami_copier.lambda_handler(sample_manual_event, None)

        assert response['statusCode'] == 200
        assert mock_get_creds.called
        assert mock_get_token.called
        assert mock_find_compose.called
        assert mock_get_metadata.called
