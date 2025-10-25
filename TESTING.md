# Testing

This project includes comprehensive unit tests for the Lambda function.

## Test Coverage

The test suite covers:

- **Credential retrieval** from both SSM Parameter Store and Secrets Manager
- **Red Hat API authentication** using service accounts and legacy offline tokens
- **Red Hat API interactions** including compose lookup and metadata retrieval
- **AMI operations** including block device mapping conversion and AMI copying
- **Lambda handler** event processing with various scenarios

## Running Tests

### Prerequisites

1. Install `uv` (if not already installed):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   uv venv
   source .venv/bin/activate  # On macOS/Linux
   # .venv\Scripts\activate   # On Windows
   uv pip install -r requirements-dev.txt
   ```

### Run Tests

```bash
# Run all tests
uv run pytest tests/

# Run with verbose output
uv run pytest tests/ -v

# Run with coverage report
uv run pytest tests/ --cov=lambda --cov-report=term-missing

# Run specific test class
uv run pytest tests/test_ami_copier.py::TestGetRedhatCredentials -v

# Run specific test
uv run pytest tests/test_ami_copier.py::TestGetRedhatCredentials::test_ssm_credentials_success -v
```

### Coverage Reports

Coverage reports are generated in two formats:

1. **Terminal output** - Shows coverage summary with line numbers of missing coverage
2. **HTML report** - Detailed coverage report in `htmlcov/index.html`

To view the HTML coverage report:
```bash
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

## Test Structure

```
tests/
├── __init__.py
└── test_ami_copier.py  # Main test file with all test cases
```

### Test Classes

- **TestGetRedhatCredentials** - Tests for credential retrieval from SSM/Secrets Manager
- **TestGetAccessToken** - Tests for Red Hat API authentication
- **TestFindComposeByAmi** - Tests for Image Builder compose lookup
- **TestGetComposeMetadata** - Tests for compose metadata retrieval
- **TestEnrichTagsFromCompose** - Tests for tag enrichment logic
- **TestGetBlockDeviceMappings** - Tests for block device mapping conversion
- **TestGenerateAmiName** - Tests for AMI name generation
- **TestCopyAmi** - Tests for AMI copy operation
- **TestLambdaHandler** - Tests for the main Lambda handler function

## Mocking Strategy

The tests use:

- **moto** - For mocking AWS services (EC2, SSM, Secrets Manager)
- **unittest.mock** - For mocking HTTP requests and other Python operations

### Key Fixtures

- `aws_credentials` - Sets up AWS credentials for moto
- `mock_ec2_client` - Provides a mocked EC2 client
- `mock_ssm_client` - Provides a mocked SSM client
- `mock_secretsmanager_client` - Provides a mocked Secrets Manager client
- `sample_ami_data` - Sample AMI data for testing
- `sample_eventbridge_event` - Sample EventBridge event structure

## Current Test Results

```
31 tests passed
92% code coverage
```

### Coverage Summary

The following areas have test coverage:

- ✅ Credential retrieval (SSM and Secrets Manager)
- ✅ Red Hat API authentication (service account and offline token)
- ✅ Compose lookup and metadata retrieval
- ✅ Tag enrichment logic
- ✅ Block device mapping conversion
- ✅ AMI name generation
- ✅ AMI copy operations
- ✅ Lambda handler event processing
- ✅ Error handling and edge cases

### Uncovered Code

The 8% of uncovered code consists mainly of:

- Defensive error handling branches that are hard to trigger in tests
- Edge cases in AWS API error responses
- Some logging statements

## Continuous Integration

To integrate these tests into CI/CD:

```yaml
# Example GitHub Actions workflow
- name: Install dependencies
  run: |
    pip install uv
    uv venv
    source .venv/bin/activate
    uv pip install -r requirements-dev.txt

- name: Run tests
  run: |
    source .venv/bin/activate
    uv run pytest tests/ -v --cov=lambda --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## Adding New Tests

When adding new tests:

1. Add test methods to the appropriate test class
2. Use descriptive test names that explain what is being tested
3. Follow the Arrange-Act-Assert pattern
4. Mock external dependencies (AWS services, HTTP requests)
5. Test both success and failure scenarios
6. Update this documentation if adding new test classes

## Troubleshooting

### Import Errors

If you encounter import errors, ensure the virtual environment is activated:
```bash
source .venv/bin/activate
```

### Moto Version Incompatibility

This project uses moto v5+. If you see import errors related to `mock_ec2`, ensure you have the latest version:
```bash
uv pip install --upgrade moto
```

### Test Failures

If tests fail unexpectedly:

1. Check that environment variables are not interfering (tests manage their own env vars)
2. Ensure you're using Python 3.8+
3. Clear pytest cache: `rm -rf .pytest_cache`
4. Reinstall dependencies: `uv pip install -r requirements-dev.txt --force-reinstall`
