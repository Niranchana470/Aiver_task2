# Offensive Security Agent

A production-grade, autonomous security scanning system for AWS infrastructure that acts as a "paranoid auditor" for cloud security posture.

## Architecture Overview

The agent is built with clear separation of concerns and extensible design:

```
offensive-security-agent/
├── main.py                      # Entry point and orchestrator
├── config/
│   └── security_config.yaml     # Security check configuration
├── src/
│   ├── core/                     # Core framework
│   │   ├── base_check.py        # Abstract base class for all checks
│   │   ├── check_engine.py      # Parallel check orchestration engine
│   │   ├── config_loader.py     # Configuration management
│   │   └── reporter.py          # Report generation (JSON + Markdown)
│   ├── checks/                   # Individual security checks
│   │   ├── base_aws_check.py    # AWS-specific base class
│   │   ├── s3_security_check.py
│   │   ├── iam_security_check.py
│   │   ├── security_group_check.py
│   │   ├── ec2_security_check.py
│   │   ├── rds_security_check.py
│   │   ├── kms_security_check.py
│   │   ├── cloudtrail_security_check.py
│   │   └── lambda_security_check.py
│   └── utils/                    # Utility modules
│       ├── aws_client.py        # AWS client management
│       └── logger.py            # Structured logging
├── logs/                         # Structured JSON logs
└── reports/                      # Generated security reports
```

### Key Components

1. **Check Engine** (`check_engine.py`)
   - Orchestrates parallel execution of security checks
   - Manages concurrency and timeouts
   - Aggregates findings across all checks

2. **Base Check Interface** (`base_check.py`)
   - Abstract base class enforcing consistent check implementation
   - Structured finding data model with severity levels
   - Automatic validation and confidence scoring

3. **AWS Client Manager** (`aws_client.py`)
   - Centralized boto3 session management
   - Proper error handling for AWS API errors (403, 429)
   - Context-aware error reporting

4. **Security Reporter** (`reporter.py`)
   - Generates JSON reports for automation
   - Generates Markdown reports for human consumption
   - Provides executive summary with severity breakdown

## Features - Level 1: Infrastructure Scanning

✅ **8 Comprehensive Security Checks**
- S3: Public ACLs, encryption, versioning, public access blocks
- IAM: MFA status, password policy, inline policies, access key age
- Security Groups: Open ports to 0.0.0.0/0, protocol-specific risks
- EC2: EBS encryption, IMDSv2 enforcement
- RDS: Storage encryption, public accessibility, backup retention
- KMS: Key rotation, deletion status, policy permissions
- CloudTrail: Trail status, encryption, multi-region, CloudWatch integration
- Lambda: Admin privileges, tracing, public function URLs

✅ **Zero False Positive Guarantee on Critical Findings**
- Confidence scoring system (0.0 to 1.0)
- Critical findings require ≥80% confidence
- Raw API evidence included for every finding

✅ **Comprehensive Error Handling**
- Explicit logging of 403 (Access Denied) errors
- Explicit logging of 429 (Rate Limit) errors
- Partial results with clear error reporting

✅ **Rich Finding Context**
Every finding includes:
- Resource ARN
- Severity (Critical → Info)
- Title and description
- Raw API evidence
- Business impact assessment
- Step-by-step remediation commands
- Confidence score
- Timestamp

✅ **Dual Output Formats**
- JSON: Machine-readable for automation and CI/CD integration
- Markdown: Human-readable with executive summary and severity breakdown

## Setup Instructions

### Prerequisites

1. Python 3.8 or higher
2. AWS credentials configured (via `aws configure` or environment variables)
3. Required IAM permissions (see below)

### Installation

```bash
# Clone the repository
cd offensive-security-agent

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure
```

### IAM Permissions

The agent requires read-only security audit permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetPublicAccessBlock",
        "iam:ListUsers",
        "iam:GetAccountPasswordPolicy",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "rds:DescribeDBInstances",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:GetKeyPolicy",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctionUrlConfigs",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Usage

### Basic Scan

```bash
python main.py
```

### Custom Configuration

```bash
python main.py -c /path/to/custom_config.yaml
```

### Configuration

Edit `config/security_config.yaml` to enable/disable checks:

```yaml
checks:
  S3SecurityCheck:
    enabled: true
    severity_threshold: Info
    timeout: 300
  
  IAMSecurityCheck:
    enabled: true
    severity_threshold: Info
    timeout: 300
```

### Output

The agent generates two reports in the `reports/` directory:

1. **JSON Report**: `{scan_id}_report.json`
   - Complete machine-readable findings
   - Raw API evidence
   - Execution statistics

2. **Markdown Report**: `{scan_id}_report.md`
   - Human-readable executive summary
   - Findings grouped by severity
   - Step-by-step remediation commands

### Example Output

```
================================================================================
SECURITY SCAN SUMMARY
================================================================================
Scan ID: scan_20240106_143022
Duration: 45.23 seconds
Checks Executed: 8
Total Findings: 23

Severity Breakdown:
  🔴 CRITICAL: 3
  🟠 HIGH: 8
  🟡 MEDIUM: 7
  🟢 LOW: 5
  ℹ️  INFO: 0

Reports Generated:
  📄 JSON: reports/scan_20240106_143022_report.json
  📝 Markdown: reports/scan_20240106_143022_report.md
================================================================================
```

## Extensibility

### Adding New Checks

1. Create a new check class inheriting from `BaseAWSCheck`:

```python
from src.checks.base_aws_check import BaseAWSCheck
from src.core.base_check import SecurityFinding, Severity

class MyCustomCheck(BaseAWSCheck):
    def execute(self, config):
        self.setup_aws_client(config)
        # Your check logic here
        return self.findings
```

2. Register the check in `main.py`:

```python
from src.checks.my_custom_check import MyCustomCheck

# Add to all_checks list
all_checks = [
    # ... existing checks ...
    MyCustomCheck,
]
```

3. Add configuration to `config/security_config.yaml`:

```yaml
checks:
  MyCustomCheck:
    enabled: true
    severity_threshold: Info
    timeout: 300
    parameters: {}
```

## Roadmap

### Level 2: Multi-Domain Extension (Planned)
- API endpoint scanning (CORS, rate limiting, auth bypass)
- Code dependency CVE scanning
- Secrets detection in repositories
- Triage layer with deduplication

### Level 3: Autonomous Operations (Planned)
- Scheduled scanning service
- Finding lifecycle database
- SLA alerting for Critical findings
- Security posture score trending

## Observability

All actions are logged to `logs/` with structured JSON format:

```json
{
  "timestamp": "2024-01-06T14:30:22.123Z",
  "level": "INFO",
  "logger": "S3SecurityCheck",
  "message": "Starting S3 security scan",
  "context": {
    "check_name": "S3SecurityCheck",
    "account_id": "123456789012"
  }
}
```

## Production Considerations

1. **Rate Limiting**: The agent uses concurrent workers (default: 10). Reduce `max_workers` in config if experiencing 429 errors.

2. **Access Denied**: 403 errors are logged explicitly. Review IAM permissions if findings are lower than expected.

3. **Long-Running Scans**: Large environments may take several minutes. Consider running in screen/tmux session.

4. **Integration**: JSON reports can be parsed by SIEM tools or monitoring systems for alerting.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please ensure:
- All new checks inherit from BaseCheck
- Findings include confidence scores
- Error handling uses record_api_error()
- Tests cover new functionality