# Quick Start Guide - Offensive Security Agent

## 5-Minute Setup

### Step 1: Install Dependencies
```bash
cd offensive-security-agent
pip install -r requirements.txt
```

### Step 2: Configure AWS Credentials
```bash
aws configure
# Enter your AWS Access Key ID and Secret Access Key
```

### Step 3: Test with Example (No AWS Required)
```bash
python example_usage.py
```

Expected output:
- 3 sample findings generated
- JSON and Markdown reports created in `reports/`
- Structured logs written to `logs/`

### Step 4: Run Real Scan (Requires AWS Access)
```bash
python main.py
```

## Understanding the Output

### Console Output
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

### JSON Report (`reports/scan_*.json`)
```json
{
  "scan_metadata": {
    "scan_id": "scan_20240106_143022",
    "total_findings": 23
  },
  "findings": [
    {
      "check_name": "S3SecurityCheck",
      "resource_arn": "arn:aws:s3:::example-bucket",
      "severity": "Critical",
      "title": "S3 Bucket Publicly Accessible",
      "evidence": {...},
      "remediation": "aws s3api put-bucket-acl..."
    }
  ]
}
```

### Markdown Report (`reports/scan_*.md`)
```markdown
# Security Scan Report

## Executive Summary
- **Total Findings:** 23
- **Critical:** 3

## 🔴 CRITICAL FINDINGS
### S3 Bucket Publicly Accessible
**Resource:** `arn:aws:s3:::example-bucket`
**Severity:** Critical
**Remediation:**
```bash
aws s3api put-bucket-acl --bucket example-bucket --access-control-policy private
```
```

## Common Issues

### Issue: "Access Denied" Errors
**Cause**: IAM permissions insufficient for scanning

**Solution**: Grant read-only security audit permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:ListAllMyBuckets",
      "s3:GetBucketAcl",
      "iam:ListUsers",
      "ec2:DescribeSecurityGroups"
    ],
    "Resource": "*"
  }]
}
```

### Issue: "Rate Limit" Errors
**Cause**: Too many concurrent API calls

**Solution**: Reduce workers in config:
```yaml
execution:
  max_workers: 5  # Default is 10
```

### Issue: No Findings Generated
**Cause**: Either (a) environment is secure, or (b) access denied prevented scanning

**Solution**: Check logs for errors:
```bash
cat logs/security_agent_*.log | grep "Access Denied"
```

## Configuration Tips

### Enable Specific Checks Only
```yaml
checks:
  S3SecurityCheck:
    enabled: true
  IAMSecurityCheck:
    enabled: true
  SecurityGroupCheck:
    enabled: false  # Disabled
```

### Adjust Severity Threshold
```yaml
checks:
  S3SecurityCheck:
    severity_threshold: High  # Only report High and above
```

### Increase Timeout for Large Environments
```yaml
checks:
  S3SecurityCheck:
    timeout: 600  # 10 minutes instead of 5
```

## Integration Examples

### CI/CD Integration
```bash
# Run scan and fail if Critical findings found
python main.py
exit_code=$?
if [ $exit_code -eq 2 ]; then
  echo "Critical findings detected!"
  exit 1
fi
```

### Slack Notification
```bash
# Send summary to Slack
SCAN_ID=$(ls -t reports/ | head -1 | sed 's/_report.json//')
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Security scan complete: $(cat reports/${SCAN_ID}_report.md | head -20)\"}" \
  $SLACK_WEBHOOK_URL
```

### SIEM Integration
```bash
# Send JSON to SIEM (Splunk example)
curl -X POST https://splunk-server:8088/services/collector \
  -H "Authorization: Splunk $TOKEN" \
  -d @reports/scan_*.json
```

## Performance Guidelines

| Environment Size | Recommended Workers | Expected Duration |
|------------------|---------------------|-------------------|
| Small (<100 resources) | 10 | 1-2 minutes |
| Medium (100-1000) | 10 | 5-10 minutes |
| Large (>1000) | 5-10 | 15-30 minutes |

## Troubleshooting

### Debug Mode
```bash
# Enable debug logging in config
logging:
  level: DEBUG
```

### Dry Run
```bash
# Test with example first
python example_usage.py
```

### Check Permissions
```bash
# Verify AWS credentials work
aws sts get-caller-identity
aws s3 ls
```

## Next Steps

1. Review generated reports in `reports/`
2. Address Critical and High findings first
3. Schedule regular scans (cron, systemd)
4. Integrate with existing security workflows
5. Consider extending to Level 2 features

## Support

For issues or questions:
1. Check logs in `logs/` directory
2. Review ARCHITECTURE.md for design details
3. Examine IMPLEMENTATION_SUMMARY.md for feature list
4. Run `example_usage.py` to verify installation