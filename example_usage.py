"""
Example Usage and Testing of Offensive Security Agent

This script demonstrates how to use the security agent components
without requiring actual AWS credentials.
"""

import json
from datetime import datetime
from src.core.base_check import BaseCheck, SecurityFinding, Severity
from src.core.reporter import SecurityReporter
from src.utils.logger import get_logger


class ExampleCheck(BaseCheck):
    """Example security check that generates sample findings"""
    
    def execute(self, config):
        """Generate example findings for demonstration"""
        self.resources_scanned = 3
        
        # Critical Finding
        self.add_finding(SecurityFinding(
            check_name="ExampleCheck",
            resource_arn="arn:aws:s3:::example-public-bucket",
            severity=Severity.CRITICAL,
            title="S3 Bucket Publicly Accessible",
            description="Bucket 'example-public-bucket' has public read ACL",
            evidence={
                "acl": {
                    "Owner": {"DisplayName": "admin"},
                    "Grants": [
                        {
                            "Grantee": {
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                            },
                            "Permission": "READ"
                        }
                    ]
                }
            },
            business_impact="Public read access exposes sensitive data to internet",
            remediation="aws s3api put-bucket-acl --bucket example-public-bucket --access-control-policy private",
            confidence=1.0,
            timestamp=datetime.utcnow()
        ))
        
        # High Finding
        self.add_finding(SecurityFinding(
            check_name="ExampleCheck",
            resource_arn="arn:aws:iam::123456789012:user/admin-user",
            severity=Severity.HIGH,
            title="IAM User Without MFA",
            description="User 'admin-user' does not have MFA enabled",
            evidence={
                "user_name": "admin-user",
                "mfa_devices": [],
                "has_access_keys": True
            },
            business_impact="Users without MFA are vulnerable to credential theft",
            remediation="aws iam enable-mfa-device --user-name admin-user --serial-number <device-arn>",
            confidence=1.0,
            timestamp=datetime.utcnow()
        ))
        
        # Medium Finding
        self.add_finding(SecurityFinding(
            check_name="ExampleCheck",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345",
            severity=Severity.MEDIUM,
            title="Security Group Allows SSH from Internet",
            description="Security group allows SSH (port 22) from 0.0.0.0/0",
            evidence={
                "security_group_id": "sg-12345",
                "direction": "inbound",
                "ip_protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr": "0.0.0.0/0"
            },
            business_impact="SSH access from internet increases brute force attack surface",
            remediation="aws ec2 revoke-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0",
            confidence=1.0,
            timestamp=datetime.utcnow()
        ))
        
        return self.findings


def main():
    """Run example security check and generate reports"""
    print("="*70)
    print("Offensive Security Agent - Example Execution")
    print("="*70)
    
    # Initialize logger
    logger = get_logger("ExampleAgent", {"log_dir": "logs"})
    logger.info("Starting example security scan")
    
    # Create and run example check
    check = ExampleCheck(logger)
    findings = check.execute({})
    
    # Print findings summary
    print(f"\\n✅ Resources scanned: {check.resources_scanned}")
    print(f"🔍 Findings generated: {len(findings)}")
    print()
    
    # Print individual findings
    for i, finding in enumerate(findings, 1):
        severity_emoji = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Info": "ℹ️"
        }.get(finding.severity.value, "⚪")
        
        print(f"{i}. {severity_emoji} {finding.title}")
        print(f"   Resource: {finding.resource_arn}")
        print(f"   Severity: {finding.severity.value} ({finding.confidence:.0%} confidence)")
        print(f"   Impact: {finding.business_impact}")
        print()
    
    # Generate reports
    print("="*70)
    print("Generating reports...")
    print("="*70)
    
    # Create mock execution results
    execution_results = {
        "total_checks": 1,
        "successful_checks": 1,
        "failed_checks": 0,
        "check_results": [{
            "check_name": "ExampleCheck",
            "status": "success",
            "findings": [f.to_dict() for f in findings],
            "summary": check.get_summary()
        }],
        "execution_summary": {
            "duration_seconds": 1.5,
            "total_findings": len(findings),
            "severity_breakdown": {
                "Critical": 1,
                "High": 1,
                "Medium": 1,
                "Low": 0,
                "Info": 0
            },
            "api_errors": {
                "access_denied": 0,
                "rate_limit": 0,
                "other": 0
            }
        }
    }
    
    # Generate reports
    reporter = SecurityReporter(logger)
    report_paths = reporter.generate_reports(
        execution_results,
        [f.to_dict() for f in findings]
    )
    
    print(f"\\n✅ Reports generated:")
    print(f"   📄 JSON: {report_paths['json']}")
    print(f"   📝 Markdown: {report_paths['markdown']}")
    print()
    
    # Show JSON report snippet
    print("="*70)
    print("JSON Report Sample")
    print("="*70)
    
    with open(report_paths['json'], 'r') as f:
        json_report = json.load(f)
        print(f"Scan ID: {json_report['scan_metadata']['scan_id']}")
        print(f"Total Findings: {json_report['scan_metadata']['total_findings']}")
        print(f"\\nFirst finding (JSON):")
        print(json.dumps(json_report['findings'][0], indent=2)[:500] + "...")
    
    print("\\n" + "="*70)
    print("Example completed successfully!")
    print("="*70)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())