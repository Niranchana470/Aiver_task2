"""CloudTrail Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class CloudTrailSecurityCheck(BaseAWSCheck):
    """
    Check CloudTrail for:
    - Missing trail in region
    - Trail not logging to CloudWatch
    - Trail not encrypted
    - Trail not enabled for all regions
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute CloudTrail security checks"""
        self.setup_aws_client(config)
        cloudtrail_client = self.aws_manager.get_client("cloudtrail")
        
        self.logger.info(f"[{self.check_name}] Starting CloudTrail security scan")
        
        try:
            # Describe all trails
            response = cloudtrail_client.describe_trails()
            trails = response.get("trailList", [])
            self.resources_scanned = len(trails)
            
            if not trails:
                # No trails at all - critical finding
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=self.build_arn("cloudtrail", "aws-account"),
                    severity=Severity.CRITICAL,
                    title="No CloudTrail Configured",
                    description="AWS account has no CloudTrail trails configured",
                    evidence={
                        "trails_found": 0,
                        "region": self.aws_manager._region
                    },
                    business_impact=(
                        "Without CloudTrail, you cannot audit API activity or detect "
                        "security incidents. Compliance frameworks require CloudTrail."
                    ),
                    remediation=(
                        "aws cloudtrail create-trail "
                        "--name security-trail "
                        "--s3-bucket-name <logging-bucket> "
                        "--include-global-services-events "
                        "--is-multi-region"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                return self.findings
            
            # Check each trail
            for trail in trails:
                trail_arn = trail.get("TrailARN", "")
                trail_name = trail.get("Name", "unknown")
                
                # Check if trail is logging
                self._check_trail_logging(cloudtrail_client, trail, trail_arn)
                
                # Check encryption
                self._check_trail_encryption(trail, trail_arn)
                
                # Check multi-region
                self._check_trail_multi_region(trail, trail_arn)
                
                # Check CloudWatch logging
                self._check_trail_cloudwatch(cloudtrail_client, trail, trail_arn)
                
        except ClientError as e:
            self.handle_aws_error(e, "cloudtrail:*", "Failed to describe CloudTrail trails")
        except Exception as e:
            self.logger.error(f"Unexpected error in CloudTrail check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_trail_logging(
        self,
        cloudtrail_client,
        trail: Dict[str, Any],
        trail_arn: str
    ) -> None:
        """Check if trail is actively logging"""
        trail_name = trail.get("Name", "")
        
        try:
            status = cloudtrail_client.get_trail_status(Name=trail_arn)
            is_logging = status.get("IsLogging", False)
            
            if not is_logging:
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=trail_arn,
                    severity=Severity.CRITICAL,
                    title=f"CloudTrail Not Logging: {trail_name}",
                    description=f"CloudTrail '{trail_name}' exists but is not actively logging",
                    evidence={
                        "trail_name": trail_name,
                        "is_logging": is_logging,
                        "latest_delivery_time": status.get("LatestDeliveryTime"),
                        "time_logging_started": status.get("StartLoggingTime"),
                        "time_logging_stopped": status.get("StopLoggingTime")
                    },
                    business_impact=(
                        "Inactive CloudTrail cannot audit API activity or help with "
                        "incident response. Security events go undetected."
                    ),
                    remediation=(
                        f"aws cloudtrail start-logging --name {trail_name}"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                
        except ClientError as e:
            if not self.is_access_denied(e):
                self.logger.debug(f"Could not check trail status for {trail_name}: {e}")
    
    def _check_trail_encryption(
        self,
        trail: Dict[str, Any],
        trail_arn: str
    ) -> None:
        """Check if trail logs are encrypted"""
        trail_name = trail.get("Name", "")
        kms_key_id = trail.get("KmsKeyId", "")
        
        if not kms_key_id:
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=trail_arn,
                severity=Severity.HIGH,
                title=f"CloudTrail Not Encrypted: {trail_name}",
                description=f"CloudTrail '{trail_name}' does not use KMS encryption for log files",
                evidence={
                    "trail_name": trail_name,
                    "kms_key_id": kms_key_id
                },
                business_impact=(
                    "Unencrypted CloudTrail logs could be tampered with or read by "
                    "unauthorized parties if S3 bucket is compromised."
                ),
                remediation=(
                    f"aws cloudtrail update-trail --name {trail_name} "
                    f"--kms-key-id <kms-key-id>"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _check_trail_multi_region(
        self,
        trail: Dict[str, Any],
        trail_arn: str
    ) -> None:
        """Check if trail covers all regions"""
        trail_name = trail.get("Name", "")
        is_multi_region = trail.get("IsMultiRegionTrail", False)
        
        if not is_multi_region:
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=trail_arn,
                severity=Severity.HIGH,
                title=f"CloudTrail Not Multi-Region: {trail_name}",
                description=f"CloudTrail '{trail_name}' only logs to a single region",
                evidence={
                    "trail_name": trail_name,
                    "is_multi_region": is_multi_region,
                    "home_region": trail.get("HomeRegion")
                },
                business_impact=(
                    "Single-region trails miss activity in other regions, leaving "
                    "blind spots in security monitoring and compliance."
                ),
                remediation=(
                    f"aws cloudtrail update-trail --name {trail_name} --is-multi-region"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _check_trail_cloudwatch(
        self,
        cloudtrail_client,
        trail: Dict[str, Any],
        trail_arn: str
    ) -> None:
        """Check if trail sends events to CloudWatch Logs"""
        trail_name = trail.get("Name", "")
        
        try:
            # Check if trail has CloudWatch Logs configuration
            if not trail.get("CloudWatchLogsLogGroupArn"):
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=trail_arn,
                    severity=Severity.MEDIUM,
                    title=f"CloudTrail Not Logging to CloudWatch: {trail_name}",
                    description=f"CloudTrail '{trail_name}' does not send events to CloudWatch Logs",
                    evidence={
                        "trail_name": trail_name,
                        "cloudwatch_log_group": trail.get("CloudWatchLogsLogGroupArn")
                    },
                    business_impact=(
                        "Without CloudWatch Logs integration, you cannot easily query "
                        "recent API activity or set up real-time alerting."
                    ),
                    remediation=(
                        f"aws cloudtrail update-trail --name {trail_name} "
                        f"--cloud-watch-logs-log-group-arn <log-group-arn> "
                        f"--cloud-watch-logs-role-arn <role-arn>"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                
        except Exception as e:
            self.logger.debug(f"Could not check CloudWatch for {trail_name}: {e}")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()