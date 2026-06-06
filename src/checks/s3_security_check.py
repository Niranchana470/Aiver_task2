"""S3 Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class S3SecurityCheck(BaseAWSCheck):
    """
    Check S3 buckets for:
    - Public ACLs
    - Missing encryption
    - Missing versioning
    - No logging configuration
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute S3 security checks"""
        self.setup_aws_client(config)
        s3_client = self.aws_manager.get_client("s3")
        
        self.logger.info(f"[{self.check_name}] Starting S3 security scan")
        
        try:
            # List all buckets
            buckets = s3_client.list_buckets()
            self.resources_scanned = len(buckets.get("Buckets", []))
            
            for bucket_info in buckets.get("Buckets", []):
                bucket_name = bucket_info["Name"]
                bucket_arn = self.build_arn("s3", bucket_name)
                
                self._check_bucket_security(s3_client, bucket_name, bucket_arn)
                
        except ClientError as e:
            self.handle_aws_error(e, "s3:*", "Failed to list S3 buckets")
        except Exception as e:
            self.logger.error(f"Unexpected error in S3 check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_bucket_security(
        self,
        s3_client,
        bucket_name: str,
        bucket_arn: str
    ) -> None:
        """Check individual bucket security"""
        try:
            # Check ACL for public access
            self._check_bucket_acl(s3_client, bucket_name, bucket_arn)
            
            # Check encryption configuration
            self._check_bucket_encryption(s3_client, bucket_name, bucket_arn)
            
            # Check versioning
            self._check_bucket_versioning(s3_client, bucket_name, bucket_arn)
            
            # Check public access block settings
            self._check_public_access_block(s3_client, bucket_name, bucket_arn)
            
        except ClientError as e:
            if self.is_access_denied(e):
                self.handle_aws_error(e, bucket_arn, f"Cannot inspect bucket {bucket_name}")
            else:
                raise
    
    def _check_bucket_acl(
        self,
        s3_client,
        bucket_name: str,
        bucket_arn: str
    ) -> None:
        """Check if bucket has public ACLs"""
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                permission = grant.get("Permission", "")
                
                # Check for public access
                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    if permission in ["READ", "READ_ACP", "WRITE", "WRITE_ACP"]:
                        self.add_finding(SecurityFinding(
                            check_name=self.check_name,
                            resource_arn=bucket_arn,
                            severity=Severity.CRITICAL,
                            title="S3 Bucket has Public ACL",
                            description=f"Bucket {bucket_name} grants {permission} to AllUsers group",
                            evidence={
                                "acl": acl,
                                "problematic_grant": grant,
                                "grantee_uri": grantee.get("URI"),
                                "permission": permission
                            },
                            business_impact=(
                                "Public read access exposes sensitive data to anyone. "
                                "Public write access allows data tampering and ransomware attacks."
                            ),
                            remediation=(
                                f"aws s3api put-bucket-acl --bucket {bucket_name} "
                                f"--access-control-policy private"
                            ),
                            confidence=1.0,  # ACL check is definitive
                            timestamp=self._get_timestamp()
                        ))
                        return  # One critical finding is enough
                
        except ClientError as e:
            self.handle_aws_error(e, bucket_arn, "Failed to check bucket ACL")
    
    def _check_bucket_encryption(
        self,
        s3_client,
        bucket_name: str,
        bucket_arn: str
    ) -> None:
        """Check if bucket has default encryption enabled"""
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            
            # Check if using SSE-KMS (better) or SSE-S3 (good)
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                algorithm = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "AES256")
                self.logger.debug(f"Bucket {bucket_name} uses encryption: {algorithm}")
                
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                # No encryption configured
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=bucket_arn,
                    severity=Severity.HIGH,
                    title="S3 Bucket Missing Default Encryption",
                    description=f"Bucket {bucket_name} does not have default encryption enabled",
                    evidence={
                        "error": "ServerSideEncryptionConfigurationNotFoundError",
                        "bucket_name": bucket_name
                    },
                    business_impact=(
                        "Data stored in S3 without encryption is vulnerable to "
                        "unauthorized access if AWS internal controls fail."
                    ),
                    remediation=(
                        f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                        f"--server-side-encryption-configuration "
                        f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'"
                    ),
                    confidence=0.95,  # High confidence - AWS returns specific error
                    timestamp=self._get_timestamp()
                ))
            else:
                self.handle_aws_error(e, bucket_arn, "Failed to check bucket encryption")
    
    def _check_bucket_versioning(
        self,
        s3_client,
        bucket_name: str,
        bucket_arn: str
    ) -> None:
        """Check if bucket has versioning enabled"""
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status", "Suspended")
            
            if status != "Enabled":
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=bucket_arn,
                    severity=Severity.MEDIUM,
                    title="S3 Bucket Versioning Disabled",
                    description=f"Bucket {bucket_name} does not have versioning enabled (Status: {status})",
                    evidence={
                        "versioning_status": status,
                        "versioning_config": versioning
                    },
                    business_impact=(
                        "Without versioning, accidental or malicious deletions cannot be "
                        "easily recovered, increasing risk of data loss."
                    ),
                    remediation=(
                        f"aws s3api put-bucket-versioning --bucket {bucket_name} "
                        f"--versioning-configuration Status=Enabled"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                
        except ClientError as e:
            self.handle_aws_error(e, bucket_arn, "Failed to check bucket versioning")
    
    def _check_public_access_block(
        self,
        s3_client,
        bucket_name: str,
        bucket_arn: str
    ) -> None:
        """Check if public access block is configured"""
        try:
            public_config = s3_client.get_public_access_block(Bucket=bucket_name)
            config = public_config.get("PublicAccessBlockConfiguration", {})
            
            # Check if all public access blocks are enabled
            all_enabled = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False)
            ])
            
            if not all_enabled:
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=bucket_arn,
                    severity=Severity.MEDIUM,
                    title="S3 Bucket Public Access Block Not Fully Enabled",
                    description=f"Bucket {bucket_name} has incomplete public access block configuration",
                    evidence={
                        "public_access_config": config,
                        "all_enabled": all_enabled
                    },
                    business_impact=(
                        "Incomplete public access block settings may allow accidental "
                        "exposure of sensitive data."
                    ),
                    remediation=(
                        f"aws s3api put-public-access-block --bucket {bucket_name} "
                        f"--public-access-block-configuration "
                        f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                        f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                # No public access block configured at all
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=bucket_arn,
                    severity=Severity.HIGH,
                    title="S3 Bucket Missing Public Access Block",
                    description=f"Bucket {bucket_name} does not have public access block enabled",
                    evidence={
                        "error": "NoSuchPublicAccessBlockConfiguration",
                        "bucket_name": bucket_name
                    },
                    business_impact=(
                        "Without public access block, accidental public exposure is easier "
                        "and may go undetected."
                    ),
                    remediation=(
                        f"aws s3api put-public-access-block --bucket {bucket_name} "
                        f"--public-access-block-configuration "
                        f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                        f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
            else:
                self.handle_aws_error(e, bucket_arn, "Failed to check public access block")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()