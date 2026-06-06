"""RDS Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class RDSSecurityCheck(BaseAWSCheck):
    """
    Check RDS instances for:
    - Unencrypted storage
    - Public accessibility
    - Missing backup retention
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute RDS security checks"""
        self.setup_aws_client(config)
        rds_client = self.aws_manager.get_client("rds")
        
        self.logger.info(f"[{self.check_name}] Starting RDS security scan")
        
        try:
            # Describe all DB instances
            response = rds_client.describe_db_instances()
            db_instances = response.get("DBInstances", [])
            self.resources_scanned = len(db_instances)
            
            for db_instance in db_instances:
                db_id = db_instance["DBInstanceIdentifier"]
                db_arn = db_instance["DBInstanceArn"]
                
                # Check encryption
                self._check_rds_encryption(db_instance, db_arn)
                
                # Check public accessibility
                self._check_rds_public_access(db_instance, db_arn)
                
                # Check backup retention
                self._check_rds_backups(db_instance, db_arn)
                
        except ClientError as e:
            self.handle_aws_error(e, "rds:*", "Failed to describe RDS instances")
        except Exception as e:
            self.logger.error(f"Unexpected error in RDS check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_rds_encryption(
        self,
        db_instance: Dict[str, Any],
        db_arn: str
    ) -> None:
        """Check if RDS instance is encrypted"""
        db_id = db_instance["DBInstanceIdentifier"]
        encrypted = db_instance.get("StorageEncrypted", False)
        
        if not encrypted:
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=db_arn,
                severity=Severity.HIGH,
                title=f"RDS Instance Not Encrypted: {db_id}",
                description=f"RDS instance {db_id} does not have encryption at rest enabled",
                evidence={
                    "db_instance_id": db_id,
                    "storage_encrypted": encrypted,
                    "engine": db_instance.get("Engine"),
                    "engine_version": db_instance.get("EngineVersion")
                },
                business_impact=(
                    "Unencrypted database storage exposes sensitive data. "
                    "Compliance frameworks (HIPAA, PCI-DSS) require encryption."
                ),
                remediation=(
                    "To enable encryption, you must snapshot the instance, restore it "
                    "with encryption enabled, then switch applications to the new instance:\\n"
                    f"aws rds create-db-snapshot --db-instance-identifier {db_id} "
                    f"--db-snapshot-identifier {db_id}-pre-encryption-snapshot\\n"
                    f"aws rds restore-db-instance-from-db-snapshot "
                    f"--db-instance-identifier {db_id}-encrypted "
                    f"--db-snapshot-identifier <snapshot-arn> --kms-key-id <kms-key-id>"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _check_rds_public_access(
        self,
        db_instance: Dict[str, Any],
        db_arn: str
    ) -> None:
        """Check if RDS instance is publicly accessible"""
        db_id = db_instance["DBInstanceIdentifier"]
        publicly_accessible = db_instance.get("PubliclyAccessible", False)
        
        if publicly_accessible:
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=db_arn,
                severity=Severity.CRITICAL,
                title=f"RDS Instance Publicly Accessible: {db_id}",
                description=f"RDS instance {db_id} is configured to be publicly accessible from the internet",
                evidence={
                    "db_instance_id": db_id,
                    "publicly_accessible": publicly_accessible,
                    "endpoint": db_instance.get("Endpoint", {}).get("Address")
                },
                business_impact=(
                    "Publicly accessible databases can be attacked from anywhere on "
                    "the internet. Increases attack surface dramatically."
                ),
                remediation=(
                    f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                    f"--no-publicly-accessible --apply-immediately"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _check_rds_backups(
        self,
        db_instance: Dict[str, Any],
        db_arn: str
    ) -> None:
        """Check if RDS instance has adequate backup retention"""
        db_id = db_instance["DBInstanceIdentifier"]
        backup_retention = db_instance.get("BackupRetentionPeriod", 0)
        
        if backup_retention < 7:
            severity = Severity.HIGH if backup_retention == 0 else Severity.MEDIUM
            
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=db_arn,
                severity=severity,
                title=f"RDS Instance Low Backup Retention: {db_id}",
                description=f"RDS instance {db_id} has only {backup_retention} days of backup retention",
                evidence={
                    "db_instance_id": db_id,
                    "backup_retention_period": backup_retention,
                    "backup_window": db_instance.get("PreferredBackupWindow")
                },
                business_impact=(
                    "Insufficient backup retention increases risk of data loss "
                    "from accidental deletion, corruption, or ransomware attacks."
                ),
                remediation=(
                    f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                    f"--backup-retention-period 7 --apply-immediately"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()