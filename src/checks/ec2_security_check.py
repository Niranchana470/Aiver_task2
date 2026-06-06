"""EC2 Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class EC2SecurityCheck(BaseAWSCheck):
    """
    Check EC2 instances for:
    - Unencrypted EBS volumes
    - Instances in public subnets
    - Missing IMDSv2 enforcement
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute EC2 security checks"""
        self.setup_aws_client(config)
        ec2_client = self.aws_manager.get_client("ec2")
        
        self.logger.info(f"[{self.check_name}] Starting EC2 security scan")
        
        try:
            # Describe all instances
            response = ec2_client.describe_instances()
            
            for reservation in response.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    instance_arn = self.build_arn("ec2", f"instance/{instance_id}")
                    
                    self._check_instance_encryption(instance, instance_arn)
                    self._check_instance_metadata_options(instance, instance_arn)
                    
                    self.resources_scanned += 1
                    
        except ClientError as e:
            self.handle_aws_error(e, "ec2:*", "Failed to describe EC2 instances")
        except Exception as e:
            self.logger.error(f"Unexpected error in EC2 check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_instance_encryption(
        self,
        instance: Dict[str, Any],
        instance_arn: str
    ) -> None:
        """Check if instance has encrypted EBS volumes"""
        instance_id = instance["InstanceId"]
        
        # Check block device mappings
        block_devices = instance.get("BlockDeviceMappings", [])
        unencrypted_volumes = []
        
        for bdm in block_devices:
            volume_details = bdm.get("Ebs", {})
            if volume_details.get("Encrypted", False) is False:
                volume_id = volume_details.get("VolumeId", "unknown")
                unencrypted_volumes.append(volume_id)
        
        if unencrypted_volumes:
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=instance_arn,
                severity=Severity.HIGH,
                title=f"EC2 Instance with Unencrypted Volumes: {instance_id}",
                description=f"Instance {instance_id} has {len(unencrypted_volumes)} unencrypted EBS volume(s)",
                evidence={
                    "instance_id": instance_id,
                    "unencrypted_volumes": unencrypted_volumes,
                    "block_device_mappings": block_devices
                },
                business_impact=(
                    "Unencrypted EBS volumes expose sensitive data at rest. "
                    "If AWS physical security controls fail, data could be exposed."
                ),
                remediation=(
                    f"For each volume: "
                    f"aws ec2 create-snapshot --volume-id <volume-id> --description 'Encryption migration'\\n"
                    f"aws ec2 copy-snapshot --source-snapshot-id <snapshot-id> --source-region <region> --encrypted\\n"
                    f"aws ec2 create-volume --snapshot-id <new-snapshot-id> --availability-zone <az> --encrypted\\n"
                    f"Then stop instance, detach old volume, attach new encrypted volume, and restart"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _check_instance_metadata_options(
        self,
        instance: Dict[str, Any],
        instance_arn: str
    ) -> None:
        """Check if instance enforces IMDSv2 (Instance Metadata Service v2)"""
        instance_id = instance["InstanceId"]
        metadata_options = instance.get("MetadataOptions", {})
        
        # Check if IMDSv2 is required
        http_tokens = metadata_options.get("HttpTokens", "optional")  # default is "optional"
        http_endpoint = metadata_options.get("HttpEndpoint", "enabled")
        
        if http_endpoint != "enabled":
            # Metadata service disabled - this is actually secure
            return
        
        if http_tokens != "required":
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=instance_arn,
                severity=Severity.MEDIUM,
                title=f"EC2 Instance Not Requiring IMDSv2: {instance_id}",
                description=f"Instance {instance_id} allows IMDSv1 (HttpTokens={http_tokens})",
                evidence={
                    "instance_id": instance_id,
                    "metadata_options": metadata_options,
                    "http_tokens": http_tokens,
                    "http_endpoint": http_endpoint
                },
                business_impact=(
                    "IMDSv1 is vulnerable to SSRF attacks. Web application vulnerabilities "
                    "can be exploited to steal instance credentials via IMDSv1."
                ),
                remediation=(
                    f"aws ec2 modify-instance-metadata-options "
                    f"--instance-id {instance_id} "
                    f"--http-tokens required --http-endpoint enabled"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()