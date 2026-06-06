"""KMS Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class KMSSecurityCheck(BaseAWSCheck):
    """
    Check KMS keys for:
    - Keys with wide principal permissions
    - Keys approaching deletion
    - Key rotation disabled
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute KMS security checks"""
        self.setup_aws_client(config)
        kms_client = self.aws_manager.get_client("kms")
        
        self.logger.info(f"[{self.check_name}] Starting KMS security scan")
        
        try:
            # List all KMS keys
            response = kms_client.list_keys()
            keys = response.get("Keys", [])
            self.resources_scanned = len(keys)
            
            for key_info in keys:
                key_id = key_info["KeyId"]
                
                try:
                    # Get key details
                    key_metadata = kms_client.describe_key(KeyId=key_id)
                    key_arn = key_metadata["KeyMetadata"]["Arn"]
                    
                    # Check various aspects
                    self._check_key_rotation(kms_client, key_metadata, key_arn)
                    self._check_key_deletion(kms_client, key_metadata, key_arn)
                    self._check_key_permissions(kms_client, key_metadata, key_arn)
                    
                except ClientError as e:
                    if self.is_access_denied(e):
                        self.handle_aws_error(e, key_id, f"Cannot inspect key {key_id}")
                    else:
                        raise
                
        except ClientError as e:
            self.handle_aws_error(e, "kms:*", "Failed to list KMS keys")
        except Exception as e:
            self.logger.error(f"Unexpected error in KMS check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_key_rotation(
        self,
        kms_client,
        key_metadata: Dict[str, Any],
        key_arn: str
    ) -> None:
        """Check if key has automatic key rotation enabled"""
        key_id = key_metadata["KeyMetadata"]["KeyId"]
        key_spec = key_metadata["KeyMetadata"].get("KeySpec", "")
        
        # Key rotation only applies to symmetric CMKs
        if key_spec != "SYMMETRIC_DEFAULT":
            return
        
        try:
            rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)
            
            if not rotation_status.get("KeyRotationEnabled", False):
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=key_arn,
                    severity=Severity.MEDIUM,
                    title=f"KMS Key Rotation Disabled: {key_id}",
                    description=f"Symmetric KMS key {key_id} does not have automatic key rotation enabled",
                    evidence={
                        "key_id": key_id,
                        "rotation_enabled": rotation_status.get("KeyRotationEnabled", False)
                    },
                    business_impact=(
                        "Key rotation limits exposure if a key is compromised. "
                        "Without rotation, compromised keys remain valid indefinitely."
                    ),
                    remediation=(
                        f"aws kms enable-key-rotation --key-id {key_id}"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                
        except ClientError as e:
            # Some keys might not support rotation
            if not self.is_access_denied(e):
                self.logger.debug(f"Could not check rotation for key {key_id}: {e}")
    
    def _check_key_deletion(
        self,
        kms_client,
        key_metadata: Dict[str, Any],
        key_arn: str
    ) -> None:
        """Check if key is scheduled for deletion"""
        key_id = key_metadata["KeyMetadata"]["KeyId"]
        key_state = key_metadata["KeyMetadata"].get("KeyState", "")
        deletion_date = key_metadata["KeyMetadata"].get("DeletionDate")
        
        if key_state == "PendingDeletion":
            days_until_deletion = None
            if deletion_date:
                from datetime import datetime, timedelta
                days_until_deletion = (deletion_date - datetime.utcnow()).days
            
            self.add_finding(SecurityFinding(
                check_name=self.check_name,
                resource_arn=key_arn,
                severity=Severity.HIGH,
                title=f"KMS Key Pending Deletion: {key_id}",
                description=f"KMS key {key_id} is scheduled for deletion in {days_until_deletion} days",
                evidence={
                    "key_id": key_id,
                    "key_state": key_state,
                    "deletion_date": deletion_date.isoformat() if deletion_date else None,
                    "days_until_deletion": days_until_deletion
                },
                business_impact=(
                    f"Key deletion will permanently destroy all encrypted data that "
                    f"relies on this key. Ensure data is re-encrypted before deletion."
                ),
                remediation=(
                    f"To cancel deletion: aws kms cancel-key-deletion --key-id {key_id}\\n"
                    f"To schedule new deletion: aws kms schedule-key-deletion "
                    f"--key-id {key_id} --pending-window-in-days 30"
                ),
                confidence=1.0,
                timestamp=self._get_timestamp()
            ))
    
    def _check_key_permissions(
        self,
        kms_client,
        key_metadata: Dict[str, Any],
        key_arn: str
    ) -> None:
        """Check if key has overly permissive key policies"""
        key_id = key_metadata["KeyMetadata"]["KeyId"]
        
        try:
            policy = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
            policy_document = policy.get("Policy", "{}")
            
            # Check for dangerous wildcard permissions
            if self._has_dangerous_kms_policy(policy_document):
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=key_arn,
                    severity=Severity.HIGH,
                    title=f"KMS Key with Permissive Policy: {key_id}",
                    description=f"KMS key {key_id} has key policy that grants broad access",
                    evidence={
                        "key_id": key_id,
                        "policy_document": policy_document
                    },
                    business_impact=(
                        "Overly permissive key policies can allow unauthorized principals "
                        "to decrypt sensitive data or create new key grants."
                    ),
                    remediation=(
                        f"Review and restrict key policy for {key_id}. Use IAM policies "
                        f"instead of key policies where possible. Avoid '*' in Principal."
                    ),
                    confidence=0.8,  # Policy analysis can be complex
                    timestamp=self._get_timestamp()
                ))
                
        except ClientError as e:
            if not self.is_access_denied(e):
                self.logger.debug(f"Could not check key policy for {key_id}: {e}")
    
    def _has_dangerous_kms_policy(self, policy_document: str) -> bool:
        """Check if KMS key policy has dangerous permissions"""
        import json
        
        try:
            policy = json.loads(policy_document)
        except:
            return False
        
        statements = policy.get("Statement", [])
        
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            
            # Check for wildcard principal
            principal = statement.get("Principal", {})
            if isinstance(principal, str) and principal == "*":
                # Check if it allows kms:Decrypt or kms:*
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                
                dangerous_actions = ["kms:Decrypt", "kms:*", "*"]
                if any(action in dangerous_actions for action in actions):
                    return True
            
            # Check for AWS account wildcard (less dangerous but notable)
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS", "")
                if aws_principal == "*":
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    if "kms:Decrypt" in actions or "kms:*" in actions:
                        return True
        
        return False
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()