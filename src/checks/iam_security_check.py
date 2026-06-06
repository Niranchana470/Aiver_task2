"""IAM Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class IAMSecurityCheck(BaseAWSCheck):
    """
    Check IAM for:
    - Users without MFA
    - Password policy issues
    - Inline policies with wildcard permissions
    - Access keys older than 90 days
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute IAM security checks"""
        self.setup_aws_client(config)
        iam_client = self.aws_manager.get_client("iam")
        
        self.logger.info(f"[{self.check_name}] Starting IAM security scan")
        
        try:
            # Check password policy
            self._check_password_policy(iam_client)
            
            # Check users for MFA
            self._check_users_mfa(iam_client)
            
            # Check for dangerous inline policies
            self._check_inline_policies(iam_client)
            
            # Check access key age
            self._check_access_key_age(iam_client)
            
        except ClientError as e:
            self.handle_aws_error(e, "arn:aws:iam:::root", "Failed to perform IAM checks")
        except Exception as e:
            self.logger.error(f"Unexpected error in IAM check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_password_policy(self, iam_client) -> None:
        """Check account password policy"""
        try:
            policy = iam_client.get_account_password_policy()
            policy_details = policy.get("PasswordPolicy", {})
            
            issues = []
            
            # Check minimum password length
            if policy_details.get("MinimumPasswordLength", 0) < 12:
                issues.append("Minimum password length < 12")
            
            # Check for password requirements
            if not policy_details.get("RequireNumbers", False):
                issues.append("Does not require numbers")
            if not policy_details.get("RequireSymbols", False):
                issues.append("Does not require symbols")
            if not policy_details.get("RequireUppercaseCharacters", False):
                issues.append("Does not require uppercase")
            if not policy_details.get("RequireLowercaseCharacters", False):
                issues.append("Does not require lowercase")
            
            # Check for expiration
            if not policy_details.get("MaxPasswordAge", 0):
                issues.append("No password expiration set")
            elif policy_details.get("MaxPasswordAge", 0) > 90:
                issues.append("Password expiration > 90 days")
            
            if issues:
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=self.build_arn("iam", "account-password-policy"),
                    severity=Severity.MEDIUM,
                    title="IAM Password Policy Not Compliant",
                    description=f"Account password policy has {len(issues)} issues: {', '.join(issues)}",
                    evidence={
                        "password_policy": policy_details,
                        "issues": issues
                    },
                    business_impact=(
                        "Weak password policies increase risk of account compromise "
                        "through brute force or guessing attacks."
                    ),
                    remediation=(
                        "aws iam update-account-password-policy "
                        "--minimum-password-length 12 "
                        "--require-symbols --require-numbers "
                        "--require-uppercase-characters --require-lowercase-characters "
                        "--max-password-age 90 --password-reuse-prevention 24"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchEntity":
                # No password policy configured
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=self.build_arn("iam", "account-password-policy"),
                    severity=Severity.HIGH,
                    title="IAM Password Policy Not Configured",
                    description="Account does not have a custom password policy (using AWS defaults)",
                    evidence={
                        "error": "NoSuchEntity",
                        "aws_default_policy": "AWS default allows weak passwords"
                    },
                    business_impact=(
                        "Default password policy allows weak passwords, increasing "
                        "risk of unauthorized access."
                    ),
                    remediation=(
                        "aws iam update-account-password-policy "
                        "--minimum-password-length 12 "
                        "--require-symbols --require-numbers "
                        "--require-uppercase-characters --require-lowercase-characters "
                        "--max-password-age 90 --password-reuse-prevention 24"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
            else:
                self.handle_aws_error(
                    e,
                    self.build_arn("iam", "account-password-policy"),
                    "Failed to check password policy"
                )
    
    def _check_users_mfa(self, iam_client) -> None:
        """Check which users have MFA enabled"""
        try:
            users = iam_client.list_users()
            self.resources_scanned += len(users.get("Users", []))
            
            for user in users.get("Users", []):
                user_name = user["UserName"]
                user_arn = user["Arn"]
                
                # Check if user has MFA devices
                mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
                
                if len(mfa_devices.get("MFADevices", [])) == 0:
                    # Check if user has access keys (console users without MFA is critical)
                    access_keys = iam_client.list_access_keys(UserName=user_name)
                    has_access_keys = len(access_keys.get("AccessKeyMetadata", [])) > 0
                    
                    severity = Severity.CRITICAL if has_access_keys else Severity.HIGH
                    
                    self.add_finding(SecurityFinding(
                        check_name=self.check_name,
                        resource_arn=user_arn,
                        severity=severity,
                        title=f"IAM User Without MFA: {user_name}",
                        description=f"User {user_name} does not have MFA enabled",
                        evidence={
                            "user_name": user_name,
                            "mfa_devices": mfa_devices.get("MFADevices", []),
                            "has_access_keys": has_access_keys,
                            "access_keys_count": len(access_keys.get("AccessKeyMetadata", []))
                        },
                        business_impact=(
                            "Users without MFA are vulnerable to phishing and credential "
                            "theft. Console access without MFA is especially dangerous."
                        ),
                        remediation=(
                            f"aws iam enable-mfa-device --user-name {user_name} "
                            f"--serial-number <device-arn> --authentication-code-1 <code1> "
                            f"--authentication-code-2 <code2>"
                        ),
                        confidence=1.0,
                        timestamp=self._get_timestamp(),
                        metadata={"user_created_date": user.get("CreateDate")}
                    ))
                else:
                    self.logger.debug(f"User {user_name} has MFA enabled")
                    
        except ClientError as e:
            self.handle_aws_error(e, self.build_arn("iam", "users"), "Failed to check user MFA")
    
    def _check_inline_policies(self, iam_client) -> None:
        """Check for dangerous inline policies (wildcard permissions)"""
        try:
            users = iam_client.list_users()
            
            for user in users.get("Users", []):
                user_name = user["UserName"]
                
                # List inline user policies
                policies = iam_client.list_user_policies(UserName=user_name)
                
                for policy_name in policies.get("PolicyNames", []):
                    try:
                        policy_version = iam_client.get_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name
                        )
                        
                        policy_document = policy_version.get("PolicyDocument", {})
                        
                        # Check for dangerous wildcard permissions
                        if self._has_wildcard_permissions(policy_document):
                            self.add_finding(SecurityFinding(
                                check_name=self.check_name,
                                resource_arn=user["Arn"],
                                severity=Severity.CRITICAL,
                                title=f"Dangerous Inline Policy: {policy_name}",
                                description=f"User {user_name} has inline policy '{policy_name}' with wildcard permissions",
                                evidence={
                                    "user_name": user_name,
                                    "policy_name": policy_name,
                                    "policy_document": policy_document
                                },
                                business_impact=(
                                    "Wildcard permissions grant excessive access and "
                                    "increase blast radius of compromised credentials."
                                ),
                                remediation=(
                                    f"aws iam delete-user-policy --user-name {user_name} "
                                    f"--policy-name {policy_name}\\n"
                                    f"Then create scoped policies using principle of least privilege"
                                ),
                                confidence=1.0,
                                timestamp=self._get_timestamp()
                            ))
                            
                    except ClientError as e:
                        self.handle_aws_error(
                            e,
                            user["Arn"],
                            f"Failed to get policy {policy_name} for user {user_name}"
                        )
                    
        except ClientError as e:
            self.handle_aws_error(e, self.build_arn("iam", "users"), "Failed to check inline policies")
    
    def _has_wildcard_permissions(self, policy_document: Dict) -> bool:
        """Check if policy grants wildcard (*) permissions on resources"""
        if not isinstance(policy_document, dict):
            return False
        
        statements = policy_document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            
            effect = statement.get("Effect", "")
            if effect != "Allow":
                continue
            
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            
            # Normalize to lists
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for wildcard in actions and resources
            has_wildcard_action = any(action == "*" for action in actions)
            has_wildcard_resource = any(resource == "*" for resource in resources)
            
            if has_wildcard_action and has_wildcard_resource:
                return True
        
        return False
    
    def _check_access_key_age(self, iam_client) -> None:
        """Check for access keys older than 90 days"""
        try:
            users = iam_client.list_users()
            
            for user in users.get("Users", []):
                user_name = user["UserName"]
                
                access_keys = iam_client.list_access_keys(UserName=user_name)
                
                for key in access_keys.get("AccessKeyMetadata", []):
                    key_id = key["AccessKeyId"]
                    create_date = key["CreateDate"]
                    
                    # Calculate age
                    from datetime import datetime, timedelta
                    age_days = (datetime.utcnow() - create_date).days
                    
                    if age_days > 90:
                        self.add_finding(SecurityFinding(
                            check_name=self.check_name,
                            resource_arn=user["Arn"],
                            severity=Severity.LOW,
                            title=f"Old Access Key: {key_id}",
                            description=f"Access key {key_id} for user {user_name} is {age_days} days old",
                            evidence={
                                "user_name": user_name,
                                "access_key_id": key_id,
                                "age_days": age_days,
                                "create_date": create_date.isoformat(),
                                "status": key.get("Status")
                            },
                            business_impact=(
                                f"Long-lived access keys ({age_days} days) increase risk "
                                "if credentials are exposed. Rotate keys regularly."
                            ),
                            remediation=(
                                f"aws iam delete-access-key --user-name {user_name} "
                                f"--access-key-id {key_id}\\n"
                                f"Then create new access key and update applications"
                            ),
                            confidence=1.0,
                            timestamp=self._get_timestamp()
                        ))
                        
        except ClientError as e:
            self.handle_aws_error(e, self.build_arn("iam", "users"), "Failed to check access key age")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()