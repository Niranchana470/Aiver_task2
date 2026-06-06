"""Lambda Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class LambdaSecurityCheck(BaseAWSCheck):
    """
    Check Lambda functions for:
    - Functions with admin privileges
    - Functions without tracing
    - Public access via function URLs
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute Lambda security checks"""
        self.setup_aws_client(config)
        lambda_client = self.aws_manager.get_client("lambda")
        
        self.logger.info(f"[{self.check_name}] Starting Lambda security scan")
        
        try:
            # List all Lambda functions
            paginator = lambda_client.get_paginator('list_functions')
            page_iterator = paginator.paginate()
            
            for page in page_iterator:
                functions = page.get("Functions", [])
                self.resources_scanned += len(functions)
                
                for function in functions:
                    function_name = function["FunctionName"]
                    function_arn = function["FunctionArn"]
                    
                    # Check function permissions
                    self._check_lambda_permissions(lambda_client, function, function_arn)
                    
                    # Check tracing
                    self._check_lambda_tracing(lambda_client, function, function_arn)
                    
                    # Check public URL access
                    self._check_lambda_urls(lambda_client, function, function_arn)
                    
        except ClientError as e:
            self.handle_aws_error(e, "lambda:*", "Failed to list Lambda functions")
        except Exception as e:
            self.logger.error(f"Unexpected error in Lambda check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_lambda_permissions(
        self,
        lambda_client,
        function: Dict[str, Any],
        function_arn: str
    ) -> None:
        """Check if Lambda function has excessive IAM permissions"""
        function_name = function["FunctionName"]
        role_arn = function.get("Role", "")
        
        # Get IAM role name from ARN
        if role_arn:
            import re
            role_name_match = re.search(r'/([^/]+)$', role_arn)
            if role_name_match:
                role_name = role_name_match.group(1)
                
                try:
                    iam_client = self.aws_manager.get_client("iam")
                    
                    # Get the role policy
                    role_policy = iam_client.get_role(RoleName=role_name)
                    
                    # Check if role has AdministratorAccess
                    attached_policies = iam_client.list_attached_role_policies(
                        RoleName=role_name
                    )
                    
                    for policy in attached_policies.get("AttachedPolicies", []):
                        policy_name = policy.get("PolicyName", "")
                        if "Administrator" in policy_name:
                            self.add_finding(SecurityFinding(
                                check_name=self.check_name,
                                resource_arn=function_arn,
                                severity=Severity.CRITICAL,
                                title=f"Lambda with Admin Rights: {function_name}",
                                description=f"Lambda function '{function_name}' has role '{role_name}' with '{policy_name}' policy",
                                evidence={
                                    "function_name": function_name,
                                    "role_arn": role_arn,
                                    "policy_name": policy_name
                                },
                                business_impact=(
                                    "Lambda functions with admin privileges can access or "
                                    "modify any AWS resource if compromised."
                                ),
                                remediation=(
                                    f"Review and minimize Lambda execution role. Use principle "
                                    f"of least privilege: aws iam detach-role-policy "
                                    f"--role-name {role_name} --policy-arn {policy.get('PolicyArn')}"
                                ),
                                confidence=1.0,
                                timestamp=self._get_timestamp()
                            ))
                            return
                    
                except ClientError as e:
                    if self.is_access_denied(e):
                        self.logger.debug(f"Cannot check role {role_name}: Access denied")
    
    def _check_lambda_tracing(
        self,
        lambda_client,
        function: Dict[str, Any],
        function_arn: str
    ) -> None:
        """Check if Lambda has X-Ray tracing enabled"""
        function_name = function["FunctionName"]
        
        try:
            # Get function configuration
            config_response = lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            
            tracing_mode = config_response.get("TracingConfig", {}).get("Mode", "PassThrough")
            
            if tracing_mode == "PassThrough":
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=function_arn,
                    severity=Severity.LOW,
                    title=f"Lambda Tracing Disabled: {function_name}",
                    description=f"Lambda function '{function_name}' does not have active X-Ray tracing",
                    evidence={
                        "function_name": function_name,
                        "tracing_mode": tracing_mode
                    },
                    business_impact=(
                        "Without tracing, debugging and security analysis of Lambda "
                        "invocations is more difficult."
                    ),
                    remediation=(
                        f"aws lambda update-function-configuration "
                        f"--function-name {function_name} "
                        f"--tracing-config Mode=Active"
                    ),
                    confidence=1.0,
                    timestamp=self._get_timestamp()
                ))
                
        except ClientError as e:
            if not self.is_access_denied(e):
                self.logger.debug(f"Could not check tracing for {function_name}: {e}")
    
    def _check_lambda_urls(
        self,
        lambda_client,
        function: Dict[str, Any],
        function_arn: str
    ) -> None:
        """Check if Lambda has public function URL"""
        function_name = function["FunctionName"]
        
        try:
            # List function URLs
            urls_response = lambda_client.list_function_url_configs(
                FunctionName=function_name
            )
            
            for url_config in urls_response.get("FunctionUrlConfigs", []):
                auth_type = url_config.get("AuthType", "")
                
                if auth_type == "NONE":
                    self.add_finding(SecurityFinding(
                        check_name=self.check_name,
                        resource_arn=function_arn,
                        severity=Severity.HIGH,
                        title=f"Public Lambda URL: {function_name}",
                        description=f"Lambda function '{function_name}' has publicly accessible URL with no authentication",
                        evidence={
                            "function_name": function_name,
                            "auth_type": auth_type,
                            "url": url_config.get("FunctionUrl")
                        },
                        business_impact=(
                            "Public function URLs without authentication can be accessed "
                            "by anyone on the internet, potentially exposing sensitive data."
                        ),
                        remediation=(
                            f"aws lambda delete-function-url-config "
                            f"--function-name {function_name} "
                            f"--url-id <url-id>\\n"
                            f"Or update to use AWS IAM or API key authentication"
                        ),
                        confidence=1.0,
                        timestamp=self._get_timestamp()
                    ))
                    
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                self.logger.debug(f"Could not check URLs for {function_name}: {e}")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()