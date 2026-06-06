"""
Transparent Failure Handler - Detailed error explanations
The "Transparent Failure" trait - explains exactly what went wrong and what to do
"""
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ErrorCategory(Enum):
    """Categories of errors with specific explanations"""
    ACCESS_DENIED = "access_denied"
    RATE_LIMITED = "rate_limited"
    NETWORK_ERROR = "network_error"
    INVALID_INPUT = "invalid_input"
    RESOURCE_NOT_FOUND = "resource_not_found"
    DEPENDENCY_ERROR = "dependency_error"
    PERMISSION_MISSING = "permission_missing"
    QUOTA_EXCEEDED = "quota_exceeded"
    UNKNOWN = "unknown"


@dataclass
class ErrorExplanation:
    """Detailed explanation of an error with next steps"""
    error_category: ErrorCategory
    error_code: str
    error_message: str
    what_happened: str  # Plain English explanation
    why_it_happened: str  # Root cause
    what_we_tried: List[str]  # Recovery attempts already made
    what_is_needed: str  # What's required to proceed
    next_steps: List[str]  # Actionable next steps
    can_retry: bool
    retry_delay_seconds: Optional[int] = None
    severity: str = "error"  # error, warning, info


class FailureHandler:
    """
    Transparent failure handler - the "Transparent Failure" trait
    
    When something fails, it explains:
    1. Exactly what went wrong (not generic messages)
    2. Why it happened (root cause analysis)
    3. What was already tried (recovery attempts)
    4. What's needed from a human operator (specific requirements)
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.error_history: List[ErrorExplanation] = []
        
        # Error templates for common AWS errors
        self.error_templates = self._load_error_templates()
    
    def explain_error(self, error: Dict[str, Any], 
                     attempted_action: str,
                     recovery_attempts: Optional[List[str]] = None) -> ErrorExplanation:
        """
        Generate detailed explanation for an error
        
        Args:
            error: Error details (code, message, resource, etc.)
            attempted_action: What we were trying to do
            recovery_attempts: What we already tried to fix it
        """
        error_code = error.get("error_code", "Unknown")
        error_message = error.get("error_message", str(error))
        resource = error.get("resource", "unknown")
        
        self.logger.error(
            f"Explaining error: {error_code}",
            error_code=error_code,
            resource=resource,
            action=attempted_action
        )
        
        # Categorize the error
        category = self._categorize_error(error_code, error_message)
        
        # Generate explanation
        explanation = self._generate_explanation(
            category, error_code, error_message, resource, attempted_action, recovery_attempts
        )
        
        self.error_history.append(explanation)
        self._log_error_explanation(explanation)
        
        return explanation
    
    def _categorize_error(self, error_code: str, error_message: str) -> ErrorCategory:
        """Categorize error based on code and message"""
        error_code_upper = error_code.upper()
        error_message_lower = error_message.lower()
        
        # AWS-specific error codes
        if error_code_upper in ["ACCESS_DENIED", "UNAUTHORIZEDCLIENT", "AUTH_FAILURE"]:
            return ErrorCategory.ACCESS_DENIED
        
        if error_code_upper in ["THROTTLING", "THROTTLING_EXCEPTION", "TOO_MANY_REQUESTS"]:
            return ErrorCategory.RATE_LIMITED
        
        if error_code_upper in ["NETWORK_ERROR", "CONNECTION_ERROR", "TIMEOUT"]:
            return ErrorCategory.NETWORK_ERROR
        
        if error_code_upper in ["INVALID_PARAM", "INVALID_PARAMETER", "VALIDATION_ERROR"]:
            return ErrorCategory.INVALID_INPUT
        
        if error_code_upper in ["NOT_FOUND", "NO_SUCH_ENTITY", "DOES_NOT_EXIST"]:
            return ErrorCategory.RESOURCE_NOT_FOUND
        
        if "denied" in error_message_lower and "access" in error_message_lower:
            return ErrorCategory.PERMISSION_MISSING
        
        if "quota" in error_message_lower or "limit" in error_message_lower:
            return ErrorCategory.QUOTA_EXCEEDED
        
        # Default to unknown
        return ErrorCategory.UNKNOWN
    
    def _generate_explanation(self, category: ErrorCategory, error_code: str,
                            error_message: str, resource: str,
                            attempted_action: str,
                            recovery_attempts: Optional[List[str]]) -> ErrorExplanation:
        """Generate detailed explanation based on category"""
        
        template = self.error_templates.get(category, self.error_templates[ErrorCategory.UNKNOWN])
        
        # Safe format function that handles missing placeholders
        def safe_format(template_str: str, **kwargs) -> str:
            try:
                return template_str.format(**kwargs)
            except KeyError:
                # If placeholder missing, return template as-is
                return template_str
        
        # Customize explanation with specific details
        what_happened = safe_format(
            template["what_happened"],
            resource=resource,
            error_code=error_code,
            action=attempted_action
        )
        
        why_it_happened = safe_format(
            template["why_it_happened"],
            resource=resource,
            error_code=error_code,
            error_message=error_message
        )
        
        what_we_tried = recovery_attempts or template["what_we_tried"]
        
        what_is_needed = safe_format(
            template["what_is_needed"],
            resource=resource,
            action=attempted_action
        )
        
        next_steps = [safe_format(step, resource=resource, action=attempted_action) 
                     for step in template["next_steps"]]
        
        can_retry = template["can_retry"]
        retry_delay = template.get("retry_delay_seconds")
        
        return ErrorExplanation(
            error_category=category,
            error_code=error_code,
            error_message=error_message,
            what_happened=what_happened,
            why_it_happened=why_it_happened,
            what_we_tried=what_we_tried,
            what_is_needed=what_is_needed,
            next_steps=next_steps,
            can_retry=can_retry,
            retry_delay_seconds=retry_delay,
            severity=template.get("severity", "error")
        )
    
    def _load_error_templates(self) -> Dict[ErrorCategory, Dict[str, Any]]:
        """Load detailed explanation templates for each error category"""
        return {
            ErrorCategory.ACCESS_DENIED: {
                "what_happened": "Access was denied when trying to {action} on {resource}. The AWS API returned error code {error_code}.",
                "why_it_happened": "The IAM credentials being used do not have the required permissions to perform {action} on {resource}. This is typically caused by: 1) Missing IAM permission, 2) Explicit deny in IAM policy, 3) Resource-based policy restrictions.",
                "what_we_tried": ["Verified AWS credentials are valid", "Checked resource exists and is accessible"],
                "what_is_needed": "The IAM user/role needs the following specific permission: {action} for {resource}. Add this to the IAM policy or resource-based policy.",
                "next_steps": [
                    "Check IAM policy for missing permission: {action}",
                    "Verify no explicit deny in IAM policy",
                    "Check resource-based policy (e.g., bucket policy, S3 bucket ACL)",
                    "Ensure credentials are for the correct AWS account",
                    "Test with admin permissions to verify permission requirements"
                ],
                "can_retry": False,
                "severity": "error"
            },
            
            ErrorCategory.PERMISSION_MISSING: {
                "what_happened": "Missing IAM permission when accessing {resource}. The specific permission required was not found in the IAM policy.",
                "why_it_happened": "The IAM policy attached to the current credentials does not include the required action. This is different from AccessDenied - it means the permission is simply not granted.",
                "what_we_tried": ["Verified credentials are valid", "Attempted the action with available permissions"],
                "what_is_needed": "Add the specific IAM permission to the policy. Look at the error message for the exact action required.",
                "next_steps": [
                    "Identify the exact permission from the error message",
                    "Add permission to IAM policy: {action}",
                    "Test permission with IAM simulator: aws iam simulate-principal-policy",
                    "Ensure policy is attached to the correct user/role"
                ],
                "can_retry": False,
                "severity": "error"
            },
            
            ErrorCategory.RATE_LIMITED: {
                "what_happened": "AWS API rate limit was exceeded when trying to {action}. The API returned {error_code}.",
                "why_it_happened": "Too many API calls were made in a short time period. AWS has rate limits per API, per account, and per region to protect service stability.",
                "what_we_tried": ["Attempted the API call", "Respected configured rate limits"],
                "what_is_needed": "Reduce the rate of API calls or request a quota increase from AWS.",
                "next_steps": [
                    "Wait 60 seconds before retrying",
                    "Reduce concurrent workers (current: max_workers)",
                    "Implement exponential backoff",
                    "Request quota increase: AWS Console → Service Quotas",
                    "Use paginated APIs to reduce call count"
                ],
                "can_retry": True,
                "retry_delay_seconds": 60,
                "severity": "warning"
            },
            
            ErrorCategory.NETWORK_ERROR: {
                "what_happened": "Network connectivity issue when trying to {action}. Could not reach AWS API endpoint.",
                "why_it_happened": "Possible causes: 1) Internet connectivity issues, 2) DNS resolution failure, 3) Firewall blocking AWS endpoints, 4) AWS service outage.",
                "what_we_tried": ["Attempted API call", "Verified endpoint is correct"],
                "what_is_needed": "Stable network connectivity to AWS endpoints. Check network configuration and connectivity.",
                "next_steps": [
                    "Test internet connectivity: ping 8.8.8.8",
                    "Test DNS resolution: nslookup {resource}",
                    "Check firewall rules for AWS endpoints",
                    "Verify VPN/proxy configuration if used",
                    "Check AWS service status: https://status.aws.amazon.com/",
                    "Retry in 30 seconds"
                ],
                "can_retry": True,
                "retry_delay_seconds": 30,
                "severity": "warning"
            },
            
            ErrorCategory.INVALID_INPUT: {
                "what_happened": "Invalid input parameter when trying to {action}. The API rejected the request with error code {error_code}.",
                "why_it_happened": "One or more parameters in the API call are invalid. This could be: wrong format, invalid value, missing required parameter, or parameter conflict.",
                "what_we_tried": ["Validated input parameters against API documentation"],
                "what_is_needed": "Correct the invalid parameter(s) in the API call. Review API documentation for valid formats and values.",
                "next_steps": [
                    "Review API call parameters for typos",
                    "Check API documentation for valid values",
                    "Validate parameter types (string, integer, boolean)",
                    "Ensure required parameters are present",
                    "Check for parameter conflicts (e.g., mutually exclusive parameters)"
                ],
                "can_retry": False,
                "severity": "error"
            },
            
            ErrorCategory.RESOURCE_NOT_FOUND: {
                "what_happened": "Resource {resource} was not found when trying to {action}. The API returned error code {error_code}.",
                "why_it_happened": "The resource does not exist or has been deleted. This could also be a typo in the resource identifier.",
                "what_we_tried": ["Verified resource ARN/ID format", "Attempted to access resource"],
                "what_is_needed": "Verify the resource exists and the ARN/ID is correct. If the resource should exist, it may have been deleted.",
                "next_steps": [
                    "Verify resource ARN/ID is correct",
                    "Check if resource was recently deleted",
                    "List resources to verify existence",
                    "Check if in correct region/account",
                    "Verify no typos in resource identifier"
                ],
                "can_retry": False,
                "severity": "error"
            },
            
            ErrorCategory.QUOTA_EXCEEDED: {
                "what_happened": "AWS service quota exceeded when trying to {action}. The account has reached its limit.",
                "why_it_happened": "The AWS account has reached the maximum allowed number of resources or API calls for this service. Quotas prevent runaway costs and protect service stability.",
                "what_we_tried": ["Attempted to create/access resource", "Verified quota status"],
                "what_is_needed": "Request a quota increase from AWS or delete unused resources to free up quota.",
                "next_steps": [
                    "Check current quota: AWS Console → Service Quotas",
                    "Request quota increase: AWS Console → Service Quotas → Request quota increase",
                    "Delete unused resources to free up quota",
                    "Use AWS Cost Explorer to identify underutilized resources"
                ],
                "can_retry": False,
                "severity": "error"
            },
            
            ErrorCategory.DEPENDENCY_ERROR: {
                "what_happened": "A dependency required for {action} is not available or misconfigured.",
                "why_it_happened": "The operation depends on another service or resource that is not available. This could be a missing library, incorrect configuration, or unavailable dependency.",
                "what_we_tried": ["Verified dependencies are installed", "Checked configuration files"],
                "what_is_needed": "Install or configure the missing dependency before retrying.",
                "next_steps": [
                    "Install missing dependencies: pip install -r requirements.txt",
                    "Check configuration files are present and valid",
                    "Verify all required services are available",
                    "Check if API keys/credentials are configured"
                ],
                "can_retry": False,
                "severity": "error"
            },
            
            ErrorCategory.UNKNOWN: {
                "what_happened": "An unexpected error occurred when trying to {action}. Error code: {error_code}. Message: {error_message}",
                "why_it_happened": "An unknown error was encountered. This could be a transient issue, a bug, or an unhandled error case.",
                "what_we_tried": ["Attempted the operation", "Logged error details"],
                "what_is_needed": "Additional investigation is needed. Check logs and error details for more context.",
                "next_steps": [
                    "Review full error message and stack trace",
                    "Check logs for additional context",
                    "Search for known issues with this error code",
                    "Report as a bug if error persists",
                    "Retry once to see if it's transient"
                ],
                "can_retry": True,
                "retry_delay_seconds": 10,
                "severity": "warning"
            }
        }
    
    def _log_error_explanation(self, explanation: ErrorExplanation) -> None:
        """Log detailed error explanation for observability"""
        self.logger.error(
            f"ERROR EXPLANATION: {explanation.error_category.value}",
            error_category=explanation.error_category.value,
            error_code=explanation.error_code,
            what_happened=explanation.what_happened,
            why_it_happened=explanation.why_it_happened,
            what_is_needed=explanation.what_is_needed,
            next_steps=explanation.next_steps,
            can_retry=explanation.can_retry
        )
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of errors encountered"""
        errors_by_category = {}
        for explanation in self.error_history:
            category = explanation.error_category.value
            errors_by_category[category] = errors_by_category.get(category, 0) + 1
        
        retryable_count = sum(1 for e in self.error_history if e.can_retry)
        
        return {
            "total_errors": len(self.error_history),
            "retryable_errors": retryable_count,
            "errors_by_category": errors_by_category,
            "recent_errors": [
                {
                    "category": e.error_category.value,
                    "code": e.error_code,
                    "severity": e.severity
                }
                for e in self.error_history[-10:]  # Last 10 errors
            ]
        }
