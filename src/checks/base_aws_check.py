"""Base AWS Security Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from ..core.base_check import BaseCheck, SecurityFinding, Severity
from ..utils.aws_client import AWSClientManager


class BaseAWSCheck(BaseCheck):
    """Base class for all AWS security checks"""
    
    def __init__(self, logger):
        super().__init__(logger)
        self.aws_manager: AWSClientManager = None
        self.account_id: str = None
    
    def setup_aws_client(self, config: Dict[str, Any]) -> None:
        """Initialize AWS client manager"""
        aws_config = config.get("aws", {})
        self.aws_manager = AWSClientManager(aws_config, self.logger)
        
        # Get account ID for ARN construction
        self.account_id = self.aws_manager.get_account_id()
        if not self.account_id:
            self.logger.warning("Could not determine AWS Account ID")
    
    def handle_aws_error(
        self,
        error: Exception,
        resource_arn: str,
        context: str
    ) -> None:
        """Handle AWS API errors and record them appropriately"""
        if isinstance(error, ClientError):
            error_code = error.response.get("Error", {}).get("Code", "Unknown")
            error_message = error.response.get("Error", {}).get("Message", "")
            
            self.record_api_error(
                error_code=error_code,
                resource=resource_arn,
                context=f"{context}: {error_message}"
            )
        else:
            self.record_api_error(
                error_code="Unknown",
                resource=resource_arn,
                context=f"{context}: {str(error)}"
            )
    
    def build_arn(
        self,
        resource_type: str,
        resource_id: str,
        region: str = None
    ) -> str:
        """Build AWS ARN with proper format"""
        if not self.account_id:
            return f"arn:aws:{resource_type}:::{resource_id}"
        
        region_part = region if region else ""
        
        return f"arn:aws:{resource_type}:{region_part}:{self.account_id}:{resource_id}"
    
    def is_access_denied(self, error: Exception) -> bool:
        """Check if error is access denied"""
        if isinstance(error, ClientError):
            error_code = error.response.get("Error", {}).get("Code", "")
            return error_code in ["AccessDenied", "UnauthorizedOperation"]
        return False
    
    def is_rate_limit(self, error: Exception) -> bool:
        """Check if error is rate limiting"""
        if isinstance(error, ClientError):
            error_code = error.response.get("Error", {}).get("Code", "")
            return error_code in ["Throttling", "TooManyRequestsException", "RequestLimitExceeded"]
        return False