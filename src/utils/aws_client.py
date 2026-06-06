"""AWS Client Manager"""
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, Any, Optional
from contextlib import contextmanager


class AWSClientManager:
    """Manage AWS clients with proper error handling and session management"""
    
    def __init__(self, config: Dict[str, Any], logger):
        self.config = config
        self.logger = logger
        self._session = None
        self._region = config.get("region", "us-east-1")
        self._profile = config.get("profile", "default")
        
    def get_session(self) -> boto3.Session:
        """Get or create boto3 session"""
        if self._session is None:
            try:
                session_kwargs = {"region_name": self._region}
                
                # Use profile if specified
                if self._profile and self._profile != "default":
                    session_kwargs["profile_name"] = self._profile
                
                self._session = boto3.Session(**session_kwargs)
                self.logger.info(
                    f"Created boto3 session: region={self._region}, "
                    f"profile={self._profile}"
                )
            except Exception as e:
                self.logger.error(f"Failed to create boto3 session: {e}")
                raise
        return self._session
    
    def get_client(self, service_name: str) -> Any:
        """Get a service client"""
        session = self.get_session()
        try:
            client = session.client(service_name, region_name=self._region)
            self.logger.debug(f"Created {service_name} client")
            return client
        except Exception as e:
            self.logger.error(f"Failed to create {service_name} client: {e}")
            raise
    
    @contextmanager
    def aws_error_handler(self, resource_context: str):
        """Context manager for handling AWS API errors"""
        try:
            yield
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            self.logger.error(
                f"AWS API Error: {error_code} - {resource_context}",
                error_code=error_code,
                resource=resource_context,
                error_message=str(e)
            )
            raise
        except BotoCoreError as e:
            self.logger.error(
                f"BotoCore Error: {resource_context}",
                resource=resource_context,
                error_message=str(e)
            )
            raise
        except Exception as e:
            self.logger.error(
                f"Unexpected error: {resource_context}",
                resource=resource_context,
                error_message=str(e)
            )
            raise
    
    def get_account_id(self) -> Optional[str]:
        """Get the current AWS account ID"""
        try:
            sts_client = self.get_client("sts")
            account_id = sts_client.get_caller_identity()["Account"]
            self.logger.info(f"Discovered AWS Account ID: {account_id}")
            return account_id
        except Exception as e:
            self.logger.error(f"Failed to get account ID: {e}")
            return None