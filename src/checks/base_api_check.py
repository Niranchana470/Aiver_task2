"""Base API Check for application security scanning"""
from typing import Dict, List, Any
import requests
from requests.exceptions import RequestException, Timeout

from ..core.base_check import BaseCheck, SecurityFinding, Severity


class BaseAPICheck(BaseCheck):
    """Base class for API endpoint security checks"""
    
    def __init__(self, logger):
        super().__init__(logger)
        import time
        self.timeout = 10  # seconds
        self.user_agent = "OffensiveSecurityAgent/1.0"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent
        })
    
    def make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Any:
        """Make HTTP request with error handling"""
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            return response
        except Timeout:
            self.record_api_error(
                error_code="Timeout",
                resource=url,
                context=f"Request to {url} timed out"
            )
            return None
        except RequestException as e:
            self.record_api_error(
                error_code="RequestFailed",
                resource=url,
                context=f"Request to {url} failed: {str(e)}"
            )
            return None
    
    def check_cors_configuration(self, url: str) -> Dict[str, Any]:
        """Check CORS configuration for security issues"""
        cors_findings = []
        
        try:
            # Test preflight request
            response = self.make_request(
                "OPTIONS",
                url,
                headers={
                    "Origin": "https://malicious-site.com",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Content-Type"
                }
            )
            
            if response and response.headers.get("Access-Control-Allow-Origin"):
                allowed_origin = response.headers.get("Access-Control-Allow-Origin")
                
                # Check if allows any origin
                if allowed_origin == "*":
                    cors_findings.append({
                        "issue": "Allows any origin",
                        "severity": Severity.HIGH,
                        "header": "Access-Control-Allow-Origin: *",
                        "impact": "Any website can make requests and read responses"
                    })
                elif allowed_origin == "https://malicious-site.com":
                    cors_findings.append({
                        "issue": "Accepts arbitrary origin",
                        "severity": Severity.CRITICAL,
                        "header": f"Access-Control-Allow-Origin: {allowed_origin}",
                        "impact": "Server reflects arbitrary origin in CORS header"
                    })
            
            # Check for excessive credentials allowance
            if response and response.headers.get("Access-Control-Allow-Credentials") == "true":
                allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
                if allow_origin == "*":
                    cors_findings.append({
                        "issue": "Unsafe credential configuration",
                        "severity": Severity.CRITICAL,
                        "header": "Access-Control-Allow-Credentials: true with * origin",
                        "impact": "Credentials can be exposed to any origin"
                    })
            
            # Check for exposed headers
            exposed_headers = response.headers.get("Access-Control-Expose-Headers", "")
            if "authorization" in exposed_headers.lower():
                cors_findings.append({
                    "issue": "Exposes authorization headers",
                    "severity": Severity.MEDIUM,
                    "header": f"Access-Control-Expose-Headers: {exposed_headers}",
                    "impact": "Authorization headers accessible to client-side JavaScript"
                })
            
        except Exception as e:
            self.logger.error(f"Error checking CORS for {url}: {e}")
        
        return cors_findings
    
    def check_rate_limiting(self, url: str) -> Dict[str, Any]:
        """Check if API has rate limiting implemented"""
        rate_limit_findings = []
        
        try:
            # Make multiple rapid requests
            responses = []
            for i in range(10):
                response = self.make_request("GET", url)
                if response:
                    responses.append({
                        "status_code": response.status_code,
                        "headers": dict(response.headers)
                    })
            
            # Check if we got rate limited
            rate_limited = any(
                r["status_code"] == 429 or
                r["headers"].get("X-RateLimit-Remaining") == "0" or
                r["headers"].get("Retry-After")
                for r in responses
            )
            
            if not rate_limited:
                # Check for rate limit headers
                has_rate_limit_headers = any(
                    any(key.startswith(("X-RateLimit", "RateLimit-"))
                        for key in r["headers"].keys())
                    for r in responses
                )
                
                if not has_rate_limit_headers:
                    rate_limit_findings.append({
                        "issue": "No rate limiting detected",
                        "severity": Severity.HIGH,
                        "evidence": f"Made {len(responses)} rapid requests without rate limiting",
                        "impact": "API vulnerable to abuse, DoS attacks, and credential stuffing"
                    })
            else:
                self.logger.info(f"Rate limiting detected for {url}")
            
        except Exception as e:
            self.logger.error(f"Error checking rate limiting for {url}: {e}")
        
        return rate_limit_findings
    
    def check_authentication_bypass(self, url: str) -> List[Dict[str, Any]]:
        """Check for authentication bypass vulnerabilities"""
        auth_bypass_findings = []
        
        try:
            # Test 1: Access protected endpoint without auth
            response = self.make_request("GET", url)
            if response and response.status_code == 200:
                # Check if we got data that should be protected
                content_type = response.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    try:
                        data = response.json()
                        if data and len(data) > 0:
                            auth_bypass_findings.append({
                                "issue": "Possible authentication bypass",
                                "severity": Severity.CRITICAL,
                                "evidence": f"Received {len(data)} records without authentication",
                                "impact": "Sensitive data accessible without authentication"
                            })
                    except:
                        pass
            
            # Test 2: Path traversal attempts
            traversal_payloads = ["../", "..\\/", "%2e%2e%2f", "%2e%2e%5c"]
            for payload in traversal_payloads:
                test_url = f"{url}{payload}"
                response = self.make_request("GET", test_url)
                if response and response.status_code == 200:
                    auth_bypass_findings.append({
                        "issue": "Path traversal vulnerability",
                        "severity": Severity.HIGH,
                        "evidence": f"Path '{payload}' returned 200 OK",
                        "impact": "Potential file system access through path traversal"
                    })
                    break  # One finding is enough
            
        except Exception as e:
            self.logger.error(f"Error checking auth bypass for {url}: {e}")
        
        return auth_bypass_findings
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()