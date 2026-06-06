"""API Endpoint Security Check"""
from typing import Dict, List, Any
from urllib.parse import urlparse

from .base_api_check import BaseAPICheck
from ..core.base_check import SecurityFinding, Severity


class APIEndpointCheck(BaseAPICheck):
    """
    Check live API endpoints for:
    - CORS misconfigurations
    - Missing rate limiting
    - Authentication bypass vulnerabilities
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute API endpoint security checks"""
        endpoints = config.get("checks", {}).get("APIEndpointCheck", {}).get("parameters", {}).get("endpoints", [])
        
        if not endpoints:
            self.logger.warning("No API endpoints configured for scanning")
            return self.findings
        
        self.logger.info(f"[{self.check_name}] Starting API endpoint scan for {len(endpoints)} endpoints")
        self.resources_scanned = len(endpoints)
        
        for endpoint_config in endpoints:
            if isinstance(endpoint_config, str):
                url = endpoint_config
                name = url
            else:
                url = endpoint_config.get("url")
                name = endpoint_config.get("name", url)
            
            if not url:
                continue
            
            self._check_api_endpoint(url, name)
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_api_endpoint(self, url: str, name: str) -> None:
        """Check individual API endpoint"""
        self.logger.info(f"Checking API endpoint: {name} ({url})")
        
        try:
            parsed = urlparse(url)
            resource_arn = f"api:endpoint:{parsed.netloc}{parsed.path}"
            
            # Check CORS configuration
            cors_findings = self.check_cors_configuration(url)
            for finding in cors_findings:
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=resource_arn,
                    severity=finding["severity"],
                    title=f"CORS Misconfiguration: {name}",
                    description=f"API endpoint '{name}' ({url}) has CORS issue: {finding['issue']}",
                    evidence={
                        "endpoint": url,
                        "endpoint_name": name,
                        "issue": finding["issue"],
                        "header": finding["header"],
                        "impact": finding["impact"]
                    },
                    business_impact=finding["impact"],
                    remediation=(
                        f"Configure CORS properly for {url}:\\n"
                        f"- Don't use 'Access-Control-Allow-Origin: *' with credentials\\n"
                        f"- Validate and whitelist allowed origins\\n"
                        f"- Use 'Access-Control-Allow-Origin: <specific-origin>'\\n"
                        f"- Don't expose sensitive headers via Access-Control-Expose-Headers"
                    ),
                    confidence=0.9,
                    timestamp=self._get_timestamp()
                ))
            
            # Check rate limiting
            rate_limit_findings = self.check_rate_limiting(url)
            for finding in rate_limit_findings:
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=resource_arn,
                    severity=finding["severity"],
                    title=f"Missing Rate Limiting: {name}",
                    description=f"API endpoint '{name}' ({url}) {finding['issue'].lower()}",
                    evidence={
                        "endpoint": url,
                        "endpoint_name": name,
                        "issue": finding["issue"],
                        "evidence": finding["evidence"],
                        "impact": finding["impact"]
                    },
                    business_impact=finding["impact"],
                    remediation=(
                        f"Implement rate limiting for {url}:\\n"
                        f"- Use API gateway rate limiting\\n"
                        f"- Implement application-level rate limiting\\n"
                        f"- Use Redis/memcached for distributed rate limiting\\n"
                        f"- Set appropriate limits (e.g., 100 requests/minute)"
                    ),
                    confidence=0.85,  # Rate limiting can be complex
                    timestamp=self._get_timestamp()
                ))
            
            # Check authentication bypass
            auth_findings = self.check_authentication_bypass(url)
            for finding in auth_findings:
                self.add_finding(SecurityFinding(
                    check_name=self.check_name,
                    resource_arn=resource_arn,
                    severity=finding["severity"],
                    title=f"Authentication Vulnerability: {name}",
                    description=f"API endpoint '{name}' ({url}): {finding['issue']}",
                    evidence={
                        "endpoint": url,
                        "endpoint_name": name,
                        "issue": finding["issue"],
                        "evidence": finding["evidence"],
                        "impact": finding["impact"]
                    },
                    business_impact=finding["impact"],
                    remediation=(
                        f"Secure {url} authentication:\\n"
                        f"- Implement proper authentication middleware\\n"
                        f"- Validate authentication on all protected endpoints\\n"
                        f"- Use JWT/OAuth2 with proper validation\\n"
                        f"- Sanitize and validate user input\\n"
                        f"- Implement path traversal protection"
                    ),
                    confidence=0.95,
                    timestamp=self._get_timestamp()
                ))
            
        except Exception as e:
            self.logger.error(f"Error checking API endpoint {url}: {e}")
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()