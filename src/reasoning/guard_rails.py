"""
Guard Rails - Scope enforcement and safety boundaries
Prevents reckless actions and ensures agent operates within defined bounds
"""
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import re


class ScopeViolationType(Enum):
    """Types of scope violations"""
    ACCOUNT_NOT_ALLOWED = "account_not_allowed"
    RESOURCE_TYPE_NOT_ALLOWED = "resource_type_not_allowed"
    REGION_NOT_ALLOWED = "region_not_allowed"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    DESTRUCTIVE_OPERATION = "destructive_operation"
    PERMISSION_DENIED = "permission_denied"


@dataclass
class ScopeViolation:
    """A scope violation that was prevented"""
    violation_type: ScopeViolationType
    attempted_action: str
    reason: str
    resource: str
    allowed_alternatives: List[str]
    blocked: bool


@dataclass
class ScopeConfig:
    """Configuration defining agent's operational boundaries"""
    # AWS Account restrictions
    allowed_account_ids: Optional[Set[str]] = None  # None = any account
    forbidden_account_ids: Set[str] = None  # Never scan these
    
    # Region restrictions
    allowed_regions: Optional[Set[str]] = None  # None = any region
    forbidden_regions: Set[str] = None  # Never scan these
    
    # Resource type restrictions
    allowed_resource_types: Optional[Set[str]] = None  # None = all
    forbidden_resource_types: Set[str] = None  # Never scan these
    
    # Action restrictions
    read_only: bool = True  # Only allow read operations
    allow_destructive: bool = False  # Never allow destructive operations
    
    # Rate limiting
    max_api_calls_per_minute: int = 1000
    max_concurrent_requests: int = 20
    
    # Safety checks
    require_approval_for_critical: bool = True  # Require approval for critical changes
    dry_run: bool = False  # Log what would happen, don't execute
    
    def __post_init__(self):
        """Initialize empty sets as None"""
        if self.forbidden_account_ids is None:
            self.forbidden_account_ids = set()
        if self.forbidden_regions is None:
            self.forbidden_regions = set()
        if self.forbidden_resource_types is None:
            self.forbidden_resource_types = set()


class GuardRails:
    """
    Guard rails enforcement - the "Guard Rails" trait
    
    Ensures the agent knows its scope and operates strictly within it
    Prevents reckless actions before they happen
    """
    
    def __init__(self, config: ScopeConfig, logger):
        self.config = config
        self.logger = logger
        self.violations: List[ScopeViolation] = []
        self.api_call_count = 0
        self.api_call_timestamps: List[float] = []
        
        self.logger.info(
            "Guard Rails initialized",
            read_only=config.read_only,
            allowed_accounts=len(config.allowed_account_ids) if config.allowed_account_ids else "unrestricted",
            allowed_regions=len(config.allowed_regions) if config.allowed_regions else "unrestricted"
        )
    
    def check_action_allowed(self, action: str, resource_arn: str, 
                            context: Optional[Dict[str, Any]] = None) -> ScopeViolation:
        """
        Check if an action is allowed within guard rails
        
        Returns None if allowed, or a ScopeViolation if blocked
        This is the pre-execution check that prevents reckless actions
        """
        self.logger.info(f"Checking action: {action}", resource=resource_arn)
        
        # Parse ARN
        arn_parts = self._parse_arn(resource_arn)
        
        # Check 1: Account restrictions
        account_violation = self._check_account_allowed(arn_parts)
        if account_violation:
            return account_violation
        
        # Check 2: Region restrictions
        region_violation = self._check_region_allowed(arn_parts)
        if region_violation:
            return region_violation
        
        # Check 3: Resource type restrictions
        resource_violation = self._check_resource_type_allowed(arn_parts)
        if resource_violation:
            return resource_violation
        
        # Check 4: Action restrictions (read-only, destructive)
        action_violation = self._check_action_allowed(action)
        if action_violation:
            return action_violation
        
        # Check 5: Rate limiting
        rate_violation = self._check_rate_limit()
        if rate_violation:
            return rate_violation
        
        # All checks passed
        self.logger.info("Action allowed by guard rails")
        return None
    
    def _parse_arn(self, arn: str) -> Dict[str, Optional[str]]:
        """Parse AWS ARN into components"""
        # ARN format: arn:partition:service:region:account-id:resource
        parts = arn.split(":")
        
        if len(parts) >= 6:
            return {
                "partition": parts[1],
                "service": parts[2],
                "region": parts[3],
                "account": parts[4],
                "resource": parts[5]
            }
        
        # If not a valid ARN, return empty dict
        return {}
    
    def _check_account_allowed(self, arn_parts: Dict[str, Optional[str]]) -> Optional[ScopeViolation]:
        """Check if AWS account is allowed"""
        account = arn_parts.get("account")
        
        if not account:
            # Can't check without account ID
            return None
        
        # Check forbidden accounts (never allow)
        if account in self.config.forbidden_account_ids:
            violation = ScopeViolation(
                violation_type=ScopeViolationType.ACCOUNT_NOT_ALLOWED,
                attempted_action=f"Access account {account}",
                reason=f"Account {account} is in forbidden list",
                resource=account,
                allowed_alternatives=["Skip this account", "Use a different account"],
                blocked=True
            )
            self.violations.append(violation)
            self.logger.error("Account forbidden", account=account)
            return violation
        
        # If allowed list is specified, check it
        if self.config.allowed_account_ids and account not in self.config.allowed_account_ids:
            violation = ScopeViolation(
                violation_type=ScopeViolationType.ACCOUNT_NOT_ALLOWED,
                attempted_action=f"Access account {account}",
                reason=f"Account {account} is not in allowed list",
                resource=account,
                allowed_alternatives=[f"Use one of: {', '.join(self.config.allowed_account_ids)}"],
                blocked=True
            )
            self.violations.append(violation)
            self.logger.error("Account not in allowed list", account=account)
            return violation
        
        return None
    
    def _check_region_allowed(self, arn_parts: Dict[str, Optional[str]]) -> Optional[ScopeViolation]:
        """Check if region is allowed"""
        region = arn_parts.get("region")
        
        if not region or region == "":
            # Some resources don't have regions (e.g., IAM)
            return None
        
        # Check forbidden regions
        if region in self.config.forbidden_regions:
            violation = ScopeViolation(
                violation_type=ScopeViolationType.REGION_NOT_ALLOWED,
                attempted_action=f"Access region {region}",
                reason=f"Region {region} is in forbidden list",
                resource=region,
                allowed_alternatives=[f"Use one of: {', '.join(self.config.allowed_regions)}" if self.config.allowed_regions else "Any region except forbidden ones"],
                blocked=True
            )
            self.violations.append(violation)
            self.logger.error("Region forbidden", region=region)
            return violation
        
        # If allowed list is specified, check it
        if self.config.allowed_regions and region not in self.config.allowed_regions:
            violation = ScopeViolation(
                violation_type=ScopeViolationType.REGION_NOT_ALLOWED,
                attempted_action=f"Access region {region}",
                reason=f"Region {region} is not in allowed list",
                resource=region,
                allowed_alternatives=[f"Use one of: {', '.join(self.config.allowed_regions)}"],
                blocked=True
            )
            self.violations.append(violation)
            self.logger.error("Region not in allowed list", region=region)
            return violation
        
        return None
    
    def _check_resource_type_allowed(self, arn_parts: Dict[str, Optional[str]]) -> Optional[ScopeViolation]:
        """Check if resource type is allowed"""
        service = arn_parts.get("service")
        resource = arn_parts.get("resource", "")
        
        if not service:
            return None
        
        # Check forbidden resource types
        resource_type = f"{service}:{resource.split('/')[0]}"
        if resource_type in self.config.forbidden_resource_types:
            violation = ScopeViolation(
                violation_type=ScopeViolationType.RESOURCE_TYPE_NOT_ALLOWED,
                attempted_action=f"Access {resource_type}",
                reason=f"Resource type {resource_type} is forbidden",
                resource=resource_type,
                allowed_alternatives=["Skip this resource type", "Scan other resource types"],
                blocked=True
            )
            self.violations.append(violation)
            self.logger.error("Resource type forbidden", resource_type=resource_type)
            return violation
        
        # If allowed list is specified, check it
        if self.config.allowed_resource_types and service not in self.config.allowed_resource_types:
            violation = ScopeViolation(
                violation_type=ScopeViolationType.RESOURCE_TYPE_NOT_ALLOWED,
                attempted_action=f"Access {service}",
                reason=f"Service {service} is not in allowed list",
                resource=service,
                allowed_alternatives=[f"Use one of: {', '.join(self.config.allowed_resource_types)}"],
                blocked=True
            )
            self.violations.append(violation)
            self.logger.error("Service not in allowed list", service=service)
            return violation
        
        return None
    
    def _check_action_allowed(self, action: str) -> Optional[ScopeViolation]:
        """Check if action is allowed (read-only, destructive operations)"""
        action_lower = action.lower()
        
        # Check for destructive operations
        destructive_keywords = ["delete", "terminate", "destroy", "shutdown", "remove", "drop"]
        if any(keyword in action_lower for keyword in destructive_keywords):
            if not self.config.allow_destructive:
                violation = ScopeViolation(
                    violation_type=ScopeViolationType.DESTRUCTIVE_OPERATION,
                    attempted_action=action,
                    reason="Destructive operations are not allowed",
                    resource="N/A",
                    allowed_alternatives=["Use read-only equivalent", "Enable destructive operations with explicit approval"],
                    blocked=True
                )
                self.violations.append(violation)
                self.logger.error("Destructive operation blocked", action=action)
                return violation
        
        # Check for write operations in read-only mode
        write_keywords = ["put", "post", "patch", "create", "update", "modify"]
        if any(keyword in action_lower for keyword in write_keywords):
            if self.config.read_only:
                violation = ScopeViolation(
                    violation_type=ScopeViolationType.ACTION_NOT_ALLOWED,
                    attempted_action=action,
                    reason="Write operations not allowed in read-only mode",
                    resource="N/A",
                    allowed_alternatives=["Use read-only equivalent", "Disable read-only mode"],
                    blocked=True
                )
                self.violations.append(violation)
                self.logger.error("Write operation blocked in read-only mode", action=action)
                return violation
        
        return None
    
    def _check_rate_limit(self) -> Optional[ScopeViolation]:
        """Check if rate limit would be exceeded"""
        import time
        
        current_time = time.time()
        
        # Remove timestamps older than 1 minute
        self.api_call_timestamps = [
            ts for ts in self.api_call_timestamps 
            if current_time - ts < 60
        ]
        
        # Check if adding another call would exceed limit
        if len(self.api_call_timestamps) >= self.config.max_api_calls_per_minute:
            violation = ScopeViolation(
                violation_type=ScopeViolationType.ACTION_NOT_ALLOWED,
                attempted_action="API call",
                reason=f"Rate limit exceeded ({len(self.api_call_timestamps)}/{self.config.max_api_calls_per_minute} calls/min)",
                resource="N/A",
                allowed_alternatives=["Wait before retrying", "Reduce concurrent requests", "Increase rate limit"],
                blocked=True
            )
            self.violations.append(violation)
            self.logger.error("Rate limit exceeded", calls=len(self.api_call_timestamps))
            return violation
        
        # Record this call
        self.api_call_timestamps.append(current_time)
        return None
    
    def record_api_call(self) -> None:
        """Record an API call for rate limiting"""
        import time
        self.api_call_count += 1
        self.api_call_timestamps.append(time.time())
    
    def get_violations_summary(self) -> Dict[str, Any]:
        """Get summary of guard rail violations"""
        violations_by_type = {}
        for violation in self.violations:
            vtype = violation.violation_type.value
            violations_by_type[vtype] = violations_by_type.get(vtype, 0) + 1
        
        blocked_count = sum(1 for v in self.violations if v.blocked)
        
        return {
            "total_violations": len(self.violations),
            "blocked_violations": blocked_count,
            "violations_by_type": violations_by_type,
            "api_calls_made": self.api_call_count,
            "rate_limit_current": len(self.api_call_timestamps),
            "rate_limit_max": self.config.max_api_calls_per_minute
        }
    
    def is_dry_run(self) -> bool:
        """Check if operating in dry-run mode"""
        return self.config.dry_run


def create_scope_config_from_dict(config_dict: Dict[str, Any]) -> ScopeConfig:
    """Create ScopeConfig from configuration dictionary"""
    return ScopeConfig(
        allowed_account_ids=set(config_dict.get("allowed_account_ids", [])) or None,
        forbidden_account_ids=set(config_dict.get("forbidden_account_ids", [])),
        allowed_regions=set(config_dict.get("allowed_regions", [])) or None,
        forbidden_regions=set(config_dict.get("forbidden_regions", [])),
        allowed_resource_types=set(config_dict.get("allowed_resource_types", [])) or None,
        forbidden_resource_types=set(config_dict.get("forbidden_resource_types", [])),
        read_only=config_dict.get("read_only", True),
        allow_destructive=config_dict.get("allow_destructive", False),
        max_api_calls_per_minute=config_dict.get("max_api_calls_per_minute", 1000),
        max_concurrent_requests=config_dict.get("max_concurrent_requests", 20),
        require_approval_for_critical=config_dict.get("require_approval_for_critical", True),
        dry_run=config_dict.get("dry_run", False)
    )
