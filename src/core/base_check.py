"""
Base Check Interface
All security checks must inherit from this base class to ensure consistency
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class Severity(Enum):
    """Severity levels for security findings"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class SecurityFinding:
    """Structured security finding with full context"""
    check_name: str
    resource_arn: str
    severity: Severity
    title: str
    description: str
    evidence: Dict[str, Any]
    business_impact: str
    remediation: str
    confidence: float  # 0.0 to 1.0
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "check_name": self.check_name,
            "resource_arn": self.resource_arn,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "business_impact": self.business_impact,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata or {}
        }

    def is_valid_finding(self) -> bool:
        """Validate that this finding meets minimum standards"""
        return (
            self.resource_arn and
            self.severity in Severity and
            self.confidence >= 0.0 and
            self.confidence <= 1.0 and
            self.remediation and
            self.evidence
        )


class BaseCheck(ABC):
    """Base class for all security checks"""
    
    def __init__(self, logger):
        self.logger = logger
        self.check_name = self.__class__.__name__
        self.findings: List[SecurityFinding] = []
        self.errors: List[Dict[str, Any]] = []
        self.resources_scanned = 0
        self.api_errors = {
            "access_denied": 0,
            "rate_limit": 0,
            "other": 0
        }
    
    @abstractmethod
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Execute the security check.
        Must return list of SecurityFinding objects.
        """
        pass
    
    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a finding after validation"""
        if not finding.is_valid_finding():
            self.logger.warning(
                f"Invalid finding rejected from {self.check_name}: "
                f"missing required fields"
            )
            return
        
        # Critical findings must have high confidence (≥0.8)
        if finding.severity == Severity.CRITICAL and finding.confidence < 0.8:
            self.logger.warning(
                f"Critical finding requires confidence ≥0.8, got {finding.confidence}. "
                f"Downgrading to HIGH for resource: {finding.resource_arn}"
            )
            finding.severity = Severity.HIGH
        
        self.findings.append(finding)
        self.logger.info(
            f"[{self.check_name}] Finding added: {finding.severity.value} - "
            f"{finding.title} ({finding.confidence:.0%} confidence)"
        )
    
    def record_api_error(self, error_code: str, resource: str, context: str) -> None:
        """Record API access errors for observability"""
        error_info = {
            "error_code": error_code,
            "resource": resource,
            "context": context,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if error_code == "AccessDenied":
            self.api_errors["access_denied"] += 1
            self.logger.error(f"[{self.check_name}] ACCESS DENIED: {context}")
        elif error_code in ["Throttling", "TooManyRequestsException"]:
            self.api_errors["rate_limit"] += 1
            self.logger.warning(f"[{self.check_name}] RATE LIMIT: {context}")
        else:
            self.api_errors["other"] += 1
            self.logger.error(f"[{self.check_name}] API Error {error_code}: {context}")
        
        self.errors.append(error_info)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary"""
        return {
            "check_name": self.check_name,
            "resources_scanned": self.resources_scanned,
            "findings_count": len(self.findings),
            "errors_count": len(self.errors),
            "api_errors": self.api_errors,
            "severity_breakdown": self._get_severity_breakdown()
        }
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Count findings by severity"""
        breakdown = {s.value: 0 for s in Severity}
        for finding in self.findings:
            breakdown[finding.severity.value] += 1
        return breakdown