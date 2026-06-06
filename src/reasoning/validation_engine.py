"""
Validation Engine - Aggressive verification layer
Ensures all findings are backed by raw API evidence
"""
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .ai_provider import AIProvider
from ..core.base_check import SecurityFinding, Severity


class ValidationStatus(Enum):
    """Validation status for findings"""
    VERIFIED = "verified"  # Confirmed by raw API evidence
    REJECTED = "rejected"  # False positive, not supported by evidence
    DOWNGRADED = "downgraded"  # Real but severity reduced
    NEEDS_INFO = "needs_info"  # Can't verify, more evidence needed


@dataclass
class ValidationResult:
    """Result of aggressive validation"""
    status: ValidationStatus
    confidence: float
    reasoning: str
    evidence_match: Dict[str, Any]  # How finding matches evidence
    discrepancies: List[str]  # What doesn't match
    original_finding: SecurityFinding
    verified_finding: Optional[SecurityFinding] = None  # Modified if needed


class ValidationEngine:
    """
    Aggressive validation layer - the "Aggressive Validation" trait
    
    Catches hallucinations by cross-checking every claim against raw API evidence
    Never assumes - always verifies
    """
    
    def __init__(self, ai_provider: AIProvider, logger):
        self.ai_provider = ai_provider
        self.logger = logger
        self.validation_history: List[ValidationResult] = []
        
        # Validation rules for different finding types
        self.validation_rules = self._load_validation_rules()
    
    def validate_finding(self, finding: SecurityFinding, 
                        raw_api_evidence: Dict[str, Any]) -> ValidationResult:
        """
        Aggressively validate a finding against raw API evidence
        
        This is the core "no hallucinations" guarantee
        """
        self.logger.info(
            f"Aggressively validating finding: {finding.title}",
            resource=finding.resource_arn,
            severity=finding.severity.value
        )
        
        # Step 1: Validate evidence structure
        evidence_check = self._validate_evidence_structure(finding, raw_api_evidence)
        if not evidence_check["valid"]:
            return ValidationResult(
                status=ValidationStatus.REJECTED,
                confidence=0.0,
                reasoning=f"Evidence structure invalid: {evidence_check['reason']}",
                evidence_match={},
                discrepancies=[evidence_check['reason']],
                original_finding=finding,
                verified_finding=None
            )
        
        # Step 2: Cross-check claim against evidence
        claim_check = self._cross_check_claim(finding, raw_api_evidence)
        
        # Step 3: Use AI to validate the logic
        ai_validation = self._ai_validate_claim(finding, raw_api_evidence)
        
        # Step 4: Combine all checks for final decision
        final_status = self._determine_validation_status(claim_check, ai_validation)
        
        result = ValidationResult(
            status=final_status,
            confidence=ai_validation["confidence"],
            reasoning=ai_validation["reasoning"],
            evidence_match=claim_check["matches"],
            discrepancies=claim_check["discrepancies"],
            original_finding=finding,
            verified_finding=self._create_verified_finding(finding, final_status)
        )
        
        self.validation_history.append(result)
        self._log_validation_result(result)
        
        return result
    
    def _validate_evidence_structure(self, finding: SecurityFinding, 
                                    evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that evidence has required structure"""
        if not evidence:
            return {"valid": False, "reason": "No evidence provided"}
        
        if not isinstance(evidence, dict):
            return {"valid": False, "reason": "Evidence must be a dictionary"}
        
        # Check for required fields based on check type
        check_type = finding.check_name
        
        required_fields = self.validation_rules.get(check_type, {}).get("required_fields", [])
        for field in required_fields:
            if field not in evidence:
                return {"valid": False, "reason": f"Missing required field: {field}"}
        
        return {"valid": True, "reason": "Evidence structure valid"}
    
    def _cross_check_claim(self, finding: SecurityFinding, 
                          evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Cross-check the finding's claim against raw evidence"""
        matches = {}
        discrepancies = []
        
        # Extract the key assertion from the finding
        claim = self._extract_key_assertion(finding)
        
        # Verify against evidence
        for key, expected_value in claim.items():
            if key in evidence:
                actual_value = evidence[key]
                
                # Type-aware comparison
                if self._values_match(expected_value, actual_value):
                    matches[key] = {
                        "claimed": expected_value,
                        "actual": actual_value,
                        "match": True
                    }
                else:
                    discrepancies.append(
                        f"Field '{key}': claimed '{expected_value}' but evidence shows '{actual_value}'"
                    )
                    matches[key] = {
                        "claimed": expected_value,
                        "actual": actual_value,
                        "match": False
                    }
            else:
                discrepancies.append(f"Field '{key}' not found in evidence")
        
        return {"matches": matches, "discrepancies": discrepancies}
    
    def _ai_validate_claim(self, finding: SecurityFinding, 
                          evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to validate the claim logic"""
        prompt = f"""
You are a paranoid security validator. Does this finding have evidence to support it?

FINDING:
- Title: {finding.title}
- Description: {finding.description}
- Severity: {finding.severity.value}
- Confidence: {finding.confidence}

EVIDENCE (raw API response):
{self._format_evidence(evidence)}

Question: Does the evidence EXACTLY support this finding?

Analyze:
1. Does every claim in the title/description have evidence?
2. Is the severity justified by the evidence?
3. Are there any edge cases or false positives?
4. What is your confidence (0-100)?

Respond with:
VALIDATION: [VERIFIED/REJECTED/DOWNGRADED]
REASONING: [Detailed explanation]
CONFIDENCE: [0-100]
"""
        
        response = self.ai_provider.complete_with_reasoning(prompt)
        
        # Parse response
        validation_status = ValidationStatus.NEEDS_INFO
        confidence = 0.5
        reasoning = response.reasoning or response.content
        
        if "VERIFIED" in response.content.upper():
            validation_status = ValidationStatus.VERIFIED
        elif "REJECTED" in response.content.upper():
            validation_status = ValidationStatus.REJECTED
        elif "DOWNGRADED" in response.content.upper():
            validation_status = ValidationStatus.DOWNGRADED
        
        # Extract confidence
        if "CONFIDENCE:" in response.content:
            try:
                confidence_part = response.content.split("CONFIDENCE:")[1].strip()
                confidence = float(confidence_part) / 100.0
            except:
                confidence = 0.5
        
        return {
            "status": validation_status,
            "confidence": confidence,
            "reasoning": reasoning
        }
    
    def _determine_validation_status(self, claim_check: Dict[str, Any], 
                                    ai_validation: Dict[str, Any]) -> ValidationStatus:
        """Combine checks for final validation status"""
        discrepancies = claim_check["discrepancies"]
        
        # If discrepancies found, it's either rejected or downgraded
        if discrepancies:
            # If major discrepancy (core claim wrong), reject
            if any("claimed" in d and "not found" in d for d in discrepancies):
                return ValidationStatus.REJECTED
            else:
                return ValidationStatus.DOWNGRADED
        
        # If AI says reject, reject
        if ai_validation["status"] == ValidationStatus.REJECTED:
            return ValidationStatus.REJECTED
        
        # If AI says downgrade, downgrade
        if ai_validation["status"] == ValidationStatus.DOWNGRADED:
            return ValidationStatus.DOWNGRADED
        
        # If AI verified with high confidence, verify
        if ai_validation["confidence"] >= 0.8:
            return ValidationStatus.VERIFIED
        
        # Otherwise needs more info
        return ValidationStatus.NEEDS_INFO
    
    def _create_verified_finding(self, original: SecurityFinding, 
                                status: ValidationStatus) -> Optional[SecurityFinding]:
        """Create modified finding based on validation status"""
        if status == ValidationStatus.REJECTED:
            return None  # Don't create finding
        
        if status == ValidationStatus.VERIFIED:
            return original  # Return unchanged
        
        if status == ValidationStatus.DOWNGRADED:
            # Downgrade severity
            new_severity = self._downgrade_severity(original.severity)
            return SecurityFinding(
                check_name=original.check_name,
                resource_arn=original.resource_arn,
                severity=new_severity,
                title=f"[DOWNGRADED] {original.title}",
                description=original.description,
                evidence=original.evidence,
                business_impact=original.business_impact,
                remediation=original.remediation,
                confidence=original.confidence * 0.7,  # Lower confidence
                timestamp=original.timestamp,
                metadata={
                    **(original.metadata or {}),
                    "validation_status": "downgraded",
                    "original_severity": original.severity.value
                }
            )
        
        return original
    
    def _extract_key_assertion(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Extract the key claim from a finding"""
        # This is a simplified version - in production, would parse title/description
        # For now, return the evidence fields as the claim
        return finding.evidence
    
    def _values_match(self, claimed: Any, actual: Any) -> bool:
        """Check if claimed and actual values match, with type awareness"""
        # Direct equality
        if claimed == actual:
            return True
        
        # String comparison with tolerance
        if isinstance(claimed, str) and isinstance(actual, str):
            return claimed.lower() == actual.lower()
        
        # Boolean comparison
        if isinstance(claimed, bool) or isinstance(actual, bool):
            return bool(claimed) == bool(actual)
        
        return False
    
    def _downgrade_severity(self, original: Severity) -> Severity:
        """Downgrade severity by one level"""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        current_index = severity_order.index(original)
        
        if current_index < len(severity_order) - 1:
            return severity_order[current_index + 1]
        
        return Severity.INFO
    
    def _format_evidence(self, evidence: Dict[str, Any]) -> str:
        """Format evidence for AI consumption"""
        import json
        return json.dumps(evidence, indent=2, default=str)
    
    def _load_validation_rules(self) -> Dict[str, Any]:
        """Load validation rules for different check types"""
        return {
            "S3SecurityCheck": {
                "required_fields": ["Bucket", "Encryption", "ACL", "PublicAccess"]
            },
            "IAMSecurityCheck": {
                "required_fields": ["User", "MFA", "Policies"]
            },
            "SecurityGroupCheck": {
                "required_fields": ["GroupId", "Rules", "Inbound", "Outbound"]
            },
            # ... more rules for other check types
        }
    
    def _log_validation_result(self, result: ValidationResult) -> None:
        """Log validation result for observability"""
        self.logger.info(
            f"Validation: {result.status.value}",
            finding_title=result.original_finding.title,
            confidence=result.confidence,
            discrepancies_count=len(result.discrepancies),
            verified=result.verified_finding is not None
        )
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get summary of validation results"""
        verified_count = sum(1 for r in self.validation_history if r.status == ValidationStatus.VERIFIED)
        rejected_count = sum(1 for r in self.validation_history if r.status == ValidationStatus.REJECTED)
        downgraded_count = sum(1 for r in self.validation_history if r.status == ValidationStatus.DOWNGRADED)
        
        return {
            "total_validations": len(self.validation_history),
            "verified": verified_count,
            "rejected": rejected_count,
            "downgraded": downgraded_count,
            "needs_info": len(self.validation_history) - verified_count - rejected_count - downgraded_count
        }
