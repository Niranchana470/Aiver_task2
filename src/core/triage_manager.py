"""Triage Manager for Finding Deduplication and Impact Ranking"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import hashlib


class BusinessImpact(Enum):
    """Business impact levels for prioritization"""
    CRITICAL = "Critical"  # Immediate threat to data security
    HIGH = "High"          # Significant security risk
    MEDIUM = "Medium"      # Moderate risk
    LOW = "Low"            # Minor issue


@dataclass
class TriageRule:
    """Rule for business impact assessment"""
    name: str
    condition: callable  # Function that takes finding and returns bool
    impact: BusinessImpact
    priority: int  # Lower = higher priority
    reason: str


class TriageManager:
    """
    Triage findings by:
    1. Deduplicating similar findings
    2. Ranking by business impact
    3. Prioritizing remediation efforts
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.triage_rules = self._initialize_rules()
        self.deduplication_cache: Dict[str, List[Dict]] = {}
    
    def triage_findings(
        self,
        findings: List[Dict[str, Any]],
        previous_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Triage findings: deduplicate and rank by impact
        """
        self.logger.info(f"TriageManager: Processing {len(findings)} findings")
        
        # Step 1: Deduplicate findings
        unique_findings = self._deduplicate_findings(findings)
        self.logger.info(f"TriageManager: Deduplicated to {len(unique_findings)} unique findings")
        
        # Step 2: Assess business impact for each finding
        findings_with_impact = self._assess_business_impact(unique_findings)
        
        # Step 3: Rank by business impact and severity
        ranked_findings = self._rank_findings(findings_with_impact)
        
        # Step 4: Identify new vs recurring findings
        findings_with_status = self._identify_finding_status(
            ranked_findings,
            previous_findings or []
        )
        
        # Step 5: Generate triage summary
        triage_summary = self._generate_triage_summary(findings_with_status)
        
        return {
            "findings": findings_with_status,
            "summary": triage_summary,
            "deduplication_stats": {
                "original_count": len(findings),
                "unique_count": len(unique_findings),
                "duplicates_removed": len(findings) - len(unique_findings)
            }
        }
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings based on similarity
        """
        unique_findings = []
        seen_hashes = set()
        
        for finding in findings:
            # Create hash for deduplication
            finding_hash = self._create_finding_hash(finding)
            
            if finding_hash not in seen_hashes:
                seen_hashes.add(finding_hash)
                unique_findings.append(finding)
            else:
                self.logger.debug(f"Duplicate finding removed: {finding.get('title')}")
        
        return unique_findings
    
    def _create_finding_hash(self, finding: Dict[str, Any]) -> str:
        """
        Create hash for finding deduplication
        Based on check_name, resource_arn, and title
        """
        hash_input = f"{finding.get('check_name')}|{finding.get('resource_arn')}|{finding.get('title')}"
        return hashlib.md5(hash_input.encode()).hexdigest()
    
    def _assess_business_impact(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Assess business impact for each finding
        """
        for finding in findings:
            # Apply triage rules in priority order
            for rule in sorted(self.triage_rules, key=lambda r: r.priority):
                if rule.condition(finding):
                    finding["business_impact_level"] = rule.impact.value
                    finding["impact_reason"] = rule.reason
                    finding["triage_priority"] = rule.priority
                    break
            
            # Default impact if no rules matched
            if "business_impact_level" not in finding:
                finding["business_impact_level"] = BusinessImpact.LOW.value
                finding["impact_reason"] = "Default impact level"
                finding["triage_priority"] = 100
        
        return findings
    
    def _rank_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Rank findings by business impact and severity
        """
        severity_order = {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Info": 1
        }
        
        impact_order = {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2
        }
        
        # Sort by business impact, then severity, then priority
        ranked = sorted(
            findings,
            key=lambda f: (
                impact_order.get(f.get("business_impact_level", "Low"), 1),
                severity_order.get(f.get("severity", "Info"), 1),
                f.get("triage_priority", 100)
            ),
            reverse=True
        )
        
        # Add rank to findings
        for i, finding in enumerate(ranked, 1):
            finding["remediation_rank"] = i
        
        return ranked
    
    def _identify_finding_status(
        self,
        current_findings: List[Dict[str, Any]],
        previous_findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Identify if findings are new, recurring, or resolved
        """
        # Create hash set of previous findings
        previous_hashes = set()
        for finding in previous_findings:
            finding_hash = self._create_finding_hash(finding)
            previous_hashes.add(finding_hash)
        
        # Classify current findings
        for finding in current_findings:
            finding_hash = self._create_finding_hash(finding)
            
            if finding_hash in previous_hashes:
                finding["status"] = "Recurring"
                finding["first_seen"] = "Previous scan"
            else:
                finding["status"] = "New"
                finding["first_seen"] = datetime.utcnow().isoformat()
        
        return current_findings
    
    def _generate_triage_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate triage summary statistics
        """
        # Count by business impact
        impact_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }
        
        # Count by status
        status_counts = {
            "New": 0,
            "Recurring": 0
        }
        
        # Count by severity
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for finding in findings:
            impact_level = finding.get("business_impact_level", "Low")
            if impact_level in impact_counts:
                impact_counts[impact_level] += 1
            
            status = finding.get("status", "Unknown")
            if status in status_counts:
                status_counts[status] += 1
            
            severity = finding.get("severity", "Info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_findings": len(findings),
            "business_impact_breakdown": impact_counts,
            "status_breakdown": status_counts,
            "severity_breakdown": severity_counts,
            "top_priority_findings": len([f for f in findings if f.get("remediation_rank", 999) <= 5])
        }
    
    def _initialize_rules(self) -> List[TriageRule]:
        """
        Initialize triage rules for business impact assessment
        """
        return [
            # Critical Impact Rules
            TriageRule(
                name="Public Data Exposure",
                condition=lambda f: "public" in f.get("title", "").lower() and 
                                  any(s in f.get("severity", "") for s in ["Critical", "High"]),
                impact=BusinessImpact.CRITICAL,
                priority=1,
                reason="Public data exposure poses immediate threat to sensitive information"
            ),
            TriageRule(
                name="Unauthenticated Access",
                condition=lambda f: any(word in f.get("title", "").lower() 
                                       for word in ["authentication", "auth", "login", "bypass"]),
                impact=BusinessImpact.CRITICAL,
                priority=2,
                reason="Authentication bypass allows unauthorized access to systems"
            ),
            TriageRule(
                name="Credentials Leaked",
                condition=lambda f: any(word in f.get("title", "").lower() 
                                       for word in ["key", "token", "secret", "credential", "password"]),
                impact=BusinessImpact.CRITICAL,
                priority=3,
                reason="Leaked credentials can be exploited immediately by attackers"
            ),
            TriageRule(
                name="Known Exploitable Vulnerability",
                condition=lambda f: "cve" in f.get("title", "").lower() or 
                                  "vulnerability" in f.get("title", "").lower(),
                impact=BusinessImpact.CRITICAL,
                priority=4,
                reason="Known vulnerabilities with published exploits"
            ),
            
            # High Impact Rules
            TriageRule(
                name="Missing Encryption",
                condition=lambda f: "encryption" in f.get("title", "").lower(),
                impact=BusinessImpact.HIGH,
                priority=10,
                reason="Missing encryption exposes data at rest to unauthorized access"
            ),
            TriageRule(
                name="Excessive Permissions",
                condition=lambda f: any(word in f.get("title", "").lower() 
                                       for word in ["admin", "wildcard", "excessive", "over-permissive"]),
                impact=BusinessImpact.HIGH,
                priority=11,
                reason="Excessive permissions increase blast radius of credential compromise"
            ),
            TriageRule(
                name="Network Exposure",
                condition=lambda f: any(word in f.get("title", "").lower() 
                                       for word in ["internet", "public", "0.0.0.0/0", "open"]),
                impact=BusinessImpact.HIGH,
                priority=12,
                reason="Network exposure to internet increases attack surface"
            ),
            
            # Medium Impact Rules
            TriageRule(
                name="Weak Security Configuration",
                condition=lambda f: any(word in f.get("title", "").lower() 
                                       for word in ["versioning", "backup", "logging", "monitoring"]),
                impact=BusinessImpact.MEDIUM,
                priority=20,
                reason="Weak security configurations reduce operational resilience"
            ),
            TriageRule(
                name="Missing Security Best Practice",
                condition=lambda f: "missing" in f.get("title", "").lower(),
                impact=BusinessImpact.MEDIUM,
                priority=21,
                reason="Missing security controls increase risk but don't pose immediate threat"
            ),
            
            # Low Impact Rules
            TriageRule(
                name="Informational Finding",
                condition=lambda f: f.get("severity", "Info") in ["Info", "Low"],
                impact=BusinessImpact.LOW,
                priority=30,
                reason="Informational findings don't pose immediate security risk"
            )
        ]