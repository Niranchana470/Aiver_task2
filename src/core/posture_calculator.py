"""Security Posture Score Calculator"""
from typing import Dict, List, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum


class TrendDirection(Enum):
    """Security posture trend direction"""
    IMPROVING = "Improving"
    DECLINING = "Declining"
    STABLE = "Stable"


@dataclass
class PostureMetrics:
    """Security posture metrics"""
    overall_score: int  # 0-100
    trend_direction: TrendDirection
    trend_change: int  # Points change from previous period
    risk_level: str  # Critical, High, Medium, Low
    compliance_score: int  # 0-100
    finding_metrics: Dict[str, Any]
    timestamp: datetime


class SecurityPostureCalculator:
    """
    Calculate security posture score with trend analysis
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.severity_weights = {
            "Critical": 10,
            "High": 5,
            "Medium": 2,
            "Low": 1,
            "Info": 0.5
        }
        
        self.risk_thresholds = {
            "Critical": 40,
            "High": 60,
            "Medium": 75,
            "Low": 90
        }
    
    def calculate_posture_score(
        self,
        findings: List[Dict[str, Any]],
        historical_findings: Optional[List[Dict[str, Any]]] = None
    ) -> PostureMetrics:
        """
        Calculate current security posture score with trend analysis
        """
        current_metrics = self._calculate_metrics(findings)
        
        # Calculate overall score (0-100, higher is better)
        overall_score = self._calculate_overall_score(current_metrics)
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Calculate trend if historical data available
        trend_direction = TrendDirection.STABLE
        trend_change = 0
        
        if historical_findings:
            historical_metrics = self._calculate_metrics(historical_findings)
            historical_score = self._calculate_overall_score(historical_metrics)
            trend_change = overall_score - historical_score
            
            if trend_change > 5:
                trend_direction = TrendDirection.IMPROVING
            elif trend_change < -5:
                trend_direction = TrendDirection.DECLINING
        
        return PostureMetrics(
            overall_score=overall_score,
            trend_direction=trend_direction,
            trend_change=trend_change,
            risk_level=risk_level,
            compliance_score=self._calculate_compliance_score(findings),
            finding_metrics=current_metrics,
            timestamp=datetime.utcnow()
        )
    
    def _calculate_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate detailed metrics from findings"""
        # Count by severity
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        # Count by status
        status_counts = {
            "Opened": 0,
            "Recurring": 0,
            "Resolved": 0,
            "New": 0
        }
        
        # Count by age
        now = datetime.utcnow()
        age_buckets = {
            "0-7 days": 0,
            "8-30 days": 0,
            "31-90 days": 0,
            "90+ days": 0
        }
        
        total_risk_score = 0
        high_confidence_count = 0
        
        for finding in findings:
            severity = finding.get("severity", "Info")
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            status = finding.get("status", "New")
            if status in status_counts:
                status_counts[status] += 1
            
            # Calculate age
            if "first_seen" in finding:
                try:
                    first_seen = datetime.fromisoformat(finding["first_seen"])
                    age_days = (now - first_seen).days
                    
                    if age_days <= 7:
                        age_buckets["0-7 days"] += 1
                    elif age_days <= 30:
                        age_buckets["8-30 days"] += 1
                    elif age_days <= 90:
                        age_buckets["31-90 days"] += 1
                    else:
                        age_buckets["90+ days"] += 1
                except:
                    pass
            
            # Calculate risk score
            total_risk_score += self.severity_weights.get(severity, 0)
            
            # Count high confidence findings
            if finding.get("confidence", 0) >= 0.8:
                high_confidence_count += 1
        
        return {
            "severity_breakdown": severity_counts,
            "status_breakdown": status_counts,
            "age_distribution": age_buckets,
            "total_findings": len(findings),
            "total_risk_score": total_risk_score,
            "high_confidence_count": high_confidence_count,
            "average_confidence": sum(f.get("confidence", 0) for f in findings) / len(findings) if findings else 0
        }
    
    def _calculate_overall_score(self, metrics: Dict[str, Any]) -> int:
        """
        Calculate overall security posture score (0-100)
        Higher is better
        """
        # Start with base score
        base_score = 100
        
        # Penalty for open findings
        total_findings = metrics["total_findings"]
        if total_findings > 0:
            # Calculate finding penalty
            finding_penalty = min(metrics["total_risk_score"] / 10, 40)
            base_score -= finding_penalty
        
        # Penalty for old unresolved findings
        old_findings = metrics["age_distribution"].get("90+ days", 0)
        age_penalty = min(old_findings * 2, 20)
        base_score -= age_penalty
        
        # Penalty for recurring findings
        recurring = metrics["status_breakdown"].get("Recurring", 0)
        recurring_penalty = min(recurring * 3, 15)
        base_score -= recurring_penalty
        
        # Bonus for high confidence (reliable findings)
        confidence_ratio = metrics["high_confidence_count"] / total_findings if total_findings > 0 else 0
        confidence_bonus = int(confidence_ratio * 5)
        base_score += confidence_bonus
        
        # Ensure score is within bounds
        return max(0, min(100, int(base_score)))
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        if score <= self.risk_thresholds["Critical"]:
            return "Critical"
        elif score <= self.risk_thresholds["High"]:
            return "High"
        elif score <= self.risk_thresholds["Medium"]:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_compliance_score(self, findings: List[Dict[str, Any]]) -> int:
        """
        Calculate compliance score based on critical findings
        """
        total_findings = len(findings)
        if total_findings == 0:
            return 100
        
        critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in findings if f.get("severity") == "High")
        
        # Compliance penalty for critical and high findings
        compliance_penalty = (critical_count * 10) + (high_count * 5)
        
        return max(0, min(100, 100 - compliance_penalty))
    
    def get_posture_history(
        self,
        db_connection,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get security posture history over time
        """
        history = []
        
        # This would query the database for historical findings
        # For now, return empty list
        # In production, this would use FindingDatabase.get_posture_history()
        
        return history
    
    def generate_recommendations(
        self,
        posture: PostureMetrics
    ) -> List[str]:
        """
        Generate actionable recommendations based on posture
        """
        recommendations = []
        
        # Critical findings
        critical_count = posture.finding_metrics["severity_breakdown"].get("Critical", 0)
        if critical_count > 0:
            recommendations.append(
                f"Address {critical_count} critical findings immediately - "
                f"these pose the highest risk to your security posture"
            )
        
        # Trend analysis
        if posture.trend_direction == TrendDirection.DECLINING:
            recommendations.append(
                f"Security posture is declining by {abs(posture.trend_change)} points - "
                f"review recent findings and remediation efforts"
            )
        
        # Old findings
        old_findings = posture.finding_metrics["age_distribution"].get("90+ days", 0)
        if old_findings > 0:
            recommendations.append(
                f"{old_findings} findings are over 90 days old - "
                f"establish remediation processes for long-standing issues"
            )
        
        # Recurring findings
        recurring = posture.finding_metrics["status_breakdown"].get("Recurring", 0)
        if recurring > 0:
            recommendations.append(
                f"{recurring} findings are recurring - "
                f"investigate root causes and implement permanent fixes"
            )
        
        # Low compliance
        if posture.compliance_score < 70:
            recommendations.append(
                f"Compliance score is {posture.compliance_score}% - "
                f"focus on reducing high-severity findings"
            )
        
        return recommendations