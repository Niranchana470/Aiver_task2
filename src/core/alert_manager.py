"""Alert Manager for SLA Breach Notifications"""
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class AlertType(Enum):
    """Types of alerts"""
    SLA_BREACH = "SLA Breach"
    CRITICAL_FINDING = "Critical Finding"
    SECURITY_POSTURE_DECLINE = "Security Posture Decline"
    SCAN_FAILURE = "Scan Failure"
    FINDING_SPIKE = "Finding Spike"


@dataclass
class Alert:
    """Alert notification"""
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    message: str
    timestamp: datetime
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class AlertChannel:
    """Base class for alert channels"""
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert notification"""
        raise NotImplementedError
    
    def format_alert(self, alert: Alert) -> str:
        """Format alert for channel"""
        lines = [
            f"🚨 {alert.title}",
            f"Severity: {alert.severity.value}",
            f"Type: {alert.alert_type.value}",
            f"Time: {alert.timestamp.isoformat()}",
            "",
            alert.message,
            ""
        ]
        
        if alert.findings:
            lines.append("Affected Findings:")
            for finding in alert.findings[:5]:  # Limit to 5 findings
                lines.append(f"- {finding.get('title', 'Unknown')}")
            if len(alert.findings) > 5:
                lines.append(f"... and {len(alert.findings) - 5} more")
        
        return "\\n".join(lines)


class ConsoleAlertChannel(AlertChannel):
    """Send alerts to console"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def send_alert(self, alert: Alert) -> bool:
        """Log alert to console"""
        formatted = self.format_alert(alert)
        self.logger.critical(formatted)
        return True


class SlackAlertChannel(AlertChannel):
    """Send alerts to Slack"""
    
    def __init__(self, webhook_url: str, logger):
        self.webhook_url = webhook_url
        self.logger = logger
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert to Slack webhook"""
        try:
            import requests
            
            # Format alert for Slack
            color_map = {
                AlertSeverity.CRITICAL: "danger",
                AlertSeverity.HIGH: "warning",
                AlertSeverity.MEDIUM: "#FF9900",
                AlertSeverity.LOW: "good"
            }
            
            attachment = {
                "color": color_map.get(alert.severity, "good"),
                "title": alert.title,
                "text": alert.message,
                "fields": [
                    {"title": "Severity", "value": alert.severity.value, "short": True},
                    {"title": "Type", "value": alert.alert_type.value, "short": True},
                    {"title": "Time", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "short": True}
                ],
                "footer": "Offensive Security Agent",
                "ts": int(alert.timestamp.timestamp())
            }
            
            # Add findings if present
            if alert.findings:
                fields_text = "\\n".join([
                    f"• {f.get('title', 'Unknown')} ({f.get('severity', 'Unknown')})"
                    for f in alert.findings[:5]
                ])
                attachment["fields"].append({
                    "title": "Affected Findings",
                    "value": fields_text,
                    "short": False
                })
            
            payload = {"attachments": [attachment]}
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            self.logger.info(f"Alert sent to Slack: {alert.title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
            return False


class EmailAlertChannel(AlertChannel):
    """Send alerts via email"""
    
    def __init__(self, smtp_config: Dict[str, str], logger):
        self.smtp_config = smtp_config
        self.logger = logger
    
    def send_alert(self, alert: Alert) -> bool:
        """Send alert via email"""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config.get("from")
            msg['To'] = self.smtp_config.get("to")
            msg['Subject'] = f"[{alert.severity.value}] {alert.title}"
            
            # Create email body
            body = self.format_alert(alert)
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(
                self.smtp_config.get("host"),
                self.smtp_config.get("port", 587)
            ) as server:
                if self.smtp_config.get("use_tls", True):
                    server.starttls()
                
                if self.smtp_config.get("username") and self.smtp_config.get("password"):
                    server.login(
                        self.smtp_config["username"],
                        self.smtp_config["password"]
                    )
                
                server.send_message(msg)
            
            self.logger.info(f"Alert sent via email: {alert.title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False


class AlertManager:
    """
    Manage alerts for SLA breaches and critical findings
    """
    
    def __init__(self, logger, config: Dict[str, Any]):
        self.logger = logger
        self.config = config
        self.channels: List[AlertChannel] = []
        self.alert_history: List[Alert] = []
        self.max_history_size = 1000
        
        # Initialize alert channels
        self._initialize_channels()
    
    def _initialize_channels(self) -> None:
        """Initialize alert channels from configuration"""
        # Console channel (always enabled)
        self.channels.append(ConsoleAlertChannel(self.logger))
        
        # Slack channel
        slack_config = self.config.get("slack", {})
        if slack_config.get("enabled"):
            webhook_url = slack_config.get("webhook_url")
            if webhook_url:
                self.channels.append(SlackAlertChannel(webhook_url, self.logger))
        
        # Email channel
        email_config = self.config.get("email", {})
        if email_config.get("enabled"):
            self.channels.append(EmailAlertChannel(email_config, self.logger))
    
    def check_sla_breaches(
        self,
        findings: List[Dict[str, Any]],
        sla_deadlines: Dict[str, datetime]
    ) -> None:
        """Check for SLA breaches and send alerts"""
        breached_findings = []
        
        for finding in findings:
            finding_hash = self._create_finding_hash(finding)
            if finding_hash in sla_deadlines:
                deadline = sla_deadlines[finding_hash]
                if datetime.utcnow() > deadline:
                    breached_findings.append(finding)
        
        if breached_findings:
            self._send_alert(
                AlertType.SLA_BREACH,
                AlertSeverity.CRITICAL,
                f"SLA Breach: {len(breached_findings)} findings exceeded deadline",
                f"{len(breached_findings)} security findings have exceeded their SLA deadline and require immediate attention.",
                breached_findings
            )
    
    def check_critical_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Check for critical findings and send alerts"""
        critical_findings = [
            f for f in findings
            if f.get("severity") == "Critical" and f.get("status") != "Resolved"
        ]
        
        if critical_findings:
            self._send_alert(
                AlertType.CRITICAL_FINDING,
                AlertSeverity.CRITICAL,
                f"Critical Findings Detected: {len(critical_findings)}",
                f"{len(critical_findings)} critical security findings require immediate remediation.",
                critical_findings
            )
    
    def check_security_posture_decline(
        self,
        current_score: int,
        previous_score: int,
        threshold: int = 10
    ) -> None:
        """Check for significant security posture decline"""
        decline = previous_score - current_score
        
        if decline >= threshold:
            self._send_alert(
                AlertType.SECURITY_POSTURE_DECLINE,
                AlertSeverity.HIGH,
                f"Security Posture Declined by {decline} points",
                f"Security posture score declined from {previous_score} to {current_score}, indicating degradation in security posture.",
                []
            )
    
    def check_finding_spike(
        self,
        current_count: int,
        previous_count: int,
        threshold_percent: float = 0.5
    ) -> None:
        """Check for sudden spike in findings"""
        if previous_count == 0:
            return
        
        increase = (current_count - previous_count) / previous_count
        
        if increase >= threshold_percent:
            self._send_alert(
                AlertType.FINDING_SPIKE,
                AlertSeverity.MEDIUM,
                f"Finding Count Increased by {increase:.0%}",
                f"Number of findings increased from {previous_count} to {current_count}, indicating potential new security issues.",
                []
            )
    
    def check_scan_failure(self, error_message: str) -> None:
        """Alert on scan failures"""
        self._send_alert(
            AlertType.SCAN_FAILURE,
            AlertSeverity.HIGH,
            "Security Scan Failed",
            f"A scheduled security scan failed: {error_message}",
            []
        )
    
    def _send_alert(
        self,
        alert_type: AlertType,
        severity: AlertSeverity,
        title: str,
        message: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """Send alert through all configured channels"""
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            timestamp=datetime.utcnow(),
            findings=findings,
            metadata={"alert_count": len(self.alert_history) + 1}
        )
        
        # Add to history
        self.alert_history.append(alert)
        if len(self.alert_history) > self.max_history_size:
            self.alert_history.pop(0)
        
        # Send through all channels
        for channel in self.channels:
            try:
                channel.send_alert(alert)
            except Exception as e:
                self.logger.error(f"Failed to send alert via {type(channel).__name__}: {e}")
    
    def get_alert_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alert history"""
        recent_alerts = self.alert_history[-limit:]
        
        return [
            {
                "type": alert.alert_type.value,
                "severity": alert.severity.value,
                "title": alert.title,
                "timestamp": alert.timestamp.isoformat(),
                "finding_count": len(alert.findings)
            }
            for alert in recent_alerts
        ]
    
    def _create_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Create hash for finding identification"""
        import hashlib
        hash_input = f"{finding.get('check_name')}|{finding.get('resource_arn')}|{finding.get('title')}"
        return hashlib.md5(hash_input.encode()).hexdigest()