"""Security Report Generator"""
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass


@dataclass
class ReportMetadata:
    """Report metadata"""
    scan_id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_checks: int
    successful_checks: int
    failed_checks: int
    total_findings: int


class SecurityReporter:
    """Generate security reports in multiple formats"""
    
    def __init__(self, logger):
        self.logger = logger
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_reports(
        self,
        execution_results: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Generate all report formats and return file paths"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        scan_id = f"scan_{timestamp}"
        
        # Extract metadata - support both old and new structures
        summary = execution_results.get("execution_summary") or execution_results.get("execution_metadata", {})
        findings_summary = execution_results.get("findings_summary", {})
        exec_time_str = summary.get("start_time") or summary.get("execution_time")
        start_time = (
            datetime.fromisoformat(exec_time_str) if exec_time_str else datetime.utcnow()
        )
        metadata = ReportMetadata(
            scan_id=scan_id,
            start_time=start_time,
            end_time=datetime.utcnow(),
            duration_seconds=summary.get("duration_seconds", 0),
            total_checks=execution_results.get("total_checks", 0),
            successful_checks=execution_results.get("successful_checks", 0),
            failed_checks=execution_results.get("failed_checks", 0),
            total_findings=len(findings)
        )
        
        # Generate JSON report
        json_path = self._generate_json_report(
            scan_id, metadata, execution_results, findings
        )
        
        # Generate Markdown report
        md_path = self._generate_markdown_report(
            scan_id, metadata, execution_results, findings
        )
        
        self.logger.info(
            f"Reports generated: JSON={json_path}, Markdown={md_path}"
        )
        
        return {
            "json": str(json_path),
            "markdown": str(md_path),
            "scan_id": scan_id
        }
    
    def _generate_json_report(
        self,
        scan_id: str,
        metadata: ReportMetadata,
        execution_results: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Path:
        """Generate JSON report for automation"""
        report = {
            "scan_metadata": {
                "scan_id": metadata.scan_id,
                "start_time": metadata.start_time.isoformat(),
                "end_time": metadata.end_time.isoformat(),
                "duration_seconds": metadata.duration_seconds,
                "total_checks": metadata.total_checks,
                "successful_checks": metadata.successful_checks,
                "failed_checks": metadata.failed_checks,
                "total_findings": metadata.total_findings
            },
            "execution_results": execution_results,
            "findings": findings,
            "severity_summary": self._calculate_severity_summary(findings),
            "api_errors": execution_results.get("error_summary", execution_results.get("execution_summary", {})).get("api_errors", {})
        }
        
        json_path = self.reports_dir / f"{scan_id}_report.json"
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return json_path
    
    def _generate_markdown_report(
        self,
        scan_id: str,
        metadata: ReportMetadata,
        execution_results: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Path:
        """Generate Markdown report for human consumption"""
        lines = []
        
        # Header
        lines.append(f"# Security Scan Report")
        lines.append(f"**Scan ID:** {scan_id}")
        lines.append(f"**Time:** {metadata.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Duration:** {metadata.duration_seconds:.2f} seconds")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        summary = execution_results.get("execution_summary", {})
        severity_breakdown = summary.get("severity_breakdown", {})
        
        lines.append(f"- **Total Findings:** {metadata.total_findings}")
        lines.append(f"- **Critical:** {severity_breakdown.get('Critical', 0)}")
        lines.append(f"- **High:** {severity_breakdown.get('High', 0)}")
        lines.append(f"- **Medium:** {severity_breakdown.get('Medium', 0)}")
        lines.append(f"- **Low:** {severity_breakdown.get('Low', 0)}")
        lines.append(f"- **Info:** {severity_breakdown.get('Info', 0)}")
        lines.append("")
        
        # API Errors (if any)
        api_errors = summary.get("api_errors", {})
        if api_errors.get("access_denied", 0) > 0 or api_errors.get("rate_limit", 0) > 0:
            lines.append("### API Access Issues")
            if api_errors.get("access_denied", 0) > 0:
                lines.append(f"- ⚠️ **Access Denied Errors:** {api_errors['access_denied']}")
                lines.append("  - Some resources could not be scanned due to insufficient permissions")
            if api_errors.get("rate_limit", 0) > 0:
                lines.append(f"- ⚠️ **Rate Limit Errors:** {api_errors['rate_limit']}")
                lines.append("  - Some requests were throttled by AWS APIs")
            lines.append("")
        
        # Critical Findings (if any)
        critical_findings = [f for f in findings if f.get("severity") == "Critical"]
        if critical_findings:
            lines.append("## 🔴 CRITICAL FINDINGS")
            lines.append("These findings require immediate attention:")
            lines.append("")
            for finding in critical_findings:
                lines.append(self._format_finding_markdown(finding))
                lines.append("")
        
        # High Severity Findings
        high_findings = [f for f in findings if f.get("severity") == "High"]
        if high_findings:
            lines.append("## 🟠 HIGH SEVERITY FINDINGS")
            lines.append("")
            for finding in high_findings:
                lines.append(self._format_finding_markdown(finding))
                lines.append("")
        
        # Medium Severity Findings
        medium_findings = [f for f in findings if f.get("severity") == "Medium"]
        if medium_findings:
            lines.append("## 🟡 MEDIUM SEVERITY FINDINGS")
            lines.append("")
            for finding in medium_findings:
                lines.append(self._format_finding_markdown(finding))
                lines.append("")
        
        # Low and Info findings (grouped)
        low_info_findings = [f for f in findings if f.get("severity") in ["Low", "Info"]]
        if low_info_findings:
            lines.append("## 🟢 LOW & INFO FINDINGS")
            lines.append("")
            for finding in low_info_findings:
                lines.append(self._format_finding_markdown(finding, detailed=False))
                lines.append("")
        
        # Check Execution Details
        lines.append("## Check Execution Details")
        for check_result in execution_results.get("check_results", []):
            check_name = check_result.get("check_name", "Unknown")
            status = check_result.get("status", "unknown")
            summary = check_result.get("summary", {})
            
            lines.append(f"### {check_name}")
            lines.append(f"- **Status:** {status}")
            lines.append(f"- **Resources Scanned:** {summary.get('resources_scanned', 0)}")
            lines.append(f"- **Findings:** {summary.get('findings_count', 0)}")
            
            if summary.get("api_errors", {}).get("access_denied", 0) > 0:
                lines.append(f"- ⚠️ Access Denied: {summary['api_errors']['access_denied']}")
            lines.append("")
        
        # Write report
        md_path = self.reports_dir / f"{scan_id}_report.md"
        with open(md_path, 'w') as f:
            f.write('\\n'.join(lines))
        
        return md_path
    
    def _format_finding_markdown(self, finding: Dict[str, Any], detailed: bool = True) -> str:
        """Format a single finding in Markdown"""
        lines = []
        
        severity_emoji = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Info": "ℹ️"
        }.get(finding.get("severity", "Info"), "⚪")
        
        lines.append(f"### {severity_emoji} {finding.get('title', 'Untitled Finding')}")
        lines.append(f"**Resource:** `{finding.get('resource_arn', 'Unknown')}`")
        lines.append(f"**Severity:** {finding.get('severity', 'Unknown')}")
        lines.append(f"**Confidence:** {finding.get('confidence', 0):.0%}")
        lines.append("")
        
        if detailed:
            lines.append(f"**Description:**")
            lines.append(finding.get('description', 'No description provided'))
            lines.append("")
            
            lines.append(f"**Business Impact:**")
            lines.append(finding.get('business_impact', 'Not specified'))
            lines.append("")
            
            lines.append(f"**Evidence:**")
            evidence = finding.get('evidence', {})
            for key, value in evidence.items():
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, indent=2)
                lines.append(f"- `{key}`: {value}")
            lines.append("")
            
            lines.append(f"**Remediation:**")
            lines.append("```bash")
            lines.append(finding.get('remediation', 'No remediation provided'))
            lines.append("```")
            lines.append("")
        else:
            lines.append(f"{finding.get('description', 'No description')}")
            lines.append("")
        
        return '\\n'.join(lines)
    
    def _calculate_severity_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate summary statistics by severity"""
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "Info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts