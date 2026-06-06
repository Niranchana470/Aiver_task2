"""Check Engine"""
from typing import Dict, List, Any, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime
import traceback

from .base_check import BaseCheck, SecurityFinding, Severity


class CheckEngine:
    """Main engine for orchestrating security checks"""
    
    def __init__(self, logger, config: Dict[str, Any]):
        self.logger = logger
        self.config = config
        self.checks: List[BaseCheck] = []
        self.all_findings: List[SecurityFinding] = []
        self.execution_start = None
        self.execution_end = None
        self._lock = threading.Lock()
        
        # Load configuration
        self.max_workers = config.get("max_workers", 10)
        self.timeout = config.get("check_timeout", 300)
    
    def register_check(self, check_class: Type[BaseCheck]) -> None:
        """Register a check class to be executed"""
        check_instance = check_class(self.logger)
        self.checks.append(check_instance)
        self.logger.info(f"Registered check: {check_instance.check_name}")
    
    def execute_all(self) -> Dict[str, Any]:
        """Execute all registered checks"""
        self.execution_start = datetime.utcnow()
        self.logger.info(
            f"Starting security scan with {len(self.checks)} checks, "
            f"max_workers={self.max_workers}"
        )
        
        results = {
            "total_checks": len(self.checks),
            "successful_checks": 0,
            "failed_checks": 0,
            "check_results": [],
            "execution_summary": {}
        }
        
        # Execute checks in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_check = {
                executor.submit(self._execute_single_check, check): check
                for check in self.checks
            }
            
            for future in as_completed(future_to_check):
                check = future_to_check[future]
                try:
                    check_result = future.result(timeout=self.timeout)
                    results["check_results"].append(check_result)
                    results["successful_checks"] += 1
                except Exception as e:
                    self.logger.error(
                        f"Check {check.check_name} failed: {str(e)}\\n"
                        f"{traceback.format_exc()}"
                    )
                    results["failed_checks"] += 1
                    results["check_results"].append({
                        "check_name": check.check_name,
                        "status": "failed",
                        "error": str(e),
                        "findings": [],
                        "summary": check.get_summary()
                    })
        
        self.execution_end = datetime.utcnow()
        
        # Aggregate all findings
        for check_result in results["check_results"]:
            self.all_findings.extend(check_result.get("findings", []))
        
        # Build execution summary
        results["execution_summary"] = self._build_summary()
        
        self.logger.info(
            f"Scan complete: {results['successful_checks']} successful, "
            f"{results['failed_checks']} failed, "
            f"{len(self.all_findings)} findings"
        )
        
        return results
    
    def _execute_single_check(self, check: BaseCheck) -> Dict[str, Any]:
        """Execute a single check with error handling"""
        self.logger.info(f"Executing check: {check.check_name}")
        
        try:
            findings = check.execute(self.config)
            return {
                "check_name": check.check_name,
                "status": "success",
                "findings": findings,  # Keep as SecurityFinding objects
                "summary": check.get_summary()
            }
        except Exception as e:
            self.logger.error(f"Check {check.check_name} raised exception: {e}")
            raise
    
    def _build_summary(self) -> Dict[str, Any]:
        """Build execution summary with statistics"""
        duration = (
            (self.execution_end - self.execution_start).total_seconds()
            if self.execution_end and self.execution_start
            else 0
        )
        
        severity_breakdown = {s.value: 0 for s in Severity}
        api_errors = {
            "access_denied": 0,
            "rate_limit": 0,
            "other": 0
        }
        
        for check_result in self.execution_results.get("check_results", []):
            summary = check_result.get("summary", {})
            for severity, count in summary.get("severity_breakdown", {}).items():
                severity_breakdown[severity] += count
            
            errors = summary.get("api_errors", {})
            api_errors["access_denied"] += errors.get("access_denied", 0)
            api_errors["rate_limit"] += errors.get("rate_limit", 0)
            api_errors["other"] += errors.get("other", 0)
        
        return {
            "duration_seconds": round(duration, 2),
            "total_findings": len(self.all_findings),
            "severity_breakdown": severity_breakdown,
            "api_errors": api_errors,
            "execution_time": self.execution_start.isoformat() if self.execution_start else None
        }
    
    def get_findings_by_severity(self, severity: Severity) -> List[SecurityFinding]:
        """Filter findings by severity"""
        return [f for f in self.all_findings if f.severity == severity]
    
    def get_critical_findings(self) -> List[SecurityFinding]:
        """Get all critical findings (these should be zero false positives)"""
        return self.get_findings_by_severity(Severity.CRITICAL)
    
    def get_all_findings(self) -> List[SecurityFinding]:
        """Get all findings from all checks"""
        return self.all_findings
    
    @property
    def execution_results(self) -> Dict[str, Any]:
        """Get the latest execution results"""
        return getattr(self, "_execution_results", {})
    
    @execution_results.setter
    def execution_results(self, value: Dict[str, Any]):
        """Store execution results"""
        with self._lock:
            self._execution_results = value