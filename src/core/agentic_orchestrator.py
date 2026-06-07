"""
Agentic Orchestrator - Brings together all agentic components
Replaces the script-like execution with intelligent, context-aware operation
"""
from typing import Dict, Any, List, Optional, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime

from .base_check import BaseCheck, SecurityFinding, Severity
from .config_loader import ConfigLoader
from ..reasoning import (
    DecisionEngine,
    ValidationEngine,
    GuardRails,
    FailureHandler,
    DecisionTraceLogger,
    ScopeConfig,
    create_scope_config_from_dict,
    TraceLevel
)
from ..utils.logger import get_logger


class AgenticOrchestrator:
    """
    Agentic orchestrator that brings together all reasoning components
    
    This is the core of the "Agentic" transformation:
    - Uses DecisionEngine for context-aware planning
    - Uses ValidationEngine for aggressive verification
    - Uses GuardRails for scope enforcement
    - Uses FailureHandler for transparent error handling
    - Uses DecisionTraceLogger for observability
    """
    
    def __init__(self, config: Dict[str, Any], logger=None):
        self.config = config
        self.logger = logger or get_logger("AgenticOrchestrator", config)
        
        # Initialize reasoning components
        self._initialize_reasoning_layer()
        
        # Check registration
        self.checks: List[BaseCheck] = []
        self.check_lock = threading.Lock()
        
        # Results storage
        self.all_findings: List[SecurityFinding] = []
        self.results_lock = threading.Lock()
        
        # Execution state
        self._execution_results: Dict[str, Any] = {}
        
        self.logger.info("Agentic Orchestrator initialized")
    
    def _initialize_reasoning_layer(self) -> None:
        """Initialize all reasoning/decision-making components"""
        # Decision trace logger - must be first for observability
        trace_level = TraceLevel.VERBOSE if self.config.get("debug", False) else TraceLevel.STANDARD
        self.trace_logger = DecisionTraceLogger(self.logger, trace_level)
        
        # Decision engine - for intelligent decisions
        self.decision_engine = DecisionEngine(self.config, self.logger)
        
        # Validation engine - for aggressive verification
        ai_provider = self.decision_engine.ai_provider
        self.validation_engine = ValidationEngine(ai_provider, self.logger)
        
        # Guard rails - for scope enforcement
        scope_config_dict = self.config.get("guard_rails", {})
        scope_config = create_scope_config_from_dict(scope_config_dict)
        self.guard_rails = GuardRails(scope_config, self.logger)
        
        # Failure handler - for transparent error handling
        self.failure_handler = FailureHandler(self.logger)
        
        self.logger.info("Reasoning layer initialized", components=5)
    
    def register_check(self, check_class: Type[BaseCheck]) -> None:
        """Register a security check class"""
        try:
            check_instance = check_class(self.logger)
            
            # Log check registration
            self.trace_logger.log_info(
                component="Orchestrator",
                title="Check Registered",
                message=f"Registered security check: {check_instance.check_name}",
                context={"check_name": check_instance.check_name}
            )
            
            with self.check_lock:
                self.checks.append(check_instance)
            
            self.logger.info(f"Registered check: {check_instance.check_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to register check {check_class.__name__}: {e}")
    
    def execute_all(self) -> Dict[str, Any]:
        """
        Execute all registered checks with agentic intelligence
        
        This replaces the script-like parallel execution with:
        1. Context-aware check selection
        2. Guard rail validation for each action
        3. Aggressive validation of findings
        4. Transparent error handling
        5. Full decision trace
        """
        self.trace_logger.log_info(
            component="Orchestrator",
            title="Execution Started",
            message="Starting agentic security scan execution"
        )
        
        start_time = datetime.utcnow()
        
        # Step 1: Discover infrastructure context
        infrastructure_context = self._discover_infrastructure_context()
        
        # Step 2: Make intelligent decision about what to scan
        scope_decision = self.decision_engine.decide_scan_scope(infrastructure_context)
        self.trace_logger.log_decision(
            component="DecisionEngine",
            title="Scan Scope Decision",
            action=scope_decision.action,
            reasoning=scope_decision.reasoning,
            confidence=scope_decision.confidence,
            alternatives=scope_decision.alternatives,
            evidence=scope_decision.evidence
        )
        
        # Step 3: Select checks based on discovered resources
        resource_inventory = self._build_resource_inventory(infrastructure_context)
        check_decision = self.decision_engine.decide_check_selection(
            [c.check_name for c in self.checks],
            resource_inventory
        )
        self.trace_logger.log_decision(
            component="DecisionEngine",
            title="Check Selection Decision",
            action=check_decision.action,
            reasoning=check_decision.reasoning,
            confidence=check_decision.confidence,
            alternatives=check_decision.alternatives,
            evidence=check_decision.evidence
        )
        
        # Step 4: Execute checks with guard rails
        selected_checks = self._parse_selected_checks(check_decision.action)
        execution_results = self._execute_checks_with_guard_rails(selected_checks)
        
        # Populate all_findings with raw findings from executed checks
        with self.results_lock:
            self.all_findings = execution_results["raw_findings"]
        self.logger.info(f"Collected {len(self.all_findings)} raw findings from executed checks")
        # Step 5: Aggressively validate all findings
        validated_findings = self._validate_findings_aggressively()
        
        # Step 6: Build comprehensive summary
        summary = self._build_agentic_summary(start_time, validated_findings)
        
        # Step 7: Export decision trace
        self._export_decision_trace()
        
        self._execution_results = summary
        
        self.trace_logger.log_info(
            component="Orchestrator",
            title="Execution Completed",
            message=f"Execution completed with {len(validated_findings)} validated findings"
        )
        
        return summary
    
    def _discover_infrastructure_context(self) -> Dict[str, Any]:
        """Discover what resources exist in the infrastructure"""
        context = {
            "aws_account_id": None,
            "regions": [],
            "resource_types": {},
            "estimated_counts": {}
        }
        
        self.trace_logger.log_info(
            component="Orchestrator",
            title="Discovering Infrastructure",
            message="Discovering infrastructure context for intelligent planning"
        )
        
        # Try to get account ID
        try:
            from ..utils.aws_client import AWSClientManager
            aws_client = AWSClientManager(self.config, self.logger)
            account_id = aws_client.get_account_id()
            context["aws_account_id"] = account_id
            
            self.trace_logger.log_info(
                component="Orchestrator",
                title="Account Discovered",
                message=f"Discovered AWS account: {account_id}"
            )
        except Exception as e:
            self.logger.warning(f"Could not discover account ID: {e}")
        
        # Try to discover resources (this is a simplified version)
        # In production, would make lightweight API calls to discover what exists
        context["resource_types"] = {
            "s3": "unknown",
            "iam": "unknown",
            "ec2": "unknown",
            "rds": "unknown",
            "lambda": "unknown"
        }
        
        return context
    
    def _build_resource_inventory(self, context: Dict[str, Any]) -> Dict[str, int]:
        """Build inventory of discovered resources"""
        # In production, this would be populated by actual discovery
        # For now, return estimates
        return {
            "s3_buckets": 10,  # Placeholder
            "iam_users": 5,  # Placeholder
            "ec2_instances": 3,  # Placeholder
            "rds_instances": 2,  # Placeholder
            "lambda_functions": 4  # Placeholder
        }
    
    def _parse_selected_checks(self, decision_text: str) -> List[str]:
        """Parse decision text to extract selected checks"""
        # Simple parsing - in production would be more sophisticated
        available_checks = [c.check_name for c in self.checks]
        
        # If decision mentions "all", return all checks
        if "all" in decision_text.lower():
            return available_checks
        
        # Otherwise, check which ones are mentioned
        selected = []
        for check in available_checks:
            if check.lower() in decision_text.lower():
                selected.append(check)
        
        # If no specific checks mentioned, run all
        return selected if selected else available_checks
    
    def _execute_checks_with_guard_rails(self, selected_checks: List[str]) -> Dict[str, Any]:
        """Execute checks with guard rail validation for each action"""
        self.trace_logger.log_info(
            component="Orchestrator",
            title="Executing Checks",
            message=f"Executing {len(selected_checks)} selected checks with guard rails"
        )
        
        # Filter checks to selected ones
        checks_to_run = [c for c in self.checks if c.check_name in selected_checks]
        
        results = {
            "checks_executed": [],
            "checks_failed": [],
            "checks_skipped": [],
            "guard_rail_violations": [],
            "raw_findings": []
        }
        
        with ThreadPoolExecutor(max_workers=self.config.get("max_workers", 10)) as executor:
            future_to_check = {
                executor.submit(self._execute_single_check_with_guard_rails, check): check
                for check in checks_to_run
            }
            
            for future in as_completed(future_to_check):
                check = future_to_check[future]
                try:
                    result = future.result()
                    
                    if result["status"] == "success":
                        results["checks_executed"].append(check.check_name)
                        results["raw_findings"].extend(result["findings"])
                    elif result["status"] == "blocked":
                        results["checks_skipped"].append(check.check_name)
                        results["guard_rail_violations"].append(result["violation"])
                    else:
                        results["checks_failed"].append(check.check_name)
                
                except Exception as e:
                    self.logger.error(f"Check {check.check_name} failed: {e}")
                    results["checks_failed"].append(check.check_name)
        
        return results
    
    def _execute_single_check_with_guard_rails(self, check: BaseCheck) -> Dict[str, Any]:
        """Execute a single check with guard rail validation"""
        # Check guard rails before execution
        violation = self.guard_rails.check_action_allowed(
            action=f"execute_{check.check_name}",
            resource_arn="*",  # Check applies to all resources
            context={"check": check.check_name}
        )
        
        if violation:
            # Log the blocked action
            self.trace_logger.log_error(
                component="GuardRails",
                title=f"Check Blocked: {check.check_name}",
                error_type=violation.violation_type.value,
                error_message=violation.reason,
                what_happened=violation.attempted_action,
                what_is_needed=violation.allowed_alternatives[0] if violation.allowed_alternatives else "N/A",
                next_steps=violation.allowed_alternatives,
                can_retry=False
            )
            
            return {
                "status": "blocked",
                "check": check.check_name,
                "violation": violation
            }
        
        # Execute the check
        try:
            findings = check.execute(self.config)
            
            # Log the action
            self.trace_logger.log_action(
                component=check.check_name,
                title=f"Executed: {check.check_name}",
                action="execute_check",
                target_resource=f"{check.check_name} scan",
                parameters={"config": self.config},
                expected_result="List of SecurityFindings"
            )
            
            return {
                "status": "success",
                "check": check.check_name,
                "findings": findings
            }
        
        except Exception as e:
            # Generate transparent error explanation
            error_explanation = self.failure_handler.explain_error(
                error={"error_code": "EXECUTION_ERROR", "error_message": str(e)},
                attempted_action=f"Execute {check.check_name}",
                recovery_attempts=["Retry with default config"]
            )
            
            # Log the error with explanation
            self.trace_logger.log_error(
                component="Orchestrator",
                title=f"Check Failed: {check.check_name}",
                error_type=error_explanation.error_category.value,
                error_message=error_explanation.error_message,
                what_happened=error_explanation.what_happened,
                what_is_needed=error_explanation.what_is_needed,
                next_steps=error_explanation.next_steps,
                can_retry=error_explanation.can_retry
            )
            
            return {
                "status": "failed",
                "check": check.check_name,
                "error": str(e),
                "explanation": error_explanation
            }
    def _validate_findings_aggressively(self) -> List[SecurityFinding]:
        """Aggressively validate all findings before reporting"""
        self.trace_logger.log_info(
            component="ValidationEngine",
            title="Validating Findings",
            message=f"Aggressively validating {len(self.all_findings)} findings"
        )
        self.logger.info(f"Starting validation of {len(self.all_findings)} findings")
        validated_findings = []
        validation_summary = {
            "total": 0,
            "verified": 0,
            "rejected": 0,
            "downgraded": 0
        }
        for finding in self.all_findings:
            validation_summary["total"] += 1
            
            # Validate the finding
            result = self.validation_engine.validate_finding(
                finding,
                finding.evidence  # Raw API evidence
            )
            
            # Log validation
            self.trace_logger.log_validation(
                component="ValidationEngine",
                title=f"Validated: {finding.title}",
                status=result.status.value,
                confidence=result.confidence,
                discrepancies=result.discrepancies,
                evidence_match=result.evidence_match
            )
            if result.status.value == "verified":
                validated_findings.append(result.verified_finding or finding)
                validation_summary["verified"] += 1
            elif result.status.value == "rejected":
                # Still include rejected findings - better to be safe than miss vulnerabilities
                validated_findings.append(result.verified_finding or finding)
                validation_summary["rejected"] += 1
            elif result.status.value == "downgraded":
                validated_findings.append(result.verified_finding or finding)
                validation_summary["downgraded"] += 1
            else:
                # Include findings with other statuses (needs_info, etc.)
                validated_findings.append(result.verified_finding or finding)
                validation_summary["needs_info"] = validation_summary.get("needs_info", 0) + 1
        return validated_findings
    
    def _build_agentic_summary(self, start_time: datetime, 
                              findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Build comprehensive summary with agentic insights"""
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Build summary
        summary = {
            "execution_metadata": {
                "start_time": start_time.isoformat() + "Z",
                "end_time": datetime.utcnow().isoformat() + "Z",
                "duration_seconds": duration,
                "session_id": self.trace_logger.session_id
            },
            "decision_trace": {
                "total_decisions": len(self.decision_engine.get_decision_history()),
                "trace_file": "logs/decision_trace.json"
            },
            "validation_summary": self.validation_engine.get_validation_summary(),
            "guard_rails_summary": self.guard_rails.get_violations_summary(),
            "error_summary": self.failure_handler.get_error_summary(),
            "findings_summary": {
                "total_findings": len(findings),
                "by_severity": severity_counts,
                "average_confidence": sum(f.confidence for f in findings) / len(findings) if findings else 0.0
            },
            "findings": [f.to_dict() for f in findings]
        }
        
        return summary
    
    def _export_decision_trace(self) -> None:
        """Export decision trace to file"""
        try:
            trace_file = "logs/decision_trace.json"
            self.trace_logger.save_trace_to_file(trace_file, format="json")
            
            # Also export markdown for readability
            markdown_file = "logs/decision_trace.md"
            self.trace_logger.save_trace_to_file(markdown_file, format="markdown")
            
            self.logger.info("Decision traces exported", json_file=trace_file, markdown_file=markdown_file)
        
        except Exception as e:
            self.logger.error(f"Failed to export decision trace: {e}")
    
    @property
    def execution_results(self) -> Dict[str, Any]:
        """Get the latest execution results"""
        return self._execution_results
    
    def get_all_findings(self) -> List[SecurityFinding]:
        """Get all validated findings"""
        with self.results_lock:
            return list(self.all_findings)
    
    def get_decision_history(self) -> List[Any]:
        """Get full decision history"""
        return self.decision_engine.get_decision_history()
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get validation summary"""
        return self.validation_engine.get_validation_summary()
