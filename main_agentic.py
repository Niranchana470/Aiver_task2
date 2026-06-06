#!/usr/bin/env python3
"""
Offensive Security Agent - Agentic Main Entry Point

This is the NEW main entry point that uses the agentic architecture
with decision-making, validation, guard rails, and observability.

Replaces the script-like execution with intelligent, context-aware operation.
"""
import sys
import argparse
import signal
from pathlib import Path
from typing import Dict, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.logger import get_logger
from src.core.config_loader import ConfigLoader
from src.core.agentic_orchestrator import AgenticOrchestrator
from src.core.reporter import SecurityReporter

# Import all checks
from src.checks.s3_security_check import S3SecurityCheck
from src.checks.iam_security_check import IAMSecurityCheck
from src.checks.security_group_check import SecurityGroupCheck
from src.checks.ec2_security_check import EC2SecurityCheck
from src.checks.rds_security_check import RDSSecurityCheck
from src.checks.kms_security_check import KMSSecurityCheck
from src.checks.cloudtrail_security_check import CloudTrailSecurityCheck
from src.checks.lambda_security_check import LambdaSecurityCheck
from src.checks.api_endpoint_check import APIEndpointCheck
from src.checks.cve_scanner import CVEScanner
from src.checks.secrets_scanner import SecretsScanner


class AgenticSecurityAgent:
    """
    Agentic Security Agent with full reasoning capabilities
    
    This agent demonstrates all 5 required traits:
    1. Decision Making: Context-aware action selection
    2. Aggressive Validation: Self-verification of findings
    3. Transparent Failure: Detailed error explanations
    4. Guard Rails: Scope enforcement
    5. Observability: Decision trace logging
    """
    
    def __init__(self, config_path: str):
        # Initialize logger
        self.logger = get_logger("AgenticSecurityAgent", {
            "log_dir": "logs",
            "level": "INFO"
        })
        
        # Load configuration
        self.config_loader = ConfigLoader()
        self.config = self.config_loader.load_config(config_path)
        
        self.logger.info("Agentic Security Agent initialized", config=config_path)
        
        # Initialize orchestrator
        self.orchestrator = AgenticOrchestrator(self.config, self.logger)
        
        # Register all checks
        self._register_checks()
        
        # Initialize reporter
        self.reporter = SecurityReporter(self.config, self.logger)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _register_checks(self) -> None:
        """Register all available security checks"""
        checks = [
            S3SecurityCheck,
            IAMSecurityCheck,
            SecurityGroupCheck,
            EC2SecurityCheck,
            RDSSecurityCheck,
            KMSSecurityCheck,
            CloudTrailSecurityCheck,
            LambdaSecurityCheck,
            APIEndpointCheck,
            CVEScanner,
            SecretsScanner
        ]
        
        for check_class in checks:
            self.orchestrator.register_check(check_class)
    
    def run_scan(self) -> int:
        """Run a single agentic security scan"""
        self.logger.info("="*70)
        self.logger.info("STARTING AGENTIC SECURITY SCAN")
        self.logger.info("="*70)
        
        try:
            # Execute with agentic intelligence
            results = self.orchestrator.execute_all()
            
            # Generate reports
            self._generate_reports(results)
            
            # Print summary
            self._print_agentic_summary(results)
            
            # Return exit code based on critical findings
            critical_count = results["findings_summary"]["by_severity"].get("Critical", 0)
            if critical_count > 0:
                return 2  # Critical findings found
            else:
                return 0  # Success
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}", exc_info=True)
            return 1
    
    def _generate_reports(self, results: Dict[str, Any]) -> None:
        """Generate JSON and Markdown reports"""
        findings = [f.to_dict() for f in self.orchestrator.get_all_findings()]
        
        # Generate JSON report
        json_report = self.reporter.generate_json_report(
            results.get("execution_metadata", {}),
            findings,
            results.get("validation_summary", {}),
            results.get("guard_rails_summary", {})
        )
        
        # Generate Markdown report
        md_report = self.reporter.generate_markdown_report(
            results.get("execution_metadata", {}),
            findings,
            results.get("validation_summary", {})
        )
        
        self.logger.info(
            "Reports generated",
            json_report=str(json_report),
            markdown_report=str(md_report)
        )
    
    def _print_agentic_summary(self, results: Dict[str, Any]) -> None:
        """Print comprehensive agentic summary"""
        print("\n" + "="*70)
        print("AGENTIC SECURITY SCAN SUMMARY")
        print("="*70)
        
        # Execution metadata
        metadata = results.get("execution_metadata", {})
        print(f"\nSession ID: {metadata.get('session_id', 'N/A')}")
        print(f"Duration: {metadata.get('duration_seconds', 0):.2f} seconds")
        
        # Decision trace
        decision_trace = results.get("decision_trace", {})
        print(f"Decisions Made: {decision_trace.get('total_decisions', 0)}")
        print(f"Decision Trace: {decision_trace.get('trace_file', 'N/A')}")
        
        # Validation summary
        validation = results.get("validation_summary", {})
        print(f"\nValidation Summary:")
        print(f"  Total Validations: {validation.get('total_validations', 0)}")
        print(f"  ✓ Verified: {validation.get('verified', 0)}")
        print(f"  ✗ Rejected: {validation.get('rejected', 0)}")
        print(f"  ↓ Downgraded: {validation.get('downgraded', 0)}")
        
        # Guard rails
        guard_rails = results.get("guard_rails_summary", {})
        print(f"\nGuard Rails:")
        print(f"  Violations Blocked: {guard_rails.get('blocked_violations', 0)}")
        print(f"  API Calls Made: {guard_rails.get('api_calls_made', 0)}")
        
        # Findings summary
        findings_summary = results.get("findings_summary", {})
        print(f"\nFindings Summary:")
        print(f"  Total Findings: {findings_summary.get('total_findings', 0)}")
        print(f"  Average Confidence: {findings_summary.get('average_confidence', 0):.2%}")
        
        print("\nSeverity Breakdown:")
        severity_emojis = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Info": "ℹ️"
        }
        
        for severity, count in findings_summary.get("by_severity", {}).items():
            emoji = severity_emojis.get(severity, "•")
            print(f"  {emoji} {severity.upper()}: {count}")
        
        print("\n" + "="*70)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        sys.exit(130)  # Standard exit code for SIGINT


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Offensive Security Agent - Agentic Security Scanning"
    )
    parser.add_argument(
        "-c", "--config",
        default="config/security_config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode with verbose logging"
    )
    
    args = parser.parse_args()
    
    # Create agent
    try:
        agent = AgenticSecurityAgent(args.config)
        
        # Run scan
        exit_code = agent.run_scan()
        
        sys.exit(exit_code)
    
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
