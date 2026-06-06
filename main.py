"""Offensive Security Agent - Main Entry Point"""
import sys
import argparse
from pathlib import Path

from src.utils.logger import get_logger
from src.core.config_loader import ConfigLoader
from src.core.check_engine import CheckEngine
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


class OffensiveSecurityAgent:
    """Main security agent orchestrator"""
    
    def __init__(self, config_path: str):
        # Initialize logger
        self.logger = get_logger("OffensiveSecurityAgent", {"log_dir": "logs"})
        self.logger.info("Initializing Offensive Security Agent")
        
        # Load configuration
        self.config_loader = ConfigLoader(config_path)
        self.config = self.config_loader.load()
        self.logger.info(f"Configuration loaded from: {config_path}")
        
        # Initialize reporter
        self.reporter = SecurityReporter(self.logger)
    
    def run(self) -> int:
        """Run the security scan and return exit code"""
        try:
            # Create check engine
            engine = CheckEngine(self.logger, self.config_loader.to_dict())
            
            # Register all available checks
            all_checks = [
                S3SecurityCheck,
                IAMSecurityCheck,
                SecurityGroupCheck,
                EC2SecurityCheck,
                RDSSecurityCheck,
                KMSSecurityCheck,
                CloudTrailSecurityCheck,
                LambdaSecurityCheck
            ]
            
            # Register enabled checks only
            enabled_checks = self.config_loader.get_enabled_checks()
            checks_registered = 0
            
            for check_class in all_checks:
                check_name = check_class.__name__
                if enabled_checks and check_name not in enabled_checks:
                    self.logger.info(f"Skipping disabled check: {check_name}")
                    continue
                
                engine.register_check(check_class)
                checks_registered += 1
            
            self.logger.info(f"Registered {checks_registered} security checks")
            
            if checks_registered == 0:
                self.logger.warning("No checks enabled in configuration")
                return 1
            
            # Execute all checks
            execution_results = engine.execute_all()
            
            # Get all findings
            all_findings = [f.to_dict() for f in engine.get_all_findings()]
            
            # Generate reports
            report_paths = self.reporter.generate_reports(
                execution_results,
                all_findings
            )
            
            # Print summary
            self._print_summary(execution_results, report_paths)
            
            # Return exit code based on critical findings
            critical_count = len(engine.get_critical_findings())
            if critical_count > 0:
                self.logger.error(f"Scan completed with {critical_count} CRITICAL findings")
                return 2
            else:
                self.logger.info("Scan completed successfully")
                return 0
                
        except Exception as e:
            self.logger.critical(f"Fatal error during scan: {e}")
            import traceback
            self.logger.critical(traceback.format_exc())
            return 1
    
    def _print_summary(
        self,
        execution_results: dict,
        report_paths: dict
    ) -> None:
        """Print execution summary to console"""
        summary = execution_results.get("execution_summary", {})
        severity_breakdown = summary.get("severity_breakdown", {})
        
        print("\\n" + "="*70)
        print("SECURITY SCAN SUMMARY")
        print("="*70)
        print(f"Scan ID: {report_paths.get('scan_id', 'unknown')}")
        print(f"Duration: {summary.get('duration_seconds', 0):.2f} seconds")
        print(f"Checks Executed: {execution_results.get('successful_checks', 0)}")
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        print()
        print("Severity Breakdown:")
        print(f"  🔴 CRITICAL: {severity_breakdown.get('Critical', 0)}")
        print(f"  🟠 HIGH: {severity_breakdown.get('High', 0)}")
        print(f"  🟡 MEDIUM: {severity_breakdown.get('Medium', 0)}")
        print(f"  🟢 LOW: {severity_breakdown.get('Low', 0)}")
        print(f"  ℹ️  INFO: {severity_breakdown.get('Info', 0)}")
        print()
        print("Reports Generated:")
        print(f"  📄 JSON: {report_paths.get('json', 'unknown')}")
        print(f"  📝 Markdown: {report_paths.get('markdown', 'unknown')}")
        print("="*70)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Offensive Security Agent - AWS Infrastructure Security Scanner"
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="config/security_config.yaml",
        help="Path to configuration file (default: config/security_config.yaml)"
    )
    
    args = parser.parse_args()
    
    # Validate config file exists
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Configuration file not found: {args.config}")
        print("Create a configuration file or specify the correct path with -c")
        return 1
    
    # Run the agent
    agent = OffensiveSecurityAgent(str(config_path))
    exit_code = agent.run()
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())