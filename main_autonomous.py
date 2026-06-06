"""Offensive Security Agent - Autonomous Operations (Level 3)"""
import sys
import argparse
import signal
from pathlib import Path
from typing import Dict, Any

from src.utils.logger import get_logger
from src.core.config_loader import ConfigLoader
from src.core.check_engine import CheckEngine
from src.core.reporter import SecurityReporter
from src.core.triage_manager import TriageManager
from src.core.finding_database import FindingDatabase, FindingStatus
from src.core.scheduler import ScheduleManager, ScheduleConfig
from src.core.alert_manager import AlertManager
from src.core.posture_calculator import SecurityPostureCalculator

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


class AutonomousSecurityAgent:
    """Autonomous security agent with Level 2 and Level 3 capabilities"""
    
    def __init__(self, config_path: str):
        # Initialize logger
        self.logger = get_logger("AutonomousSecurityAgent", {"log_dir": "logs"})
        self.logger.info("Initializing Autonomous Security Agent (Level 3)")
        
        # Load configuration
        self.config_loader = ConfigLoader(config_path)
        self.config_loader.load()
        self.config = self.config_loader.to_dict()
        self.logger.info(f"Configuration loaded from: {config_path}")
        
        # Initialize components
        self.reporter = SecurityReporter(self.logger)
        self.triage_manager = TriageManager(self.logger)
        self.db = FindingDatabase("findings.db")
        self.posture_calculator = SecurityPostureCalculator(self.logger)
        self.schedule_manager = ScheduleManager(self.logger)
        
        # Initialize alert manager
        alert_config = self.config.get("alerting", {})
        self.alert_manager = AlertManager(self.logger, alert_config)
        
        # Initialize schedulers if autonomous mode enabled
        if self.config.get("autonomous_mode", {}).get("enabled", False):
            self._initialize_schedulers()
    
    def run_scan(self) -> int:
        """Run a single security scan"""
        try:
            self.logger.info("Starting security scan")
            
            # Create check engine
            engine = CheckEngine(self.logger, self.config_loader.to_dict())
            
            # Register all available checks
            all_checks = [
                # Level 1: Infrastructure checks
                S3SecurityCheck,
                IAMSecurityCheck,
                SecurityGroupCheck,
                EC2SecurityCheck,
                RDSSecurityCheck,
                KMSSecurityCheck,
                CloudTrailSecurityCheck,
                LambdaSecurityCheck,
                # Level 2: Multi-domain checks
                APIEndpointCheck,
                CVEScanner,
                SecretsScanner
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
            
            # Store findings in database
            for finding in all_findings:
                self.db.store_finding(finding)
            
            # Get previous findings for comparison
            previous_findings = self._get_previous_findings()
            
            # Triage findings
            triage_result = self.triage_manager.triage_findings(
                all_findings,
                previous_findings
            )
            
            # Calculate security posture
            posture = self.posture_calculator.calculate_posture_score(
                all_findings,
                previous_findings
            )
            
            # Check for SLA breaches
            findings_past_sla = self.db.get_findings_past_sla()
            if findings_past_sla:
                self.alert_manager.check_sla_breaches(
                    all_findings,
                    {f.finding_hash: f.sla_deadline for f in findings_past_sla}
                )
            
            # Check for critical findings
            self.alert_manager.check_critical_findings(
                [f for f in all_findings if f.get("status") != "Resolved"]
            )
            
            # Generate reports with triage and posture data
            report_paths = self.reporter.generate_reports(
                execution_results,
                triage_result["findings"]
            )
            
            # Print summary
            self._print_summary(
                execution_results,
                triage_result["summary"],
                posture,
                report_paths
            )
            
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
            self.alert_manager.check_scan_failure(str(e))
            return 1
    
    def run_autonomous(self) -> None:
        """Run in autonomous mode with scheduling"""
        self.logger.info("Starting autonomous security operations")
        
        # Start all schedulers
        self.schedule_manager.start_all()
        
        # Keep running until interrupted
        try:
            while True:
                import time
                time.sleep(60)
                
                # Print status periodically
                status = self.schedule_manager.get_all_status()
                for name, scheduler_status in status.items():
                    if scheduler_status["running"]:
                        self.logger.info(
                            f"Scheduler '{name}': "
                            f"Last scan {scheduler_status['last_scan_time']}, "
                            f"Next scan {scheduler_status['next_scan_time']}"
                        )
                        
        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
            self.schedule_manager.stop_all()
            self.db.close()
    
    def _initialize_schedulers(self) -> None:
        """Initialize scheduled scans"""
        autonomous_config = self.config.get("autonomous_mode", {})
        
        # Main security scan scheduler
        scan_config = ScheduleConfig(
            enabled=autonomous_config.get("scan_schedule", {}).get("enabled", True),
            interval_minutes=autonomous_config.get("scan_schedule", {}).get("interval_minutes", 1440),  # Daily
            initial_delay_minutes=autonomous_config.get("scan_schedule", {}).get("initial_delay_minutes", 0)
        )
        
        self.schedule_manager.create_scheduler(
            "main_security_scan",
            scan_config,
            self.run_scan
        )
        
        # Posture check scheduler (lightweight)
        posture_config = ScheduleConfig(
            enabled=autonomous_config.get("posture_check", {}).get("enabled", True),
            interval_minutes=autonomous_config.get("posture_check", {}).get("interval_minutes", 360),  # 6 hours
        )
        
        self.schedule_manager.create_scheduler(
            "posture_check",
            posture_config,
            self._run_posture_check
        )
    
    def _run_posture_check(self) -> int:
        """Run security posture check"""
        try:
            # Get current posture from database
            posture_score = self.db.get_security_posture_score(days=30)
            
            # Get historical comparison
            previous_score = self.db.get_security_posture_score(days=60)
            
            # Check for decline
            self.alert_manager.check_security_posture_decline(
                posture_score["posture_score"],
                previous_score["posture_score"],
                threshold=10
            )
            
            self.logger.info(
                f"Security Posture Score: {posture_score['posture_score']}/100 "
                f"({posture_score.get('open_findings', 0)} open findings)"
            )
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Error in posture check: {e}")
            return 1
    
    def _get_previous_findings(self) -> list:
        """Get findings from previous scan for comparison"""
        # In production, this would query the database for the most recent scan
        # For now, return empty list
        return []
    
    def _print_summary(
        self,
        execution_results: dict,
        triage_summary: dict,
        posture,
        report_paths: dict
    ) -> None:
        """Print comprehensive summary"""
        summary = execution_results.get("execution_summary", {})
        severity_breakdown = summary.get("severity_breakdown", {})
        
        print("\\n" + "="*70)
        print("AUTONOMOUS SECURITY AGENT - SCAN SUMMARY")
        print("="*70)
        print(f"Scan ID: {report_paths.get('scan_id', 'unknown')}")
        print(f"Duration: {summary.get('duration_seconds', 0):.2f} seconds")
        print(f"Checks Executed: {execution_results.get('successful_checks', 0)}")
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        print()
        
        # Security Posture
        print("Security Posture:")
        trend_emoji = {
            "Improving": "📈",
            "Declining": "📉",
            "Stable": "➡️"
        }.get(posture.trend_direction.value, "➡️")
        
        print(f"  Score: {posture.overall_score}/100 {trend_emoji} {posture.trend_direction.value}")
        print(f"  Risk Level: {posture.risk_level}")
        print(f"  Compliance: {posture.compliance_score}%")
        print()
        
        # Severity Breakdown
        print("Severity Breakdown:")
        print(f"  🔴 CRITICAL: {severity_breakdown.get('Critical', 0)}")
        print(f"  🟠 HIGH: {severity_breakdown.get('High', 0)}")
        print(f"  🟡 MEDIUM: {severity_breakdown.get('Medium', 0)}")
        print(f"  🟢 LOW: {severity_breakdown.get('Low', 0)}")
        print(f"  ℹ️  INFO: {severity_breakdown.get('Info', 0)}")
        print()
        
        # Triage Summary
        print("Triage Summary:")
        impact_breakdown = triage_summary.get("business_impact_breakdown", {})
        print(f"  Business Impact Critical: {impact_breakdown.get('Critical', 0)}")
        print(f"  Business Impact High: {impact_breakdown.get('High', 0)}")
        print(f"  Business Impact Medium: {impact_breakdown.get('Medium', 0)}")
        print(f"  New Findings: {triage_summary.get('status_breakdown', {}).get('New', 0)}")
        print(f"  Recurring Findings: {triage_summary.get('status_breakdown', {}).get('Recurring', 0)}")
        print()
        
        # Recommendations
        recommendations = self.posture_calculator.generate_recommendations(posture)
        if recommendations:
            print("Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
            print()
        
        # Reports Generated
        print("Reports Generated:")
        print(f"  📄 JSON: {report_paths.get('json', 'unknown')}")
        print(f"  📝 Markdown: {report_paths.get('markdown', 'unknown')}")
        print(f"  💾 Database: findings.db")
        print("="*70)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Autonomous Offensive Security Agent - AWS Infrastructure Security Scanner (Level 3)"
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default="config/security_config.yaml",
        help="Path to configuration file (default: config/security_config.yaml)"
    )
    parser.add_argument(
        "--autonomous",
        action="store_true",
        help="Run in autonomous mode with scheduling"
    )
    
    args = parser.parse_args()
    
    # Validate config file exists
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Configuration file not found: {args.config}")
        print("Create a configuration file or specify the correct path with -c")
        return 1
    
    # Run the agent
    agent = AutonomousSecurityAgent(str(config_path))
    
    if args.autonomous:
        # Run in autonomous mode
        signal.signal(signal.SIGINT, lambda sig, frame: agent.schedule_manager.stop_all())
        agent.run_autonomous()
        return 0
    else:
        # Run single scan
        exit_code = agent.run_scan()
        agent.db.close()
        return exit_code


if __name__ == "__main__":
    sys.exit(main())