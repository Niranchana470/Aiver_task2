"""Scheduler for Autonomous Security Scanning"""
import time
import threading
from typing import Dict, Any, Callable, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
import schedule


@dataclass
class ScheduleConfig:
    """Schedule configuration"""
    enabled: bool
    interval_minutes: int
    initial_delay_minutes: int = 0
    max_retries: int = 3
    retry_delay_minutes: int = 5


class ScanScheduler:
    """
    Schedule and execute security scans autonomously
    """
    
    def __init__(self, logger, config: ScheduleConfig):
        self.logger = logger
        self.config = config
        self.scan_function: Optional[Callable] = None
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self.last_scan_time: Optional[datetime] = None
        self.next_scan_time: Optional[datetime] = None
        self.scan_count = 0
        self.failure_count = 0
    
    def register_scan_function(self, scan_func: Callable) -> None:
        """Register the function to execute for each scan"""
        self.scan_function = scan_func
        self.logger.info("Scan function registered with scheduler")
    
    def start(self) -> None:
        """Start the scheduled scanner"""
        if not self.config.enabled:
            self.logger.info("Scheduler is disabled in configuration")
            return
        
        if not self.scan_function:
            self.logger.error("Cannot start scheduler: No scan function registered")
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        self.logger.info(
            f"Scheduler started: Scans every {self.config.interval_minutes} minutes"
        )
    
    def stop(self) -> None:
        """Stop the scheduled scanner"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        self.logger.info("Scheduler stopped")
    
    def _run_scheduler(self) -> None:
        """Run the scheduler loop"""
        # Wait for initial delay
        if self.config.initial_delay_minutes > 0:
            self.logger.info(
                f"Waiting {self.config.initial_delay_minutes} minutes before first scan"
            )
            time.sleep(self.config.initial_delay_minutes * 60)
        
        # Set up initial schedule
        schedule.every(self.config.interval_minutes).minutes.do(self._execute_scan)
        
        # Execute first scan immediately
        self._execute_scan()
        
        # Run scheduler loop
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
                
                # Update next scan time
                next_run = schedule.next_run()
                if next_run:
                    self.next_scan_time = next_run
                    
            except Exception as e:
                self.logger.error(f"Scheduler error: {e}")
                time.sleep(60)
    
    def _execute_scan(self) -> None:
        """Execute a scan with retry logic"""
        if not self.running:
            return
        
        self.logger.info(f"Starting scheduled scan #{self.scan_count + 1}")
        self.last_scan_time = datetime.utcnow()
        
        retries = 0
        while retries <= self.config.max_retries:
            try:
                # Execute scan
                result = self.scan_function()
                
                # Scan successful
                self.scan_count += 1
                self.failure_count = 0
                
                self.logger.info(
                    f"Scheduled scan #{self.scan_count} completed successfully"
                )
                
                # Store result if needed
                self._store_scan_result(result)
                
                break
                
            except Exception as e:
                retries += 1
                self.failure_count += 1
                
                self.logger.error(
                    f"Scan attempt {retries}/{self.config.max_retries + 1} failed: {e}"
                )
                
                if retries <= self.config.max_retries:
                    delay = self.config.retry_delay_minutes
                    self.logger.info(f"Retrying in {delay} minutes...")
                    time.sleep(delay * 60)
                else:
                    self.logger.error(
                        f"Scan failed after {self.config.max_retries + 1} attempts"
                    )
    
    def _store_scan_result(self, result: Any) -> None:
        """Store scan result (placeholder for database storage)"""
        # In production, store results in database
        self.logger.debug(f"Scan result stored: {type(result)}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        return {
            "running": self.running,
            "enabled": self.config.enabled,
            "interval_minutes": self.config.interval_minutes,
            "last_scan_time": self.last_scan_time.isoformat() if self.last_scan_time else None,
            "next_scan_time": self.next_scan_time.isoformat() if self.next_scan_time else None,
            "scan_count": self.scan_count,
            "failure_count": self.failure_count
        }


class ScheduleManager:
    """
    Manage multiple scheduled scans with different configurations
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.schedulers: Dict[str, ScanScheduler] = {}
    
    def create_scheduler(
        self,
        name: str,
        config: ScheduleConfig,
        scan_function: Callable
    ) -> ScanScheduler:
        """Create and register a new scheduler"""
        scheduler = ScanScheduler(self.logger, config)
        scheduler.register_scan_function(scan_function)
        self.schedulers[name] = scheduler
        
        self.logger.info(f"Created scheduler '{name}'")
        return scheduler
    
    def start_scheduler(self, name: str) -> None:
        """Start a specific scheduler"""
        if name in self.schedulers:
            self.schedulers[name].start()
        else:
            self.logger.error(f"Scheduler '{name}' not found")
    
    def stop_scheduler(self, name: str) -> None:
        """Stop a specific scheduler"""
        if name in self.schedulers:
            self.schedulers[name].stop()
        else:
            self.logger.error(f"Scheduler '{name}' not found")
    
    def start_all(self) -> None:
        """Start all schedulers"""
        for name, scheduler in self.schedulers.items():
            self.logger.info(f"Starting scheduler '{name}'")
            scheduler.start()
    
    def stop_all(self) -> None:
        """Stop all schedulers"""
        for name, scheduler in self.schedulers.items():
            self.logger.info(f"Stopping scheduler '{name}'")
            scheduler.stop()
    
    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all schedulers"""
        return {
            name: scheduler.get_status()
            for name, scheduler in self.schedulers.items()
        }