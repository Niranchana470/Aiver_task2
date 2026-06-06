"""Structured Logger for Security Operations"""
import logging
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Any, Dict
from contextlib import contextmanager


class StructuredLogger:
    """Structured JSON logger for full observability"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with human-readable format
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with JSON structured format
        log_dir = Path(config.get("log_dir", "logs"))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"security_agent_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # JSON formatter for file logs
        json_formatter = JsonFormatter()
        file_handler.setFormatter(json_formatter)
        self.logger.addHandler(file_handler)
        
        # Store file path for reference
        self.log_file = str(log_file)
        
        self.logger.info(f"Logger initialized: {name}")
        self.logger.info(f"Structured logs: {log_file}")
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with structured context"""
        self.logger.debug(message, extra={"context": kwargs})
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message with structured context"""
        self.logger.info(message, extra={"context": kwargs})
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with structured context"""
        self.logger.warning(message, extra={"context": kwargs})
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message with structured context"""
        self.logger.error(message, extra={"context": kwargs})
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message with structured context"""
        self.logger.critical(message, extra={"context": kwargs})
    
    @contextmanager
    def log_context(self, **kwargs):
        """Context manager for adding persistent context to logs within a block"""
        old_factory = logging.getLogRecordFactory()
        
        def record_factory(*args, **inner_kwargs):
            record = old_factory(*args, **inner_kwargs)
            if not hasattr(record, 'context'):
                record.context = {}
            record.context.update(kwargs)
            return record
        
        logging.setLogRecordFactory(record_factory)
        try:
            yield
        finally:
            logging.setLogRecordFactory(old_factory)


class JsonFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add context if present
        if hasattr(record, 'context'):
            log_entry["context"] = record.context
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)


def get_logger(name: str, config: Dict[str, Any] = None) -> StructuredLogger:
    """Get or create a structured logger"""
    if config is None:
        config = {
            "log_dir": "logs",
            "level": "INFO"
        }
    return StructuredLogger(name, config)