"""Configuration Loader"""
import yaml
import json
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class CheckConfig:
    """Configuration for a single security check"""
    enabled: bool
    severity_threshold: str
    timeout: int
    parameters: Dict[str, Any]


@dataclass
class AWSConfig:
    """AWS configuration"""
    profile: str
    region: str
    assume_role_arn: str = None
    external_id: str = None


@dataclass
class AgentConfig:
    """Main agent configuration"""
    aws: AWSConfig
    checks: Dict[str, CheckConfig]
    output: Dict[str, Any]
    logging: Dict[str, Any]
    execution: Dict[str, Any]
    check_definitions: Dict[str, Any]


class ConfigLoader:
    """Load and validate configuration from YAML/JSON"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        
    def load(self) -> AgentConfig:
        """Load configuration from file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            if self.config_path.suffix in ['.yaml', '.yml']:
                self.config = yaml.safe_load(f)
            elif self.config_path.suffix == '.json':
                self.config = json.load(f)
            else:
                raise ValueError(f"Unsupported config format: {self.config_path.suffix}")
        
        return self._parse_config()
    
    def _parse_config(self) -> AgentConfig:
        """Parse configuration into structured objects"""
        # AWS configuration
        aws_config = AWSConfig(
            profile=self.config.get("aws", {}).get("profile", "default"),
            region=self.config.get("aws", {}).get("region", "us-east-1"),
            assume_role_arn=self.config.get("aws", {}).get("assume_role_arn"),
            external_id=self.config.get("aws", {}).get("external_id")
        )
        
        # Check configurations
        checks_config = {}
        for check_name, check_def in self.config.get("checks", {}).items():
            checks_config[check_name] = CheckConfig(
                enabled=check_def.get("enabled", True),
                severity_threshold=check_def.get("severity_threshold", "Info"),
                timeout=check_def.get("timeout", 300),
                parameters=check_def.get("parameters", {})
            )
        
        # Build agent config
        return AgentConfig(
            aws=aws_config,
            checks=checks_config,
            output=self.config.get("output", {}),
            logging=self.config.get("logging", {}),
            execution=self.config.get("execution", {}),
            check_definitions=self.config.get("check_definitions", {})
        )
    
    def get_enabled_checks(self) -> List[str]:
        """Get list of enabled check names"""
        return [
            name for name, check_config in self.config.get("checks", {}).items()
            if check_config.get("enabled", True)
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Return config as dictionary for engine consumption"""
        return {
            "aws": {
                "profile": self.config.get("aws", {}).get("profile", "default"),
                "region": self.config.get("aws", {}).get("region", "us-east-1"),
                "assume_role_arn": self.config.get("aws", {}).get("assume_role_arn"),
                "external_id": self.config.get("aws", {}).get("external_id")
            },
            "checks": {
                name: {
                    "enabled": cfg.get("enabled", True),
                    "severity_threshold": cfg.get("severity_threshold", "Info"),
                    "timeout": cfg.get("timeout", 300),
                    "parameters": cfg.get("parameters", {})
                }
                for name, cfg in self.config.get("checks", {}).items()
            },
            "output": self.config.get("output", {}),
            "execution": self.config.get("execution", {}),
            "max_workers": self.config.get("execution", {}).get("max_workers", 10),
            "check_timeout": self.config.get("execution", {}).get("check_timeout", 300)
        }