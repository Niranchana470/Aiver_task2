"""Secrets Scanner for Leaked Credentials"""
from typing import Dict, List, Any
import re
from pathlib import Path

from ..core.base_check import BaseCheck, SecurityFinding, Severity


class SecretsScanner(BaseCheck):
    """
    Scan repositories and config files for leaked credentials:
    - AWS Access Keys
    - API Tokens
    - Private Keys
    - Database Credentials
    - API Secrets
    """
    
    # Patterns for detecting secrets
    SECRET_PATTERNS = {
        "aws_access_key": {
            "pattern": r'(?i)(aws_access_key_id|aws_access_key)\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?',
            "severity": Severity.CRITICAL,
            "description": "AWS Access Key ID leaked"
        },
        "aws_secret_key": {
            "pattern": r'(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            "severity": Severity.CRITICAL,
            "description": "AWS Secret Access Key leaked"
        },
        "aws_session_token": {
            "pattern": r'(?i)(aws_session_token|security_token)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{200,})["\']?',
            "severity": Severity.CRITICAL,
            "description": "AWS Session Token leaked"
        },
        "api_key_generic": {
            "pattern": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9]{32,})["\']?',
            "severity": Severity.HIGH,
            "description": "Generic API key detected"
        },
        "api_token": {
            "pattern": r'(?i)(api[_-]?token|apitoken|bearer[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9\-._~+/]{20,})["\']?',
            "severity": Severity.HIGH,
            "description": "API token detected"
        },
        "private_key": {
            "pattern": r'-----BEGIN ([A-Z]+ PRIVATE KEY)-----',
            "severity": Severity.CRITICAL,
            "description": "Private key detected"
        },
        "database_connection": {
            "pattern": r'(?i)(mongodb|mysql|postgres|redis)://[^:@]+:[^:@]+@',
            "severity": Severity.HIGH,
            "description": "Database connection string with credentials"
        },
        "github_token": {
            "pattern": r'ghp_[A-Za-z0-9]{36}',
            "severity": Severity.HIGH,
            "description": "GitHub personal access token"
        },
        "slack_token": {
            "pattern": r'xox[pbar]-[A-Za-z0-9-]{10,}',
            "severity": Severity.HIGH,
            "description": "Slack token detected"
        },
        "jwt_token": {
            "pattern": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            "severity": Severity.MEDIUM,
            "description": "JWT token detected"
        }
    }
    
    # Files to exclude from scanning
    EXCLUDED_FILES = [
        "package-lock.json",
        "yarn.lock",
        "Pipfile.lock",
        "poetry.lock",
        ".git",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "venv",
        "env"
    ]
    
    # Files that are likely to contain test/demo data
    TEST_FILE_PATTERNS = [
        r"test.*\.py$",
        r"test_.*\.py$",
        r"_test\.py$",
        r"spec\.js$",
        r".*\.test\.js$",
        r"example.*",
        r"demo.*",
        r"samples?/.*"
    ]
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute secrets scanning"""
        scan_paths = config.get("checks", {}).get("SecretsScanner", {}).get("parameters", {}).get("scan_paths", ["."])
        max_file_size = config.get("checks", {}).get("SecretsScanner", {}).get("parameters", {}).get("max_file_size_mb", 10) * 1024 * 1024
        
        self.logger.info(f"[{self.check_name}] Starting secrets scan")
        
        for scan_path in scan_paths:
            path = Path(scan_path)
            if not path.exists():
                self.logger.warning(f"Scan path does not exist: {scan_path}")
                continue
            
            self._scan_directory(path, max_file_size)
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _scan_directory(self, directory: Path, max_file_size: int) -> None:
        """Scan directory for secrets"""
        self.logger.info(f"Scanning directory: {directory}")
        
        # Scan all files in directory
        for item in directory.rglob("*"):
            # Skip excluded directories
            if any(excluded in str(item) for excluded in self.EXCLUDED_FILES):
                continue
            
            # Skip test files
            if any(re.search(pattern, str(item)) for pattern in self.TEST_FILE_PATTERNS):
                continue
            
            if item.is_file():
                try:
                    self._scan_file(item, max_file_size)
                except Exception as e:
                    self.logger.debug(f"Could not scan {item}: {e}")
    
    def _scan_file(self, file_path: Path, max_file_size: int) -> None:
        """Scan individual file for secrets"""
        # Skip binary files and very large files
        if file_path.stat().st_size > max_file_size:
            return
        
        # Skip non-text files by extension
        text_extensions = ['.txt', '.py', '.js', '.json', '.yaml', '.yml', '.env', 
                          '.config', '.conf', '.sh', '.bash', '.zsh', '.md', '.rb',
                          '.go', '.java', '.php', '.ts', '.tsx', '.jsx', '.css',
                          '.html', '.xml', '.gradle', '.properties']
        
        if file_path.suffix.lower() not in text_extensions:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self._scan_content(content, str(file_path))
                
        except Exception as e:
            self.logger.debug(f"Could not read {file_path}: {e}")
    
    def _scan_content(self, content: str, file_path: str) -> None:
        """Scan content for secret patterns"""
        lines = content.split('\\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, secret_config in self.SECRET_PATTERNS.items():
                pattern = secret_config["pattern"]
                severity = secret_config["severity"]
                description = secret_config["description"]
                
                matches = re.finditer(pattern, line)
                for match in matches:
                    # Get the matched secret
                    if secret_type == "private_key":
                        secret_value = f"{match.group(1)}..."  # Don't include full key
                    else:
                        secret_value = match.group(2) if len(match.groups()) > 1 else match.group(1)
                    
                    # Redact the secret in evidence
                    redacted_line = self._redact_secret(line, secret_value)
                    
                    self.add_finding(SecurityFinding(
                        check_name=self.check_name,
                        resource_arn=f"file:{file_path}:{line_num}",
                        severity=severity,
                        title=f"Secret Detected: {description}",
                        description=f"Potential secret found in {file_path} at line {line_num}",
                        evidence={
                            "file": file_path,
                            "line_number": line_num,
                            "secret_type": secret_type,
                            "redacted_line": redacted_line.strip(),
                            "context": self._get_line_context(lines, line_num)
                        },
                        business_impact=(
                            f"Leaked credentials can be exploited by attackers to gain "
                            f"unauthorized access to AWS accounts, APIs, databases, or other services. "
                            f"This is a critical security risk that requires immediate remediation."
                        ),
                        remediation=(
                            f"1. Immediately rotate the leaked credential:\\n"
                            f"   - AWS keys: Disable and create new access keys\\n"
                            f"   - API tokens: Revoke and regenerate\\n"
                            f"   - Private keys: Generate new keypair\\n"
                            f"2. Remove the secret from {file_path}\\n"
                            f"3. Add {file_path} to .gitignore if in repository\\n"
                            f"4. Consider using secret scanning in CI/CD pipeline\\n"
                            f"5. Use environment variables or secret management systems"
                        ),
                        confidence=0.8,  # Secret detection can have false positives
                        timestamp=self._get_timestamp(),
                        metadata={"secret_type": secret_type, "file": file_path}
                    ))
                    self.logger.info(f"Secret found: {secret_type} in {file_path}:{line_num}")
    
    def _redact_secret(self, line: str, secret: str) -> str:
        """Redact secret from line for evidence"""
        if len(secret) > 4:
            redacted = secret[:4] + "*" * (len(secret) - 8) + secret[-4:]
        else:
            redacted = "*" * len(secret)
        
        return line.replace(secret, redacted)
    
    def _get_line_context(self, lines: List[str], line_num: int, context_lines: int = 2) -> List[str]:
        """Get context around a finding"""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        context = []
        for i in range(start, end):
            prefix = ">> " if i == line_num - 1 else "   "
            context.append(f"{prefix}{i+1:4d}: {lines[i].strip()}")
        
        return context
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()