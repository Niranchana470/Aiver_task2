"""Dependency CVE Scanner"""
from typing import Dict, List, Any
import re
from pathlib import Path
import json
import yaml

from ..core.base_check import BaseCheck, SecurityFinding, Severity


class CVEScanner(BaseCheck):
    """
    Scan code dependency manifests for known CVEs:
    - package.json (Node.js)
    - requirements.txt (Python)
    - Gemfile (Ruby)
    - pom.xml (Java/Maven)
    - build.gradle (Java/Gradle)
    - composer.json (PHP)
    - go.mod (Go)
    """
    
    # Known vulnerable packages with CVEs (sample database)
    KNOWN_VULNERABILITIES = {
        "nodejs": {
            "lodash": {"versions": "<4.17.21", "cve": "CVE-2021-23337", "severity": "HIGH"},
            "axios": {"versions": "<0.21.2", "cve": "CVE-2021-3749", "severity": "MEDIUM"},
            "minimist": {"versions": "<1.2.6", "cve": "CVE-2021-44906", "severity": "HIGH"},
            "js-yaml": {"versions": "<3.13.1", "cve": "CVE-2021-44917", "severity": "HIGH"},
        },
        "python": {
            "pillow": {"versions": "<8.3.2", "cve": "CVE-2021-28675", "severity": "MEDIUM"},
            "urllib3": {"versions": "<1.26.5", "cve": "CVE-2021-28363", "severity": "HIGH"},
            "pyyaml": {"versions": "<5.4.1", "cve": "CVE-2020-14343", "severity": "MEDIUM"},
        },
        "java": {
            "log4j": {"versions": "<2.17.1", "cve": "CVE-2021-44228", "severity": "CRITICAL"},
            "jackson-databind": {"versions": "<2.12.6.1", "cve": "CVE-2021-39139", "severity": "HIGH"},
        }
    }
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute dependency vulnerability scanning"""
        scan_paths = config.get("checks", {}).get("CVEScanner", {}).get("parameters", {}).get("scan_paths", ["."])
        
        self.logger.info(f"[{self.check_name}] Starting dependency CVE scan")
        
        for scan_path in scan_paths:
            path = Path(scan_path)
            if not path.exists():
                self.logger.warning(f"Scan path does not exist: {scan_path}")
                continue
            
            self._scan_directory(path)
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _scan_directory(self, directory: Path) -> None:
        """Scan directory for dependency files"""
        self.logger.info(f"Scanning directory: {directory}")
        
        # Look for dependency files
        dependency_files = [
            "package.json",
            "requirements.txt",
            "Gemfile",
            "pom.xml",
            "build.gradle",
            "composer.json",
            "go.mod"
        ]
        
        for dep_file in dependency_files:
            file_path = directory / dep_file
            if file_path.exists():
                self.logger.info(f"Found dependency file: {file_path}")
                self._scan_dependency_file(file_path)
        
        # Recursively scan subdirectories (limit depth to avoid filesystem traversal)
        for item in directory.iterdir():
            if item.is_dir() and not item.name.startswith('.') and item.name != 'node_modules':
                try:
                    self._scan_directory(item)
                except Exception as e:
                    self.logger.debug(f"Could not scan {item}: {e}")
    
    def _scan_dependency_file(self, file_path: Path) -> None:
        """Scan individual dependency file"""
        file_name = file_path.name
        
        try:
            if file_name == "package.json":
                self._scan_package_json(file_path)
            elif file_name == "requirements.txt":
                self._scan_requirements_txt(file_path)
            elif file_name == "Gemfile":
                self._scan_gemfile(file_path)
            elif file_name == "pom.xml":
                self._scan_pom_xml(file_path)
            elif file_name == "build.gradle":
                self._scan_build_gradle(file_path)
            elif file_name == "composer.json":
                self._scan_composer_json(file_path)
            elif file_name == "go.mod":
                self._scan_go_mod(file_path)
                
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
    
    def _scan_package_json(self, file_path: Path) -> None:
        """Scan Node.js package.json"""
        with open(file_path, 'r') as f:
            package_json = json.load(f)
        
        dependencies = {}
        dependencies.update(package_json.get("dependencies", {}))
        dependencies.update(package_json.get("devDependencies", {}))
        
        for package, version in dependencies.items():
            self._check_package_vulnerability(
                package,
                version,
                "nodejs",
                str(file_path)
            )
    
    def _scan_requirements_txt(self, file_path: Path) -> None:
        """Scan Python requirements.txt"""
        with open(file_path, 'r') as f:
            requirements = f.readlines()
        
        for requirement in requirements:
            requirement = requirement.strip()
            if not requirement or requirement.startswith('#'):
                continue
            
            # Parse package and version
            # Format: package==version, package>=version, package~=version, etc.
            match = re.match(r'^([a-zA-Z0-9_-]+)([>=~!<>]+)([0-9.]+)', requirement)
            if match:
                package, operator, version = match.groups()
                self._check_package_vulnerability(
                    package,
                    version,
                    "python",
                    str(file_path)
                )
            else:
                # No version specified, just package name
                package = requirement.split('==')[0].split('>=')[0].split('~=')[0]
                self.logger.debug(f"Package {package} without version constraint in {file_path}")
    
    def _scan_gemfile(self, file_path: Path) -> None:
        """Scan Ruby Gemfile"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Simple regex to find gem declarations
        gem_pattern = r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?"
        matches = re.findall(gem_pattern, content)
        
        for package, version in matches:
            if version:
                self._check_package_vulnerability(
                    package,
                    version,
                    "ruby",
                    str(file_path)
                )
    
    def _scan_pom_xml(self, file_path: Path) -> None:
        """Scan Java Maven pom.xml"""
        content = file_path.read_text()
        
        # Simple regex for dependency extraction (limited implementation)
        dep_pattern = r"<dependency>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>"
        matches = re.findall(dep_pattern, content, re.DOTALL)
        
        for package, version in matches:
            self._check_package_vulnerability(
                package,
                version,
                "java",
                str(file_path)
            )
    
    def _scan_build_gradle(self, file_path: Path) -> None:
        """Scan Java Gradle build.gradle"""
        content = file_path.read_text()
        
        # Simple regex for dependency extraction
        dep_pattern = r"implementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
        matches = re.findall(dep_pattern, content)
        
        for group, package, version in matches:
            self._check_package_vulnerability(
                f"{group}:{package}",
                version,
                "java",
                str(file_path)
            )
    
    def _scan_composer_json(self, file_path: Path) -> None:
        """Scan PHP composer.json"""
        with open(file_path, 'r') as f:
            composer_json = json.load(f)
        
        dependencies = {}
        dependencies.update(composer_json.get("require", {}))
        dependencies.update(composer_json.get("require-dev", {}))
        
        for package, version in dependencies.items():
            # Strip 'v' prefix if present
            version = version.lstrip('v')
            self._check_package_vulnerability(
                package,
                version,
                "php",
                str(file_path)
            )
    
    def _scan_go_mod(self, file_path: Path) -> None:
        """Scan Go go.mod"""
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Parse require directives
        require_pattern = r"require\s+([^\s]+)\s+([^\s]+)"
        matches = re.findall(require_pattern, content)
        
        for package, version in matches:
            self._check_package_vulnerability(
                package,
                version,
                "go",
                str(file_path)
            )
    
    def _check_package_vulnerability(
        self,
        package: str,
        version: str,
        ecosystem: str,
        source_file: str
    ) -> None:
        """Check if package/version has known vulnerabilities"""
        # Normalize version (remove 'v' prefix, etc.)
        version = version.lstrip('v').strip()
        
        # Check against known vulnerabilities
        if ecosystem in self.KNOWN_VULNERABILITIES:
            vuln_data = self.KNOWN_VULNERABILITIES[ecosystem].get(package)
            
            if vuln_data:
                # Check if version is vulnerable
                vuln_version = vuln_data["versions"]
                cve = vuln_data["cve"]
                severity_str = vuln_data["severity"]
                
                if self._is_version_vulnerable(version, vuln_version):
                    severity = Severity[severity_str]
                    
                    self.add_finding(SecurityFinding(
                        check_name=self.check_name,
                        resource_arn=f"dependency:{ecosystem}:{package}:{version}",
                        severity=severity,
                        title=f"Known Vulnerable Dependency: {package}@{version}",
                        description=f"Package '{package}' version '{version}' in {ecosystem} has known vulnerability ({cve})",
                        evidence={
                            "package": package,
                            "version": version,
                            "ecosystem": ecosystem,
                            "cve": cve,
                            "vulnerable_versions": vuln_version,
                            "source_file": source_file
                        },
                        business_impact=(
                            f"Package '{package}' has {cve} vulnerability. "
                            f"This can lead to security exploits including remote code execution, "
                            f"data exposure, or denial of service depending on the vulnerability."
                        ),
                        remediation=(
                            f"Update {package} to a secure version:\\n"
                            f"- Current: {version}\\n"
                            f"- Vulnerable: {vuln_version}\\n"
                            f"- Run: Update to latest stable version\\n"
                            f"- For {ecosystem}: Use package manager to update (npm/pip/maven/etc.)"
                        ),
                        confidence=1.0,
                        timestamp=self._get_timestamp(),
                        metadata={"cve": cve, "source_file": source_file}
                    ))
                    self.logger.info(f"Found vulnerable package: {package}@{version} ({cve})")
    
    def _is_version_vulnerable(self, current_version: str, vuln_version_spec: str) -> bool:
        """Check if current version falls within vulnerable version range"""
        # Simplified version comparison (for demonstration)
        # In production, use proper version comparison library
        
        try:
            # Parse version specification
            if vuln_version_spec.startswith("<"):
                vuln_version = vuln_version_spec.lstrip("<")
                # Compare versions (simple string comparison for demo)
                # In production, use semantic version parsing
                parts_current = current_version.split('.')
                parts_vuln = vuln_version.split('.')
                
                for i in range(max(len(parts_current), len(parts_vuln))):
                    c = int(parts_current[i]) if i < len(parts_current) else 0
                    v = int(parts_vuln[i]) if i < len(parts_vuln) else 0
                    if c < v:
                        return True
                    elif c > v:
                        return False
                
        except (ValueError, IndexError):
            # If version parsing fails, assume not vulnerable
            return False
        
        return False
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()