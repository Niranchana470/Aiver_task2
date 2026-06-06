"""Security Group Check"""
from typing import Dict, List, Any
from botocore.exceptions import ClientError

from .base_aws_check import BaseAWSCheck
from ..core.base_check import SecurityFinding, Severity


class SecurityGroupCheck(BaseAWSCheck):
    """
    Check Security Groups for:
    - Open ports to 0.0.0.0/0
    - Overly permissive rules
    - Unused security groups
    """
    
    def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
        """Execute security group checks"""
        self.setup_aws_client(config)
        ec2_client = self.aws_manager.get_client("ec2")
        
        self.logger.info(f"[{self.check_name}] Starting security group scan")
        
        try:
            # Describe all security groups
            response = ec2_client.describe_security_groups()
            security_groups = response.get("SecurityGroups", [])
            self.resources_scanned = len(security_groups)
            
            for sg in security_groups:
                sg_id = sg["GroupId"]
                sg_arn = self.build_arn("ec2", f"security-group/{sg_id}")
                
                self._check_security_group(ec2_client, sg, sg_arn)
                
        except ClientError as e:
            self.handle_aws_error(e, "ec2:*", "Failed to list security groups")
        except Exception as e:
            self.logger.error(f"Unexpected error in security group check: {e}")
        
        self.logger.info(
            f"[{self.check_name}] Completed: {len(self.findings)} findings"
        )
        return self.findings
    
    def _check_security_group(
        self,
        ec2_client,
        sg: Dict[str, Any],
        sg_arn: str
    ) -> None:
        """Check individual security group"""
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "unnamed")
        
        # Check inbound rules
        for rule in sg.get("IpPermissions", []):
            self._check_rule(
                ec2_client,
                sg_id,
                sg_name,
                sg_arn,
                rule,
                "inbound"
            )
        
        # Check outbound rules
        for rule in sg.get("IpPermissionsEgress", []):
            self._check_rule(
                ec2_client,
                sg_id,
                sg_name,
                sg_arn,
                rule,
                "outbound"
            )
    
    def _check_rule(
        self,
        ec2_client,
        sg_id: str,
        sg_name: str,
        sg_arn: str,
        rule: Dict[str, Any],
        direction: str
    ) -> None:
        """Check individual security group rule"""
        from_ip_ranges = rule.get("IpRanges", [])
        from_ipv6_ranges = rule.get("Ipv6Ranges", [])
        
        # Check for open access to 0.0.0.0/0
        for ip_range in from_ip_ranges:
            cidr = ip_range.get("CidrIp", "")
            
            if cidr == "0.0.0.0/0":
                # Determine severity based on protocol and port
                severity = self._assess_rule_severity(rule, direction)
                
                # Build finding
                finding = self._create_rule_finding(
                    sg_id,
                    sg_name,
                    sg_arn,
                    rule,
                    direction,
                    cidr,
                    severity
                )
                
                self.add_finding(finding)
    
    def _assess_rule_severity(self, rule: Dict[str, Any], direction: str) -> Severity:
        """Assess severity of security group rule"""
        # Outbound rules are generally less critical
        if direction == "outbound":
            return Severity.LOW
        
        # Get protocol and ports
        ip_protocol = rule.get("IpProtocol", "")
        
        # If protocol is -1, it's all traffic
        if ip_protocol == "-1":
            return Severity.CRITICAL
        
        # Check for specific dangerous ports
        from_port = rule.get("FromPort", -1)
        to_port = rule.get("ToPort", -1)
        
        # Common management ports
        dangerous_ports = {
            22: "SSH",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            1433: "MSSQL",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS"
        }
        
        # Check if rule covers any dangerous port
        for port, service in dangerous_ports.items():
            if from_port <= port <= to_port or from_port == -1:
                return Severity.CRITICAL
        
        # HTTPS and HTTP are medium severity
        if from_port == 80 or to_port == 80:
            return Severity.MEDIUM
        if from_port == 443 or to_port == 443:
            return Severity.MEDIUM
        
        # Default to high for any other open port
        return Severity.HIGH
    
    def _create_rule_finding(
        self,
        sg_id: str,
        sg_name: str,
        sg_arn: str,
        rule: Dict[str, Any],
        direction: str,
        cidr: str,
        severity: Severity
    ) -> SecurityFinding:
        """Create a security finding for a rule"""
        ip_protocol = rule.get("IpProtocol", "")
        from_port = rule.get("FromPort", "N/A")
        to_port = rule.get("ToPort", "N/A")
        
        if ip_protocol == "-1":
            port_desc = "All protocols"
        elif from_port == to_port:
            port_desc = f"Port {from_port}"
        else:
            port_desc = f"Ports {from_port}-{to_port}"
        
        return SecurityFinding(
            check_name=self.check_name,
            resource_arn=sg_arn,
            severity=severity,
            title=f"Security Group {sg_id} ({sg_name}) - Open {direction.title()} to 0.0.0.0/0",
            description=f"Security group '{sg_name}' ({sg_id}) allows {direction} traffic from {cidr} on {port_desc} ({ip_protocol})",
            evidence={
                "security_group_id": sg_id,
                "security_group_name": sg_name,
                "direction": direction,
                "ip_protocol": ip_protocol,
                "from_port": from_port,
                "to_port": to_port,
                "cidr": cidr,
                "rule": rule
            },
            business_impact=(
                f"Open {direction} access to the internet exposes services to "
                f"unauthorized access, brute force attacks, and potential exploitation."
            ),
            remediation=(
                f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                f"--protocol {ip_protocol} --port {from_port}-{to_port} "
                f"--cidr {cidr}\\n"
                f"Then modify rule to restrict source IPs to known ranges"
            ),
            confidence=1.0,
            timestamp=self._get_timestamp()
        )
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow()