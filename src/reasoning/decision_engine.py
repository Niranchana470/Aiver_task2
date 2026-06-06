"""
Decision Engine - The reasoning/planning layer
Separates decision-making from execution
"""
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json

from .ai_provider import AIProvider, create_ai_provider


class DecisionType(Enum):
    """Types of decisions the engine makes"""
    SCAN_SCOPE = "scan_scope"  # What to scan and how deep
    CHECK_SELECTION = "check_selection"  # Which checks to run
    FINDING_VALIDATION = "finding_validation"  # Verify findings
    ERROR_RECOVERY = "error_recovery"  # How to handle failures
    PRIORITY_RANKING = "priority_ranking"  # Order of operations


@dataclass
class Decision:
    """A decision made by the reasoning engine"""
    decision_type: DecisionType
    action: str  # What action to take
    reasoning: str  # Why this action was chosen
    confidence: float  # 0.0 to 1.0
    alternatives: List[str]  # Alternative actions considered
    evidence: Dict[str, Any]  # Context that led to this decision
    timestamp: str


class DecisionEngine:
    """
    Core reasoning engine that makes decisions based on context
    Separates planning from execution - key agentic trait
    """
    
    def __init__(self, config: Dict[str, Any], logger):
        self.logger = logger
        self.config = config
        
        # Initialize AI provider
        ai_config = config.get("ai_provider", {})
        if not ai_config.get("api_key") and not ai_config.get("provider") == "mock":
            self.logger.warning("No AI provider configured, using mock provider")
            ai_config["provider"] = "mock"
        
        self.ai_provider = create_ai_provider(ai_config, logger)
        
        # Decision history for observability
        self.decision_history: List[Decision] = []
        
        self.logger.info("Decision Engine initialized with AI provider")
    
    def decide_scan_scope(self, infrastructure_context: Dict[str, Any]) -> Decision:
        """
        Decide what to scan and how deep based on infrastructure state
        
        This replaces hardcoded scripts with context-aware decisions
        """
        self.logger.info("Deciding scan scope...", context=infrastructure_context)
        
        prompt = f"""
You are a security scanning agent. Analyze this infrastructure context and decide what to scan.

Infrastructure Context:
{json.dumps(infrastructure_context, indent=2)}

Available Checks:
- S3SecurityCheck: S3 buckets (encryption, versioning, public access)
- IAMSecurityCheck: IAM users, roles, policies, MFA
- SecurityGroupCheck: Security groups and rules
- EC2SecurityCheck: EC2 instances and volumes
- RDSSecurityCheck: RDS databases
- KMSSecurityCheck: KMS keys
- CloudTrailSecurityCheck: CloudTrail logging
- LambdaSecurityCheck: Lambda functions
- APIEndpointCheck: API endpoints and CORS
- CVEScanner: Dependency vulnerabilities
- SecretsScanner: Secrets in code

Make a decision about:
1. Which checks to run (be selective based on what exists)
2. How deep to scan (quick vs comprehensive)
3. Priority order (what to scan first)

Respond with a clear decision and reasoning.
"""
        
        response = self.ai_provider.complete_with_reasoning(prompt, infrastructure_context)
        
        decision = Decision(
            decision_type=DecisionType.SCAN_SCOPE,
            action=response.content,
            reasoning=response.reasoning or "No detailed reasoning provided",
            confidence=response.confidence,
            alternatives=["Run all checks", "Skip checks with no resources", "Quick scan only"],
            evidence=infrastructure_context,
            timestamp=self._get_timestamp()
        )
        
        self.decision_history.append(decision)
        self._log_decision(decision)
        
        return decision
    
    def decide_check_selection(self, available_checks: List[str], 
                                resource_inventory: Dict[str, int]) -> Decision:
        """
        Decide which checks to run based on discovered resources
        
        Context-aware: Don't run RDS checks if no RDS instances exist
        """
        self.logger.info("Deciding check selection...", resources=resource_inventory)
        
        prompt = f"""
You are a security scanning agent. Decide which checks to run.

Available Checks: {', '.join(available_checks)}

Resource Inventory:
{json.dumps(resource_inventory, indent=2)}

Decide which checks to run based on:
1. Which resources actually exist (skip checks for non-existent resources)
2. Security priority (scan high-risk resources first)
3. Efficiency (don't waste time on empty resource types)

List the checks to run in priority order.
"""
        
        response = self.ai_provider.complete_with_reasoning(
            prompt, 
            {"available_checks": available_checks, "resources": resource_inventory}
        )
        
        decision = Decision(
            decision_type=DecisionType.CHECK_SELECTION,
            action=response.content,
            reasoning=response.reasoning or "No detailed reasoning provided",
            confidence=response.confidence,
            alternatives=["Run all checks", "Run checks with resources only", "User-specified only"],
            evidence={"available_checks": available_checks, "resources": resource_inventory},
            timestamp=self._get_timestamp()
        )
        
        self.decision_history.append(decision)
        self._log_decision(decision)
        
        return decision
    
    def validate_finding_with_aggression(self, finding: Dict[str, Any], 
                                        raw_api_evidence: Dict[str, Any]) -> Decision:
        """
        Aggressively validate a finding before reporting it
        
        This is the "Aggressive Validation" trait - cross-check against raw evidence
        """
        self.logger.info("Aggressively validating finding...", finding=finding["title"])
        
        prompt = f"""
You are a paranoid security validator. You must catch false positives and hallucinations.

Proposed Finding:
{json.dumps(finding, indent=2)}

Raw API Evidence:
{json.dumps(raw_api_evidence, indent=2)}

Question: Is this finding REAL or a FALSE POSITIVE?

Analyze:
1. Does the raw API evidence EXACTLY support the claim?
2. Are there any edge cases we're missing?
3. Could this be a false alarm?
4. What specific evidence proves this is real?

If it's real, confirm it.
If it's false, reject it with specific reasons.
"""
        
        response = self.ai_provider.complete_with_reasoning(
            prompt,
            {"finding": finding, "evidence": raw_api_evidence}
        )
        
        decision = Decision(
            decision_type=DecisionType.FINDING_VALIDATION,
            action=response.content,
            reasoning=response.reasoning or "No detailed reasoning provided",
            confidence=response.confidence,
            alternatives=["Accept finding", "Reject finding", "Downgrade severity"],
            evidence={"finding": finding, "raw_evidence": raw_api_evidence},
            timestamp=self._get_timestamp()
        )
        
        self.decision_history.append(decision)
        self._log_decision(decision)
        
        return decision
    
    def decide_error_recovery(self, error: Dict[str, Any], 
                              retry_context: Dict[str, Any]) -> Decision:
        """
        Decide how to recover from errors with transparent explanations
        
        This is the "Transparent Failure" trait - explain what happened and what's needed
        """
        self.logger.info("Deciding error recovery strategy...", error=error)
        
        error_code = error.get("error_code", "Unknown")
        resource = error.get("resource", "unknown")
        
        prompt = f"""
You are a security agent that encountered an error. You must explain what happened and what to do.

Error Details:
- Code: {error_code}
- Resource: {resource}
- Message: {error.get('message', 'No message')}
- What we tried: {error.get('attempted_action', 'Unknown')}

Context:
{json.dumps(retry_context, indent=2)}

Provide:
1. Exact explanation of what went wrong (not generic)
2. What we already tried to fix it
3. What specific permissions/config is needed to proceed
4. Whether we should retry, skip, or abort

Be specific and actionable. No generic "check permissions" - say exactly what permission.
"""
        
        response = self.ai_provider.complete_with_reasoning(
            prompt,
            {"error": error, "context": retry_context}
        )
        
        decision = Decision(
            decision_type=DecisionType.ERROR_RECOVERY,
            action=response.content,
            reasoning=response.reasoning or "No detailed reasoning provided",
            confidence=response.confidence,
            alternatives=["Retry with backoff", "Skip this resource", "Abort scan", "Request manual intervention"],
            evidence={"error": error, "context": retry_context},
            timestamp=self._get_timestamp()
        )
        
        self.decision_history.append(decision)
        self._log_decision(decision)
        
        return decision
    
    def rank_priorities(self, findings: List[Dict[str, Any]], 
                       constraints: Dict[str, Any]) -> Decision:
        """
        Rank findings by priority based on context, not just severity
        
        Considers business impact, exploitability, and available resources
        """
        self.logger.info("Ranking findings by priority...", findings_count=len(findings))
        
        prompt = f"""
You are a security triage officer. Rank these findings by remediation priority.

Findings:
{json.dumps(findings[:20], indent=2)}  # Limit to prevent token overflow

Constraints:
{json.dumps(constraints, indent=2)}

Consider:
1. Business impact (what's most critical to THIS organization)
2. Ease of exploitation (what's easiest to attack)
3. Remediation effort (what's quick wins vs big projects)
4. Dependencies (what unlocks other fixes)

Rank the top 10 findings in priority order with reasoning.
"""
        
        response = self.ai_provider.complete_with_reasoning(
            prompt,
            {"findings": findings, "constraints": constraints}
        )
        
        decision = Decision(
            decision_type=DecisionType.PRIORITY_RANKING,
            action=response.content,
            reasoning=response.reasoning or "No detailed reasoning provided",
            confidence=response.confidence,
            alternatives=["By severity only", "By business impact", "By exploitability"],
            evidence={"findings": findings, "constraints": constraints},
            timestamp=self._get_timestamp()
        )
        
        self.decision_history.append(decision)
        self._log_decision(decision)
        
        return decision
    
    def _log_decision(self, decision: Decision) -> None:
        """Log decision for observability - the "thought process" requirement"""
        self.logger.info(
            f"DECISION: {decision.decision_type.value}",
            decision_type=decision.decision_type.value,
            action=decision.action[:200],  # Truncate for log
            reasoning=decision.reasoning[:200],
            confidence=decision.confidence,
            alternatives=decision.alternatives,
            timestamp=decision.timestamp
        )
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"
    
    def get_decision_history(self) -> List[Decision]:
        """Get full decision history for observability"""
        return self.decision_history
    
    def export_decision_trace(self) -> Dict[str, Any]:
        """Export full decision trace for audit"""
        return {
            "total_decisions": len(self.decision_history),
            "decisions": [
                {
                    "type": d.decision_type.value,
                    "action": d.action,
                    "reasoning": d.reasoning,
                    "confidence": d.confidence,
                    "timestamp": d.timestamp
                }
                for d in self.decision_history
            ]
        }
