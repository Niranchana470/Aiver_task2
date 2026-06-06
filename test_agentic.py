#!/usr/bin/env python3
"""
Agentic Security Agent - Test Script

Demonstrates all five agentic traits:
1. Decision Making
2. Aggressive Validation
3. Transparent Failure
4. Guard Rails
5. Observability
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.logger import get_logger
from src.core.agentic_orchestrator import AgenticOrchestrator
from src.reasoning import DecisionEngine, ValidationEngine, GuardRails, FailureHandler, DecisionTraceLogger
from src.reasoning import ScopeConfig, create_scope_config_from_dict, TraceLevel


def test_decision_making():
    """Test 1: Decision Making"""
    print("\n" + "="*70)
    print("TEST 1: Decision Making")
    print("="*70)
    
    logger = get_logger("TestDecision", {"level": "INFO"})
    
    # Create decision engine with mock provider
    config = {
        "ai_provider": {
            "provider": "mock",
            "model": "mock-model"
        }
    }
    
    decision_engine = DecisionEngine(config, logger)
    
    # Test scan scope decision
    infrastructure_context = {
        "aws_account_id": "123456789012",
        "regions": ["us-east-1", "us-west-2"],
        "estimated_counts": {
            "s3_buckets": 100,
            "rds_instances": 0,
            "ec2_instances": 10
        }
    }
    
    decision = decision_engine.decide_scan_scope(infrastructure_context)
    
    print(f"✓ Decision Made: {decision.action[:100]}...")
    print(f"✓ Reasoning: {decision.reasoning[:100]}...")
    print(f"✓ Confidence: {decision.confidence:.2%}")
    print(f"✓ Alternatives: {decision.alternatives}")
    
    assert decision.confidence > 0, "Decision should have confidence > 0"
    assert len(decision.alternatives) > 0, "Decision should have alternatives"
    
    print("✅ TEST 1 PASSED: Decision Making works")


def test_aggressive_validation():
    """Test 2: Aggressive Validation"""
    print("\n" + "="*70)
    print("TEST 2: Aggressive Validation")
    print("="*70)
    
    logger = get_logger("TestValidation", {"level": "INFO"})
    
    # Create validation engine with mock provider
    config = {
        "ai_provider": {
            "provider": "mock",
            "model": "mock-model"
        }
    }
    
    decision_engine = DecisionEngine(config, logger)
    validation_engine = ValidationEngine(decision_engine.ai_provider, logger)
    
    # Test with a finding that should be validated
    from src.core.base_check import SecurityFinding, Severity
    from datetime import datetime, timezone
    
    finding = SecurityFinding(
        check_name="S3SecurityCheck",
        resource_arn="arn:aws:s3:::test-bucket",
        severity=Severity.CRITICAL,
        title="S3 Bucket Publicly Accessible",
        description="Bucket allows public read access",
        evidence={
            "Bucket": "test-bucket",
            "PublicAccess": True
        },
        business_impact="Data exposure risk",
        remediation="Enable bucket policy restrictions",
        confidence=0.9,
        timestamp=datetime.now(timezone.utc)
    )
    
    # Validate the finding
    result = validation_engine.validate_finding(finding, finding.evidence)
    
    print(f"✓ Validation Status: {result.status.value}")
    print(f"✓ Confidence: {result.confidence:.2%}")
    print(f"✓ Discrepancies: {len(result.discrepancies)}")
    
    assert result.status.value in ["verified", "rejected", "downgraded", "needs_info"]
    
    print("✅ TEST 2 PASSED: Aggressive Validation works")


def test_transparent_failure():
    """Test 3: Transparent Failure"""
    print("\n" + "="*70)
    print("TEST 3: Transparent Failure")
    print("="*70)
    
    logger = get_logger("TestFailure", {"level": "INFO"})
    
    failure_handler = FailureHandler(logger)
    
    # Test error explanation
    error = {
        "error_code": "AccessDenied",
        "error_message": "User: arn:aws:iam::123456789012:user/test is not authorized to perform: s3:GetBucketAcl on resource: arn:aws:s3:::test-bucket",
        "resource": "arn:aws:s3:::test-bucket",
        "attempted_action": "Check S3 bucket ACL"
    }
    
    explanation = failure_handler.explain_error(
        error,
        "Check S3 bucket ACL",
        ["Verified credentials", "Checked bucket exists"]
    )
    
    print(f"✓ Error Category: {explanation.error_category.value}")
    print(f"✓ What Happened: {explanation.what_happened[:80]}...")
    print(f"✓ Why It Happened: {explanation.why_it_happened[:80]}...")
    print(f"✓ What Is Needed: {explanation.what_is_needed[:80]}...")
    print(f"✓ Next Steps: {explanation.next_steps[:2]}")
    print(f"✓ Can Retry: {explanation.can_retry}")
    
    assert explanation.what_happened, "Should explain what happened"
    assert explanation.next_steps, "Should provide next steps"
    
    print("✅ TEST 3 PASSED: Transparent Failure works")


def test_guard_rails():
    """Test 4: Guard Rails"""
    print("\n" + "="*70)
    print("TEST 4: Guard Rails")
    print("="*70)
    
    logger = get_logger("TestGuardRails", {"level": "INFO"})
    
    # Create guard rails with restrictions
    scope_config = create_scope_config_from_dict({
        "allowed_account_ids": ["123456789012"],
        "forbidden_account_ids": ["999999999999"],
        "read_only": True,
        "allow_destructive": False
    })
    
    guard_rails = GuardRails(scope_config, logger)
    
    # Test 1: Action within allowed account
    violation1 = guard_rails.check_action_allowed(
        action="execute_S3SecurityCheck",
        resource_arn="arn:aws:s3:us-east-1:123456789012:bucket"
    )
    print(f"✓ Allowed account: No violation = {violation1 is None}")
    assert violation1 is None, "Should allow action in allowed account"
    
    # Test 2: Action in forbidden account
    violation2 = guard_rails.check_action_allowed(
        action="execute_S3SecurityCheck",
        resource_arn="arn:aws:s3:us-east-1:999999999999:bucket"
    )
    print(f"✓ Forbidden account: Violation detected = {violation2 is not None}")
    assert violation2 is not None, "Should block action in forbidden account"
    print(f"  - Violation Type: {violation2.violation_type.value}")
    print(f"  - Reason: {violation2.reason}")
    
    # Test 3: Destructive operation blocked
    violation3 = guard_rails.check_action_allowed(
        action="delete_bucket",
        resource_arn="arn:aws:s3:us-east-1:123456789012:bucket"
    )
    print(f"✓ Destructive operation: Violation detected = {violation3 is not None}")
    assert violation3 is not None, "Should block destructive operations"
    
    # Test 4: Write operation in read-only mode
    violation4 = guard_rails.check_action_allowed(
        action="put_bucket_policy",
        resource_arn="arn:aws:s3:us-east-1:123456789012:bucket"
    )
    print(f"✓ Write operation (read-only): Violation detected = {violation4 is not None}")
    assert violation4 is not None, "Should block write operations in read-only mode"
    
    print("✅ TEST 4 PASSED: Guard Rails work")


def test_observability():
    """Test 5: Observability"""
    print("\n" + "="*70)
    print("TEST 5: Observability")
    print("="*70)
    
    logger = get_logger("TestObservability", {"level": "INFO"})
    
    # Create decision trace logger
    trace_logger = DecisionTraceLogger(logger, TraceLevel.STANDARD)
    
    # Log various events
    decision_id = trace_logger.log_decision(
        component="TestComponent",
        title="Test Decision",
        action="Run S3 check",
        reasoning="S3 buckets detected in infrastructure",
        confidence=0.85,
        alternatives=["Skip S3", "Run all checks"]
    )
    print(f"✓ Decision logged: {decision_id}")
    
    action_id = trace_logger.log_action(
        component="TestComponent",
        title="Test Action",
        action="execute_check",
        target_resource="S3 bucket scan",
        parameters={"check": "S3SecurityCheck"}
    )
    print(f"✓ Action logged: {action_id}")
    
    validation_id = trace_logger.log_validation(
        component="TestComponent",
        title="Test Validation",
        status="verified",
        confidence=0.90,
        discrepancies=[]
    )
    print(f"✓ Validation logged: {validation_id}")
    
    error_id = trace_logger.log_error(
        component="TestComponent",
        title="Test Error",
        error_type="access_denied",
        error_message="Permission denied",
        what_happened="Access denied to S3 bucket",
        what_is_needed="s3:GetBucketAcl permission",
        next_steps=["Add IAM permission"],
        can_retry=False
    )
    print(f"✓ Error logged: {error_id}")
    
    # Export trace
    trace_json = trace_logger.export_trace("json")
    trace_md = trace_logger.export_trace("markdown")
    
    print(f"✓ JSON trace exported: {len(trace_json)} characters")
    print(f"✓ Markdown trace exported: {len(trace_md)} characters")
    
    # Check summary
    summary = trace_logger.get_summary()
    print(f"✓ Total events: {summary['total_events']}")
    print(f"✓ Events by type: {summary['events_by_type']}")
    print(f"✓ Average decision confidence: {summary['average_decision_confidence']:.2%}")
    
    assert summary['total_events'] == 4, "Should have 4 events"
    assert 'decision' in summary['events_by_type'], "Should have decision events"
    
    print("✅ TEST 5 PASSED: Observability works")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("AGENTIC SECURITY AGENT - TEST SUITE")
    print("="*70)
    print("\nTesting all five agentic traits...\n")
    
    try:
        test_decision_making()
        test_aggressive_validation()
        test_transparent_failure()
        test_guard_rails()
        test_observability()
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED")
        print("="*70)
        print("\nThe agentic architecture is working correctly!")
        print("All five required traits are functional:")
        print("  1. ✅ Decision Making")
        print("  2. ✅ Aggressive Validation")
        print("  3. ✅ Transparent Failure")
        print("  4. ✅ Guard Rails")
        print("  5. ✅ Observability")
        print("\nRun 'python main_agentic.py' to execute a full scan.")
        
        return 0
    
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
