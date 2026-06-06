# Agentic Security Agent - Aivar Challenge Submission

## Executive Summary

This refactored Offensive Security Agent demonstrates all five required "Agentic" traits for the Aivar AI/ML Engineering Hiring Challenge:

1. **Decision Making**: Context-aware action selection based on infrastructure state
2. **Aggressive Validation**: Self-verification of findings against raw API evidence
3. **Transparent Failure**: Detailed error explanations with specific next steps
4. **Guard Rails**: Explicit scope enforcement to prevent reckless actions
5. **Observability**: Complete decision trace showing the agent's thought process

## Architecture Overview

### Before: Script-Like Execution
```
Input → Run All Checks → Generate Reports → Output
```
**Problem**: Hardcoded script, no intelligence, no validation

### After: Agentic Architecture
```
Input → Discover Context → Make Decisions → Execute with Guard Rails 
→ Aggressively Validate → Handle Failures Transparently → Log Decisions → Output
```
**Solution**: Intelligent, context-aware, self-validating agent

## Key Architectural Changes

### 1. Separation of Concerns

**Reasoning/Planning Layer** (`src/reasoning/`):
- `DecisionEngine`: Makes intelligent decisions based on context
- `ValidationEngine`: Aggressively verifies findings
- `GuardRails`: Enforces scope boundaries
- `FailureHandler`: Explains errors with next steps
- `DecisionTraceLogger`: Logs thought process

**Execution Layer** (`src/core/`, `src/checks/`):
- `AgenticOrchestrator`: Coordinates execution
- `BaseCheck`: Existing security checks (unchanged)
- `AWSClientManager`: AWS API calls (unchanged)

### 2. AI Provider Integration

The agent now supports multiple AI providers for reasoning:
- **OpenAI GPT-4**: Production choice for complex reasoning
- **Anthropic Claude**: Alternative with strong reasoning
- **Mock Provider**: Testing without API costs

### 3. Decision-Making Process

Instead of running all checks blindly, the agent:

1. **Discovers Infrastructure Context**
   - What AWS account?
   - What regions?
   - What resources exist?

2. **Makes Intelligent Decisions**
   - Which checks to run? (Skip checks for non-existent resources)
   - How deep to scan? (Quick vs comprehensive)
   - Priority order? (High-risk resources first)

3. **Validates Against Guard Rails**
   - Is this account allowed?
   - Is this region allowed?
   - Is this action within scope?

4. **Aggressively Validates Findings**
   - Cross-checks every claim against raw API evidence
   - Rejects false positives
   - Downgrades findings with insufficient evidence

5. **Handles Failures Transparently**
   - Explains exactly what went wrong
   - Shows what was already tried
   - Lists specific next steps

## Five Agentic Traits Demonstrated

### 1. Decision Making

**File**: `src/reasoning/decision_engine.py`

**What Changed**:
- Before: Hardcoded script runs all checks in parallel
- After: AI-powered decision engine selects checks based on discovered context

**Example**:
```python
# The agent decides what to scan based on infrastructure state
decision = decision_engine.decide_scan_scope(infrastructure_context)
# Output: "Skip RDS checks (0 instances), prioritize S3 (100 buckets)"
```

**Evidence**: 
- `DecisionEngine.decide_scan_scope()` - Context-aware planning
- `DecisionEngine.decide_check_selection()` - Intelligent check selection

### 2. Aggressive Validation

**File**: `src/reasoning/validation_engine.py`

**What Changed**:
- Before: Findings accepted at face value
- After: Every finding cross-checked against raw API evidence

**Example**:
```python
# Claim: "S3 bucket is publicly accessible"
# Evidence check: Does BucketPolicy actually allow public read?
# If not: REJECT as false positive

validation = validation_engine.validate_finding(finding, raw_api_evidence)
if validation.status == ValidationStatus.REJECTED:
    logger.info("Rejected false positive: " + finding.title)
```

**Evidence**:
- `ValidationEngine.validate_finding()` - Cross-checks claims vs evidence
- `_cross_check_claim()` - Field-by-field verification
- `_ai_validate_claim()` - AI-powered logic validation

### 3. Transparent Failure

**File**: `src/reasoning/failure_handler.py`

**What Changed**:
- Before: Generic "Access Denied" errors
- After: Detailed explanations with specific next steps

**Example**:
```python
# Instead of: "Error: Access Denied"
# Now: "You need s3:GetBucketAcl permission. Add it to IAM policy.
#       What we tried: Verified credentials, checked bucket exists.
#       Next steps: 1) Check IAM policy for s3:GetBucketAcl,
#                   2) Verify no explicit deny,
#                   3) Test with IAM simulator"

explanation = failure_handler.explain_error(error, attempted_action, recovery_attempts)
print(explanation.what_happened)
print(explanation.why_it_happened)
print(explanation.what_is_needed)
print(explanation.next_steps)
```

**Evidence**:
- `FailureHandler.explain_error()` - Generates detailed explanations
- Error templates for each error category (AccessDenied, RateLimit, etc.)
- Specific next steps for each error type

### 4. Guard Rails

**File**: `src/reasoning/guard_rails.py`

**What Changed**:
- Before: No scope enforcement
- After: Explicit boundaries prevent reckless actions

**Example**:
```python
# Before: Agent could scan any AWS account
# After: Agent only scans allowed accounts

violation = guard_rails.check_action_allowed(
    action="execute_S3SecurityCheck",
    resource_arn="arn:aws:s3:::bucket"
)
if violation:
    logger.error(f"BLOCKED: {violation.reason}")
    # "Account 999999999999 not in allowed list [123456789012]"
    return  # Action blocked
```

**Evidence**:
- `GuardRails.check_action_allowed()` - Pre-execution validation
- Account/region/resource type restrictions
- Read-only enforcement (blocks write/destructive operations)
- Rate limiting

### 5. Observability

**File**: `src/reasoning/decision_trace.py`

**What Changed**:
- Before: Only final output logged
- After: Every decision, action, and validation logged

**Example**:
```python
# Decision trace shows the agent's "thought process"
# logs/decision_trace.md:
#
# ## DECISION: Scan Scope Decision
# **Time:** 2024-01-06T14:30:22Z
# **Component:** DecisionEngine
# **Action:** Skip RDS checks (0 instances), prioritize S3 (100 buckets)
# **Reasoning:** Infrastructure has 100 S3 buckets, 0 RDS instances.
#              Running RDS checks would waste time.
# **Confidence:** 85%
# **Alternatives:** Run all checks, Skip checks with no resources
#
# ## VALIDATION: S3 Bucket Public Access
# **Status:** Verified
# **Confidence:** 92%
# **Discrepancies:** 0 found
```

**Evidence**:
- `DecisionTraceLogger` - Logs every decision/action/validation
- `DecisionTraceLogger.export_trace()` - Exports JSON + Markdown traces
- `AgenticOrchestrator._export_decision_trace()` - Saves traces to files

## Installation & Deployment

### Prerequisites

```bash
# Python 3.9+
python --version

# AWS credentials configured
aws configure
```

### Setup

```bash
# 1. Install dependencies
pip install -r requirements-agentic.txt

# 2. Configure AI provider (optional - uses mock by default)
export OPENAI_API_KEY="sk-..."  # For OpenAI GPT-4
# OR
export ANTHROPIC_API_KEY="sk-ant-..."  # For Anthropic Claude

# 3. Configure scope (optional - edit config/agentic_config.yaml)
# Edit guard_rails section to set allowed accounts/regions

# 4. Run scan
python main_agentic.py
```

### Configuration

**File**: `config/agentic_config.yaml`

```yaml
# AI Provider (choose one)
ai_provider:
  provider: "mock"  # or "openai" or "anthropic"
  model: "gpt-4"
  api_key: null  # Set via environment variable

# Guard Rails
guard_rails:
  allowed_account_ids: ["123456789012"]  # Only scan these accounts
  forbidden_account_ids: ["999999999999"]  # Never scan these
  read_only: true  # Only allow read operations
  dry_run: false  # Set true for testing
```

### Running the Agent

```bash
# Basic scan
python main_agentic.py

# With custom config
python main_agentic.py -c /path/to/config.yaml

# Debug mode (verbose decision trace)
python main_agentic.py --debug
```

### Output

The agent generates:

1. **JSON Report**: `reports/scan_*_report.json`
   - Machine-readable findings
   - Validation results
   - Guard rails violations

2. **Markdown Report**: `reports/scan_*_report.md`
   - Human-readable findings
   - Remediation steps

3. **Decision Trace**: `logs/decision_trace.json` and `logs/decision_trace.md`
   - Complete decision history
   - Validation results
   - Error explanations
   - Agent's "thought process"

## Verification of Requirements

### Decision Making ✅

**Evidence**:
- `src/reasoning/decision_engine.py` - Makes context-aware decisions
- `AgenticOrchestrator.execute_all()` - Uses decisions instead of hardcoded script

**Test**:
```bash
# Run scan with no RDS instances
# Agent should decide to skip RDS checks
# Check decision trace: "Skipping RDS checks (0 instances)"
grep "Skipping RDS" logs/decision_trace.md
```

### Aggressive Validation ✅

**Evidence**:
- `src/reasoning/validation_engine.py` - Validates every finding
- `ValidationEngine.validate_finding()` - Cross-checks against evidence

**Test**:
```bash
# Create a false positive scenario
# Agent should reject or downgrade it
# Check validation summary: "rejected": > 0
grep '"rejected":' reports/*_report.json
```

### Transparent Failure ✅

**Evidence**:
- `src/reasoning/failure_handler.py` - Detailed error explanations
- `FailureHandler.explain_error()` - Shows what/why/next steps

**Test**:
```bash
# Run with insufficient permissions
# Agent should explain exactly what permission is needed
# Check error messages for specific permission name
grep "what_is_needed" logs/decision_trace.md
```

### Guard Rails ✅

**Evidence**:
- `src/reasoning/guard_rails.py` - Scope enforcement
- `GuardRails.check_action_allowed()` - Pre-execution validation

**Test**:
```bash
# Configure forbidden account in config
# Agent should block scan of that account
# Check guard rails summary: "blocked_violations": > 0
grep '"blocked_violations":' reports/*_report.json
```

### Observability ✅

**Evidence**:
- `src/reasoning/decision_trace.py` - Complete decision logging
- `DecisionTraceLogger.export_trace()` - Exports thought process

**Test**:
```bash
# Run scan
# Check decision trace file exists
ls -lh logs/decision_trace.md
# Open trace and see decisions, validations, errors
cat logs/decision_trace.md
```

## Code Quality & Maintainability

### Separation of Concerns ✅

**Reasoning Layer** (`src/reasoning/`):
- Independent of execution layer
- Can be tested without AWS
- Clear interfaces

**Execution Layer** (`src/core/`, `src/checks/`):
- Unchanged from original (backward compatible)
- Can be used without reasoning layer

### Confidence Scores ✅

Every finding includes:
- Confidence score (0-100%)
- Evidence that justifies the score
- Validation result

### Deployable by Another Engineer ✅

**Documentation**:
- `AGENTIC_ARCHITECTURE.md` (this file)
- `QUICK_START.md` (existing)
- `ARCHITECTURE.md` (existing)

**Configuration**:
- Single config file: `config/agentic_config.yaml`
- Environment variables for API keys

**Error Handling**:
- Graceful degradation (AI failure → fallback to rule-based)
- Clear error messages
- Detailed logs

## Production Readiness

### Backward Compatibility ✅

The original `main.py` still works:
```bash
python main.py  # Uses old CheckEngine (no AI)
```

The new `main_agentic.py` adds agentic features:
```bash
python main_agentic.py  # Uses AgenticOrchestrator (with AI)
```

### Graceful Degradation ✅

- AI provider failure → fallback to rule-based decisions
- Validation failure → log warning, continue
- Guard rails failure → abort with clear explanation

### Testing ✅

```bash
# Test with mock provider (no API keys needed)
python main_agentic.py  # Uses mock provider by default

# Test with real AI provider
export OPENAI_API_KEY="sk-..."
python main_agentic.py  # Uses GPT-4 for decisions
```

## Comparison: Before vs After

| Aspect | Before | After |
|--------|--------|-------|
| Decision Making | Hardcoded script | AI-powered context-aware decisions |
| Validation | Confidence score only | Aggressive cross-check vs raw evidence |
| Error Handling | Generic error codes | Detailed explanations with next steps |
| Scope Enforcement | None | Explicit guard rails |
| Observability | Final output only | Complete decision trace |
| Intelligence | Rule-based | Hybrid (rules + AI reasoning) |
| False Positives | Possible | Aggressively filtered out |
| Deployment | Simple | Still simple (default uses mock) |

## Conclusion

This refactored Offensive Security Agent demonstrates all five required agentic traits while maintaining the production-grade quality of the original codebase. The architecture is modular, testable, and deployable by another engineer with minimal changes.

### Key Achievements

1. **Decision Making**: ✅ Agent picks actions based on discovered context
2. **Aggressive Validation**: ✅ Every finding verified against raw API evidence
3. **Transparent Failure**: ✅ Detailed error explanations with specific next steps
4. **Guard Rails**: ✅ Explicit scope enforcement prevents reckless actions
5. **Observability**: ✅ Complete decision trace shows thought process

### Production Standards Met

1. ✅ Separation of concerns (reasoning vs execution)
2. ✅ Confidence scores for every finding
3. ✅ Maintainable and deployable code
4. ✅ Backward compatible
5. ✅ Graceful degradation
6. ✅ Comprehensive documentation

### Next Steps for Deployment

1. Set `ai_provider.api_key` in config or environment variable
2. Configure `guard_rails.allowed_account_ids` for your environment
3. Run `python main_agentic.py` to execute agentic scan
4. Review `logs/decision_trace.md` to see agent's thought process
5. Check `reports/` for validated findings

**The agent is ready for production deployment.** 🚀
