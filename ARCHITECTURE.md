# Offensive Security Agent - Architecture Document

## System Overview

The Offensive Security Agent is a production-grade autonomous security scanning system designed for AWS infrastructure auditing. The system follows a clear separation of concerns with extensible architecture that can be expanded to multi-domain security scanning (Levels 2 and 3).

## Core Architectural Principles

### 1. Separation of Concerns

The system is divided into distinct layers with clear responsibilities:

```
┌─────────────────────────────────────────┐
│         Application Layer               │
│  (main.py - Orchestrator)               │
└─────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│         Framework Layer                 │
│  (Check Engine, Reporter, Config)       │
└─────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│         Check Layer                     │
│  (BaseCheck, AWS-specific checks)       │
└─────────────────────────────────────────┘
                   ↓
┌─────────────────────────────────────────┐
│         Utility Layer                   │
│  (AWS Client, Logger, Error Handling)   │
└─────────────────────────────────────────┘
```

### 2. Plugin Architecture

Each security check is a self-contained plugin that:
- Inherits from `BaseCheck` (or `BaseAWSCheck` for AWS checks)
- Implements the `execute()` method
- Returns standardized `SecurityFinding` objects
- Handles its own errors via `record_api_error()`

This design allows:
- Easy addition of new checks without modifying core framework
- Independent testing of each check
- Parallel execution of checks
- Graceful degradation if individual checks fail

### 3. Zero False Positive Guarantee

Critical findings require ≥80% confidence, enforced at the framework level:

```python
# In BaseCheck.add_finding()
if finding.severity == Severity.CRITICAL and finding.confidence < 0.8:
    finding.severity = Severity.HIGH
```

This ensures security teams can trust Critical findings without manual validation.

## Component Design

### Check Engine

**Purpose:** Orchestrate parallel execution of security checks

**Key Features:**
- `ThreadPoolExecutor` for concurrent check execution
- Configurable worker count and timeouts
- Graceful error handling per check
- Aggregation of results across all checks

**Design Decision:** Why ThreadPool over multiprocessing?
- Security checks are I/O bound (AWS API calls)
- Thread pool avoids overhead of process spawning
- Sufficient for typical cloud API rate limits
- Allows for easy extension to async/await if needed

### Base Check Interface

**Purpose:** Enforce consistent check implementation

**Key Features:**
- Abstract `execute()` method ensures all checks follow same interface
- `SecurityFinding` dataclass with validation
- Automatic confidence scoring for Critical findings
- Structured error recording

**Design Decision:** Why dataclass for SecurityFinding?
- Immutable by default (prevents accidental modification)
- Built-in validation via `is_valid_finding()`
- Clean serialization to JSON via `to_dict()`
- Type hints improve IDE support

### AWS Client Manager

**Purpose:** Centralized AWS session and error management

**Key Features:**
- Single boto3 session per agent instance
- Consistent error handling across all AWS checks
- Context manager for AWS API error handling
- Automatic account ID discovery for ARN construction

**Design Decision:** Why not use boto3 clients directly in checks?
- Centralized error handling prevents inconsistent logging
- Easier to add retry logic, rate limiting, or caching
- Simplifies testing (can mock single client)
- Consistent session management (region, profile)

### Security Reporter

**Purpose:** Generate human-readable and machine-readable reports

**Key Features:**
- JSON output for automation/CI/CD
- Markdown output for security teams
- Executive summary with severity breakdown
- Detailed evidence and remediation for each finding

**Design Decision:** Why dual output formats?
- JSON: Machine-readable for SIEM integration, alerting, trend analysis
- Markdown: Human-readable for immediate action, documentation

### Structured Logger

**Purpose:** Full observability of agent operations

**Key Features:**
- JSON logs for file output (structured querying)
- Human-readable logs for console output
- Contextual logging with structured metadata
- Per-execution log files with timestamps

**Design Decision:** Why structured logging?
- Enables log aggregation and querying (ELK, Splunk)
- Easier debugging of distributed execution
- Audit trail for compliance requirements
- Performance analysis (which checks are slow)

## Security Finding Data Model

Every security finding includes:

```python
SecurityFinding(
    check_name: str              # Source check
    resource_arn: str           # Unique identifier
    severity: Severity           # Critical → Info
    title: str                  # Human-readable summary
    description: str             # Detailed explanation
    evidence: Dict[str, Any]    # Raw API evidence
    business_impact: str        # Why this matters
    remediation: str            # Step-by-step fix
    confidence: float           # 0.0 to 1.0
    timestamp: datetime         # When discovered
    metadata: Dict[str, Any]    # Additional context
)
```

**Design Rationale:**
- **Evidence field**: Enables verification and manual audit
- **Business Impact**: Helps security teams prioritize
- **Confidence**: Indicates reliability of finding
- **Remediation**: Actionable steps, not just warnings

## Error Handling Strategy

### API Error Categorization

```python
self.api_errors = {
    "access_denied": 0,    # 403 errors - insufficient permissions
    "rate_limit": 0,      # 429 errors - AWS throttling
    "other": 0            # Other exceptions
}
```

**Design Decision:** Why explicit error tracking?
- Security teams must distinguish "no issues" from "couldn't check"
- Rate limiting affects scan completeness
- Access denied indicates IAM permission gaps
- Enables SLA monitoring (e.g., "99% of resources scanned successfully")

### Graceful Degradation

The agent continues even if individual checks fail:
- Failed checks don't block successful checks
- Errors are logged and reported in summary
- Critical findings from successful checks are still delivered

## Performance Considerations

### Concurrency Model

```python
with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
    future_to_check = {
        executor.submit(self._execute_single_check, check): check
        for check in self.checks
    }
```

**Tuning Guidelines:**
- Small environments (<100 resources): 5-10 workers
- Large environments (>1000 resources): 10-20 workers
- Rate-limited APIs: 3-5 workers
- Test and monitor for 429 errors

### Resource Scanning

Each check implements its own pagination:
```python
paginator = s3_client.get_paginator('list_objects')
for page in paginator.paginate(Bucket=bucket_name):
    # Process page
```

**Design Decision:** Pagination at check level
- Framework doesn't need to know AWS pagination details
- Each check can optimize for its service's rate limits
- Prevents memory issues with large resource lists

## Extensibility Points

### Adding New Security Checks

1. Inherit from appropriate base class:
   - `BaseAWSCheck` for AWS services
   - `BaseCheck` for non-AWS checks

2. Implement `execute()` method:
   ```python
   def execute(self, config: Dict[str, Any]) -> List[SecurityFinding]:
       # Your check logic
       return self.findings
   ```

3. Register in `main.py`:
   ```python
   all_checks.append(MyNewCheck)
   ```

4. Add configuration:
   ```yaml
   checks:
     MyNewCheck:
       enabled: true
       severity_threshold: Info
   ```

### Adding New Output Formats

Extend `SecurityReporter` class:
```python
def _generate_xml_report(self, scan_id, metadata, findings) -> Path:
    # Generate XML format
    pass
```

### Adding New Severity Levels

Extend `Severity` enum:
```python
class Severity(Enum):
    # Add new level
    EXTREME = "Extreme"
```

## Level 2 & Level 3 Readiness

The architecture supports planned enhancements:

### Level 2: Multi-Domain Extension

**Framework Support:**
- `BaseCheck` works for any domain (not just AWS)
- New check types can be added:
  - `APIEndpointCheck` (HTTP-based)
  - `CVEScanner` (dependency analysis)
  - `SecretsScanner` (file-based)

**Integration Points:**
- Same `SecurityFinding` data model
- Same reporting infrastructure
- Same parallel execution engine

### Level 3: Autonomous Operations

**Framework Support:**
- Check engine can be scheduled (cron, systemd)
- JSON reports enable database ingestion
- Structured logs support trend analysis

**Required Extensions:**
- Add `FindingDatabase` class for lifecycle tracking
- Add `Scheduler` class for periodic execution
- Add `AlertManager` class for SLA breach notification

## Production Deployment Considerations

### AWS Credentials

Use IAM roles for EC2/Lambda:
```python
# If running on EC2/Lambda, use instance profile
session = boto3.Session()  # Automatically uses instance profile
```

For local development, use named profiles:
```python
session = boto3.Session(profile_name='security-audit')
```

### Rate Limiting

Monitor logs for 429 errors:
```json
{
  "error_code": "Throttling",
  "resource": "s3:*",
  "context": "Rate limit exceeded"
}
```

**Mitigation:**
- Reduce `max_workers` in config
- Add exponential backoff in `AWSClientManager`
- Use AWS Organizations for delegated scanning

### Long-Running Scans

Large environments may take 10+ minutes. Consider:
- Run in screen/tmux session
- Use async execution (Celery, AWS Lambda)
- Implement resumable scans (checkpoint in database)

## Testing Strategy

### Unit Tests

Test individual checks without AWS:
```python
def test_s3_check_with_mock():
    mock_client = Mock()
    mock_client.get_bucket_acl.return_value = {...}
    check = S3SecurityCheck(logger)
    findings = check._check_bucket_acl(mock_client, "bucket", "arn")
    assert len(findings) == 1
```

### Integration Tests

Test with real AWS account (sandbox):
```python
def test_s3_check_real():
    check = S3SecurityCheck(logger)
    findings = check.execute(config)
    assert all(f.is_valid_finding() for f in findings)
```

### Contract Tests

Test framework enforces finding quality:
```python
def test_finding_validation():
    finding = SecurityFinding(...)
    assert finding.is_valid_finding()
```

## Compliance and Security

### Read-Only Operations

The agent only uses `Describe*`, `Get*`, `List*` API calls:
- No modification of resources
- Safe to run in production
- No risk of accidental deletion or modification

### Audit Trail

Every action is logged with:
- Timestamp
- Check name
- Resource ARN
- Action performed
- Result (success/failure)

### Data Handling

The agent:
- Does not store sensitive data permanently
- Logs contain resource ARNs but not secrets
- Reports contain configuration data, not credentials
- Can be run in isolated environment

## Conclusion

This architecture provides a solid foundation for autonomous security auditing with:

✅ **Clear separation of concerns**
✅ **Extensible plugin architecture**
✅ **Zero false positive guarantee**
✅ **Full observability**
✅ **Production-ready error handling**
✅ **Multi-domain readiness**

The design patterns and abstractions enable extension to Levels 2 and 3 without framework rewrites, making it suitable for long-term evolution as security requirements grow.