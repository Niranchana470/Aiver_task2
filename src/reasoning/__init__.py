"""
Reasoning Layer - Separates decision-making from execution

This layer implements the "Agentic" traits required for the Aivar challenge:
- Decision Making: Context-aware action selection
- Aggressive Validation: Self-verification of findings
- Transparent Failure: Detailed error explanations
- Guard Rails: Scope enforcement
- Observability: Decision trace logging

Key Components:
- AIProvider: Interface for AI reasoning (OpenAI, Anthropic, Mock)
- DecisionEngine: Makes decisions based on context
- ValidationEngine: Aggressively verifies findings
- GuardRails: Enforces scope boundaries
- FailureHandler: Explains errors with next steps
- DecisionTraceLogger: Logs thought process
"""

from .ai_provider import (
    AIProvider,
    AIResponse,
    OpenAIProvider,
    AnthropicProvider,
    MockProvider,
    create_ai_provider
)

from .decision_engine import (
    DecisionType,
    Decision,
    DecisionEngine
)

from .validation_engine import (
    ValidationStatus,
    ValidationResult,
    ValidationEngine
)

from .guard_rails import (
    ScopeViolationType,
    ScopeViolation,
    ScopeConfig,
    GuardRails,
    create_scope_config_from_dict
)

from .failure_handler import (
    ErrorCategory,
    ErrorExplanation,
    FailureHandler
)

from .decision_trace import (
    TraceLevel,
    TraceEventType,
    TraceEvent,
    DecisionTraceLogger
)

__all__ = [
    # AI Provider
    "AIProvider",
    "AIResponse",
    "OpenAIProvider",
    "AnthropicProvider",
    "MockProvider",
    "create_ai_provider",
    
    # Decision Engine
    "DecisionType",
    "Decision",
    "DecisionEngine",
    
    # Validation Engine
    "ValidationStatus",
    "ValidationResult",
    "ValidationEngine",
    
    # Guard Rails
    "ScopeViolationType",
    "ScopeViolation",
    "ScopeConfig",
    "GuardRails",
    "create_scope_config_from_dict",
    
    # Failure Handler
    "ErrorCategory",
    "ErrorExplanation",
    "FailureHandler",
    
    # Decision Trace
    "TraceLevel",
    "TraceEventType",
    "TraceEvent",
    "DecisionTraceLogger"
]
