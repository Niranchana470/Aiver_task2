"""
Decision Trace Logger - Observability of agent's thought process
The "Observability" trait - traceable decisions and reasoning
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import json
import uuid


class TraceLevel(Enum):
    """Levels of trace detail"""
    MINIMAL = "minimal"  # Only final decisions
    STANDARD = "standard"  # Decisions + key context
    VERBOSE = "verbose"  # Full thought process with all context


class TraceEventType(Enum):
    """Types of events in the decision trace"""
    DECISION = "decision"
    ACTION = "action"
    VALIDATION = "validation"
    ERROR = "error"
    INFO = "info"


@dataclass
class TraceEvent:
    """A single event in the decision trace"""
    event_id: str
    timestamp: str
    event_type: TraceEventType
    component: str  # Which component generated this event
    title: str  # Short title
    description: str  # Detailed description
    decision_data: Optional[Dict[str, Any]]  # For decisions: action, reasoning, confidence
    action_data: Optional[Dict[str, Any]]  # For actions: what was executed
    validation_data: Optional[Dict[str, Any]]  # For validations: status, discrepancies
    error_data: Optional[Dict[str, Any]]  # For errors: explanation
    context: Dict[str, Any]  # Additional context
    parent_event_id: Optional[str] = None  # For event chaining
    confidence: Optional[float] = None  # Confidence level (0-1)


class DecisionTraceLogger:
    """
    Decision trace logger - the "Observability" trait
    
    Logs every decision, action, and confidence level so the agent's
    "thought process" is visible, not just the final output
    """
    
    def __init__(self, logger, trace_level: TraceLevel = TraceLevel.STANDARD):
        self.logger = logger
        self.trace_level = trace_level
        self.events: List[TraceEvent] = []
        self.session_id = str(uuid.uuid4())
        self.start_time = datetime.utcnow()
        
        # Event chaining stack
        self.event_stack: List[str] = []
        
        self.logger.info(
            "Decision Trace Logger initialized",
            session_id=self.session_id,
            trace_level=trace_level.value
        )
    
    def log_decision(self, component: str, title: str, action: str,
                    reasoning: str, confidence: float,
                    alternatives: Optional[List[str]] = None,
                    evidence: Optional[Dict[str, Any]] = None) -> str:
        """Log a decision made by the agent"""
        if self.trace_level == TraceLevel.MINIMAL:
            return  # Skip in minimal mode
        
        event_id = str(uuid.uuid4())
        
        event = TraceEvent(
            event_id=event_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=TraceEventType.DECISION,
            component=component,
            title=title,
            description=f"Decision: {action}",
            decision_data={
                "action": action,
                "reasoning": reasoning,
                "confidence": confidence,
                "alternatives": alternatives or []
            },
            action_data=None,
            validation_data=None,
            error_data=None,
            context={"evidence": evidence} or {},
            parent_event_id=self.event_stack[-1] if self.event_stack else None,
            confidence=confidence
        )
        
        self.events.append(event)
        self._log_event(event)
        
        return event_id
    
    def log_action(self, component: str, title: str, action: str,
                  target_resource: str, parameters: Optional[Dict[str, Any]] = None,
                  expected_result: Optional[str] = None) -> str:
        """Log an action taken by the agent"""
        event_id = str(uuid.uuid4())
        
        event = TraceEvent(
            event_id=event_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=TraceEventType.ACTION,
            component=component,
            title=title,
            description=f"Action: {action} on {target_resource}",
            decision_data=None,
            action_data={
                "action": action,
                "target_resource": target_resource,
                "parameters": parameters or {},
                "expected_result": expected_result
            },
            validation_data=None,
            error_data=None,
            context={},
            parent_event_id=self.event_stack[-1] if self.event_stack else None,
            confidence=None
        )
        
        self.events.append(event)
        self._log_event(event)
        
        return event_id
    
    def log_validation(self, component: str, title: str,
                     status: str, confidence: float,
                     discrepancies: Optional[List[str]] = None,
                     evidence_match: Optional[Dict[str, Any]] = None) -> str:
        """Log a validation check"""
        if self.trace_level == TraceLevel.MINIMAL:
            return  # Skip in minimal mode
        
        event_id = str(uuid.uuid4())
        
        event = TraceEvent(
            event_id=event_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=TraceEventType.VALIDATION,
            component=component,
            title=title,
            description=f"Validation: {status}",
            decision_data=None,
            action_data=None,
            validation_data={
                "status": status,
                "confidence": confidence,
                "discrepancies": discrepancies or [],
                "evidence_match": evidence_match or {}
            },
            error_data=None,
            context={},
            parent_event_id=self.event_stack[-1] if self.event_stack else None,
            confidence=confidence
        )
        
        self.events.append(event)
        self._log_event(event)
        
        return event_id
    
    def log_error(self, component: str, title: str,
                error_type: str, error_message: str,
                what_happened: str, what_is_needed: str,
                next_steps: List[str], can_retry: bool) -> str:
        """Log an error with detailed explanation"""
        event_id = str(uuid.uuid4())
        
        event = TraceEvent(
            event_id=event_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=TraceEventType.ERROR,
            component=component,
            title=title,
            description=f"Error: {error_type}",
            decision_data=None,
            action_data=None,
            validation_data=None,
            error_data={
                "error_type": error_type,
                "error_message": error_message,
                "what_happened": what_happened,
                "what_is_needed": what_is_needed,
                "next_steps": next_steps,
                "can_retry": can_retry
            },
            context={},
            parent_event_id=self.event_stack[-1] if self.event_stack else None,
            confidence=None
        )
        
        self.events.append(event)
        self._log_event(event)
        
        return event_id
    
    def log_info(self, component: str, title: str, 
                message: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Log informational event"""
        if self.trace_level != TraceLevel.VERBOSE:
            return  # Only log in verbose mode
        
        event_id = str(uuid.uuid4())
        
        event = TraceEvent(
            event_id=event_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=TraceEventType.INFO,
            component=component,
            title=title,
            description=message,
            decision_data=None,
            action_data=None,
            validation_data=None,
            error_data=None,
            context=context or {},
            parent_event_id=self.event_stack[-1] if self.event_stack else None,
            confidence=None
        )
        
        self.events.append(event)
        self._log_event(event)
        
        return event_id
    
    def push_context(self, event_id: str) -> None:
        """Push an event onto the context stack for chaining"""
        self.event_stack.append(event_id)
    
    def pop_context(self) -> None:
        """Pop an event from the context stack"""
        if self.event_stack:
            self.event_stack.pop()
    
    def _log_event(self, event: TraceEvent) -> None:
        """Log event to the main logger"""
        log_data = {
            "session_id": self.session_id,
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type.value,
            "component": event.component,
            "title": event.title,
            "description": event.description
        }
        
        # Add type-specific data
        if event.decision_data:
            log_data["decision"] = {
                "action": event.decision_data["action"],
                "confidence": event.decision_data["confidence"]
            }
        
        if event.action_data:
            log_data["action"] = {
                "action": event.action_data["action"],
                "target": event.action_data["target_resource"]
            }
        
        if event.validation_data:
            log_data["validation"] = {
                "status": event.validation_data["status"],
                "confidence": event.validation_data["confidence"]
            }
        
        if event.error_data:
            log_data["error"] = {
                "type": event.error_data["error_type"],
                "can_retry": event.error_data["can_retry"]
            }
        
        # Log at appropriate level
        if event.event_type == TraceEventType.ERROR:
            self.logger.error(f"TRACE: {event.title}", **log_data)
        elif event.event_type == TraceEventType.DECISION:
            self.logger.info(f"TRACE: {event.title}", **log_data)
        elif event.event_type == TraceEventType.VALIDATION:
            self.logger.info(f"TRACE: {event.title}", **log_data)
        elif event.event_type == TraceEventType.ACTION:
            self.logger.info(f"TRACE: {event.title}", **log_data)
        else:
            self.logger.debug(f"TRACE: {event.title}", **log_data)
    
    def export_trace(self, format: str = "json") -> str:
        """Export full decision trace in specified format"""
        if format == "json":
            return self._export_json()
        elif format == "markdown":
            return self._export_markdown()
        else:
            raise ValueError(f"Unknown format: {format}")
    
    def _export_json(self) -> str:
        """Export trace as JSON"""
        trace_data = {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat() + "Z",
            "end_time": datetime.utcnow().isoformat() + "Z",
            "total_events": len(self.events),
            "trace_level": self.trace_level.value,
            "events": [asdict(event) for event in self.events]
        }
        return json.dumps(trace_data, indent=2, default=str)
    
    def _export_markdown(self) -> str:
        """Export trace as human-readable Markdown"""
        lines = [
            f"# Decision Trace - Session {self.session_id}",
            f"",
            f"**Start Time:** {self.start_time.isoformat()}Z",
            f"**End Time:** {datetime.utcnow().isoformat()}Z",
            f"**Total Events:** {len(self.events)}",
            f"**Trace Level:** {self.trace_level.value}",
            f"",
            f"---",
            f""
        ]
        
        # Group events by type
        events_by_type = {}
        for event in self.events:
            event_type = event.event_type.value
            if event_type not in events_by_type:
                events_by_type[event_type] = []
            events_by_type[event_type].append(event)
        
        # Add sections for each event type
        for event_type, events in events_by_type.items():
            lines.append(f"## {event_type.upper()} ({len(events)} events)")
            lines.append("")
            
            for event in events:
                lines.append(f"### {event.title}")
                lines.append(f"**Time:** {event.timestamp}")
                lines.append(f"**Component:** {event.component}")
                lines.append(f"**Description:** {event.description}")
                
                if event.confidence is not None:
                    lines.append(f"**Confidence:** {event.confidence:.2%}")
                
                if event.decision_data:
                    lines.append(f"**Action:** {event.decision_data['action']}")
                    lines.append(f"**Reasoning:** {event.decision_data['reasoning'][:200]}...")
                    if event.decision_data['alternatives']:
                        lines.append(f"**Alternatives:** {', '.join(event.decision_data['alternatives'])}")
                
                if event.action_data:
                    lines.append(f"**Action:** {event.action_data['action']}")
                    lines.append(f"**Target:** {event.action_data['target_resource']}")
                
                if event.validation_data:
                    lines.append(f"**Status:** {event.validation_data['status']}")
                    lines.append(f"**Confidence:** {event.validation_data['confidence']:.2%}")
                    if event.validation_data['discrepancies']:
                        lines.append(f"**Discrepancies:** {len(event.validation_data['discrepancies'])} found")
                
                if event.error_data:
                    lines.append(f"**Error Type:** {event.error_data['error_type']}")
                    lines.append(f"**Can Retry:** {event.error_data['can_retry']}")
                    lines.append(f"**Next Steps:** {', '.join(event.error_data['next_steps'][:3])}")
                
                lines.append("")
        
        return "\n".join(lines)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of trace events"""
        events_by_type = {}
        for event in self.events:
            event_type = event.event_type.value
            events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
        
        # Calculate average confidence for decisions
        decision_confidences = [e.confidence for e in self.events 
                               if e.confidence is not None and e.event_type == TraceEventType.DECISION]
        avg_confidence = sum(decision_confidences) / len(decision_confidences) if decision_confidences else 0.0
        
        return {
            "session_id": self.session_id,
            "duration_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "total_events": len(self.events),
            "events_by_type": events_by_type,
            "average_decision_confidence": avg_confidence,
            "trace_level": self.trace_level.value
        }
    
    def save_trace_to_file(self, filepath: str, format: str = "json") -> None:
        """Save decision trace to file"""
        trace_content = self.export_trace(format)
        
        with open(filepath, 'w') as f:
            f.write(trace_content)
        
        self.logger.info(f"Decision trace saved to {filepath}", format=format)
