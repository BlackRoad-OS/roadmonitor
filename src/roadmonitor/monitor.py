"""
RoadMonitor - Application Monitoring for BlackRoad
APM, error tracking, and performance monitoring.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import asyncio
import hashlib
import json
import logging
import statistics
import threading
import time
import traceback
import uuid

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(str, Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class Span:
    """A trace span."""
    id: str
    trace_id: str
    parent_id: Optional[str]
    name: str
    service: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    duration_ms: float = 0
    status: str = "ok"
    tags: Dict[str, str] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)

    def end(self) -> None:
        self.ended_at = datetime.now()
        self.duration_ms = (self.ended_at - self.started_at).total_seconds() * 1000


@dataclass
class Trace:
    """A distributed trace."""
    id: str
    spans: List[Span] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "spans": len(self.spans),
            "started_at": self.started_at.isoformat(),
            "duration_ms": sum(s.duration_ms for s in self.spans)
        }


@dataclass
class ErrorEvent:
    """An error event."""
    id: str
    error_type: str
    message: str
    stack_trace: str
    service: str
    environment: str = "production"
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = hashlib.md5(
                f"{self.error_type}{self.message}".encode()
            ).hexdigest()[:16]


@dataclass
class MetricPoint:
    """A metric data point."""
    name: str
    value: float
    metric_type: MetricType
    tags: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Alert:
    """An alert."""
    id: str
    name: str
    severity: AlertSeverity
    message: str
    source: str
    triggered_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    acknowledged: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class MetricStore:
    """Store for metrics."""

    def __init__(self, max_points: int = 100000):
        self.points: List[MetricPoint] = []
        self.max_points = max_points
        self._lock = threading.Lock()

    def record(self, point: MetricPoint) -> None:
        with self._lock:
            self.points.append(point)
            if len(self.points) > self.max_points:
                self.points = self.points[-self.max_points:]

    def query(
        self,
        name: str,
        start: datetime,
        end: datetime,
        tags: Dict[str, str] = None
    ) -> List[MetricPoint]:
        points = [
            p for p in self.points
            if p.name == name and start <= p.timestamp <= end
        ]
        
        if tags:
            points = [
                p for p in points
                if all(p.tags.get(k) == v for k, v in tags.items())
            ]
        
        return points

    def aggregate(
        self,
        name: str,
        start: datetime,
        end: datetime,
        aggregation: str = "avg"
    ) -> Optional[float]:
        points = self.query(name, start, end)
        if not points:
            return None

        values = [p.value for p in points]
        
        if aggregation == "avg":
            return statistics.mean(values)
        elif aggregation == "sum":
            return sum(values)
        elif aggregation == "min":
            return min(values)
        elif aggregation == "max":
            return max(values)
        elif aggregation == "p50":
            return statistics.median(values)
        elif aggregation == "p95":
            return statistics.quantiles(values, n=20)[18] if len(values) >= 20 else max(values)
        elif aggregation == "p99":
            return statistics.quantiles(values, n=100)[98] if len(values) >= 100 else max(values)
        
        return None


class TraceStore:
    """Store for traces."""

    def __init__(self, max_traces: int = 10000):
        self.traces: Dict[str, Trace] = {}
        self.max_traces = max_traces
        self._lock = threading.Lock()

    def save(self, trace: Trace) -> None:
        with self._lock:
            self.traces[trace.id] = trace
            if len(self.traces) > self.max_traces:
                oldest = sorted(self.traces.values(), key=lambda t: t.started_at)
                for t in oldest[:len(self.traces) - self.max_traces]:
                    del self.traces[t.id]

    def get(self, trace_id: str) -> Optional[Trace]:
        return self.traces.get(trace_id)


class ErrorStore:
    """Store for errors."""

    def __init__(self, max_errors: int = 10000):
        self.errors: List[ErrorEvent] = []
        self.error_groups: Dict[str, List[ErrorEvent]] = {}  # fingerprint -> errors
        self.max_errors = max_errors
        self._lock = threading.Lock()

    def save(self, error: ErrorEvent) -> None:
        with self._lock:
            self.errors.append(error)
            
            if error.fingerprint not in self.error_groups:
                self.error_groups[error.fingerprint] = []
            self.error_groups[error.fingerprint].append(error)
            
            if len(self.errors) > self.max_errors:
                self.errors = self.errors[-self.max_errors:]

    def get_recent(self, limit: int = 100) -> List[ErrorEvent]:
        return self.errors[-limit:]

    def get_grouped(self) -> Dict[str, Dict[str, Any]]:
        return {
            fp: {
                "count": len(errors),
                "first_seen": min(e.timestamp for e in errors).isoformat(),
                "last_seen": max(e.timestamp for e in errors).isoformat(),
                "sample": errors[-1].message
            }
            for fp, errors in self.error_groups.items()
        }


class AlertManager:
    """Manage alerts."""

    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.rules: List[Dict[str, Any]] = []
        self._handlers: List[Callable[[Alert], None]] = []
        self._lock = threading.Lock()

    def add_handler(self, handler: Callable[[Alert], None]) -> None:
        self._handlers.append(handler)

    def add_rule(
        self,
        name: str,
        condition: Callable[[Dict[str, Any]], bool],
        severity: AlertSeverity,
        message_template: str
    ) -> None:
        self.rules.append({
            "name": name,
            "condition": condition,
            "severity": severity,
            "message_template": message_template
        })

    def check_rules(self, context: Dict[str, Any]) -> List[Alert]:
        alerts = []
        for rule in self.rules:
            if rule["condition"](context):
                alert = Alert(
                    id=str(uuid.uuid4()),
                    name=rule["name"],
                    severity=rule["severity"],
                    message=rule["message_template"].format(**context),
                    source="rule"
                )
                alerts.append(alert)
                self._fire_alert(alert)
        return alerts

    def _fire_alert(self, alert: Alert) -> None:
        with self._lock:
            self.alerts[alert.id] = alert
        
        for handler in self._handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")

    def acknowledge(self, alert_id: str) -> bool:
        alert = self.alerts.get(alert_id)
        if alert:
            alert.acknowledged = True
            return True
        return False

    def resolve(self, alert_id: str) -> bool:
        alert = self.alerts.get(alert_id)
        if alert:
            alert.resolved_at = datetime.now()
            return True
        return False

    def get_active(self) -> List[Alert]:
        return [a for a in self.alerts.values() if not a.resolved_at]


class Tracer:
    """Create and manage traces."""

    def __init__(self, service: str, store: TraceStore):
        self.service = service
        self.store = store
        self._current_trace = threading.local()

    def start_trace(self, name: str) -> Trace:
        trace = Trace(id=str(uuid.uuid4()))
        self._current_trace.trace = trace
        self.start_span(name)
        return trace

    def start_span(self, name: str, parent_id: Optional[str] = None) -> Span:
        trace = getattr(self._current_trace, 'trace', None)
        if not trace:
            trace = self.start_trace(name)
            return trace.spans[0]

        span = Span(
            id=str(uuid.uuid4()),
            trace_id=trace.id,
            parent_id=parent_id or (trace.spans[-1].id if trace.spans else None),
            name=name,
            service=self.service,
            started_at=datetime.now()
        )
        trace.spans.append(span)
        return span

    def end_trace(self) -> Optional[Trace]:
        trace = getattr(self._current_trace, 'trace', None)
        if trace:
            for span in trace.spans:
                if not span.ended_at:
                    span.end()
            self.store.save(trace)
            self._current_trace.trace = None
            return trace
        return None


class Monitor:
    """Main monitoring system."""

    def __init__(self, service: str):
        self.service = service
        self.metric_store = MetricStore()
        self.trace_store = TraceStore()
        self.error_store = ErrorStore()
        self.alert_manager = AlertManager()
        self.tracer = Tracer(service, self.trace_store)

    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        tags: Dict[str, str] = None
    ) -> None:
        point = MetricPoint(
            name=name,
            value=value,
            metric_type=metric_type,
            tags=tags or {}
        )
        self.metric_store.record(point)

    def increment(self, name: str, value: float = 1, tags: Dict[str, str] = None) -> None:
        self.record_metric(name, value, MetricType.COUNTER, tags)

    def gauge(self, name: str, value: float, tags: Dict[str, str] = None) -> None:
        self.record_metric(name, value, MetricType.GAUGE, tags)

    def histogram(self, name: str, value: float, tags: Dict[str, str] = None) -> None:
        self.record_metric(name, value, MetricType.HISTOGRAM, tags)

    def capture_exception(
        self,
        exception: Exception,
        context: Dict[str, Any] = None
    ) -> ErrorEvent:
        error = ErrorEvent(
            id=str(uuid.uuid4()),
            error_type=type(exception).__name__,
            message=str(exception),
            stack_trace=traceback.format_exc(),
            service=self.service,
            context=context or {}
        )
        self.error_store.save(error)
        
        # Check alert rules
        self.alert_manager.check_rules({
            "error_type": error.error_type,
            "message": error.message,
            "service": self.service
        })
        
        return error

    def trace(self, name: str):
        """Context manager for tracing."""
        class TraceContext:
            def __init__(ctx, tracer, span_name):
                ctx.tracer = tracer
                ctx.span_name = span_name
                ctx.span = None

            def __enter__(ctx):
                ctx.span = ctx.tracer.start_span(ctx.span_name)
                return ctx.span

            def __exit__(ctx, exc_type, exc_val, exc_tb):
                if ctx.span:
                    ctx.span.end()
                    if exc_type:
                        ctx.span.status = "error"
                        ctx.span.logs.append({
                            "error": str(exc_val),
                            "timestamp": datetime.now().isoformat()
                        })
                return False

        return TraceContext(self.tracer, name)

    def get_metrics_summary(self, metric_name: str, period_minutes: int = 60) -> Dict[str, Any]:
        end = datetime.now()
        start = end - timedelta(minutes=period_minutes)
        
        return {
            "name": metric_name,
            "period_minutes": period_minutes,
            "avg": self.metric_store.aggregate(metric_name, start, end, "avg"),
            "min": self.metric_store.aggregate(metric_name, start, end, "min"),
            "max": self.metric_store.aggregate(metric_name, start, end, "max"),
            "p95": self.metric_store.aggregate(metric_name, start, end, "p95")
        }

    def get_error_summary(self) -> Dict[str, Any]:
        grouped = self.error_store.get_grouped()
        return {
            "total_groups": len(grouped),
            "total_errors": len(self.error_store.errors),
            "groups": grouped
        }


# Example usage
def example_usage():
    """Example monitoring usage."""
    monitor = Monitor(service="my-service")

    # Record metrics
    monitor.gauge("cpu_usage", 45.2, tags={"host": "server-1"})
    monitor.increment("requests_total", tags={"endpoint": "/api/users"})
    monitor.histogram("response_time_ms", 125.5)

    # Trace a request
    with monitor.trace("handle_request") as span:
        span.tags["user_id"] = "user-123"
        
        with monitor.trace("database_query") as db_span:
            db_span.tags["query"] = "SELECT * FROM users"
            time.sleep(0.01)
        
        with monitor.trace("external_api") as api_span:
            time.sleep(0.02)

    monitor.tracer.end_trace()

    # Capture error
    try:
        raise ValueError("Something went wrong")
    except Exception as e:
        monitor.capture_exception(e, context={"user_id": "user-123"})

    # Add alert rule
    monitor.alert_manager.add_rule(
        name="High Error Rate",
        condition=lambda ctx: ctx.get("error_type") == "ValueError",
        severity=AlertSeverity.ERROR,
        message="ValueError detected: {message}"
    )

    # Get summaries
    metrics = monitor.get_metrics_summary("cpu_usage")
    print(f"CPU metrics: {metrics}")

    errors = monitor.get_error_summary()
    print(f"Error summary: {errors}")
