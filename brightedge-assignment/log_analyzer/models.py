"""Data models for MySQL log analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SystemMetrics:
    """System resource snapshot from top output."""

    timestamp: datetime
    load_1m: float
    load_5m: float
    load_15m: float
    cpu_user_pct: float
    cpu_system_pct: float
    cpu_idle_pct: float
    cpu_iowait_pct: float
    mem_total_kb: int
    mem_used_kb: int
    mem_free_kb: int
    mysql_cpu_pct: Optional[float] = None
    mysql_mem_pct: Optional[float] = None


@dataclass
class MySQLConnectionStats:
    """MySQL connection summary per sample."""

    timestamp: datetime
    total_connections: int
    active_connections: int

    @property
    def utilization_pct(self) -> float:
        if self.total_connections == 0:
            return 0.0
        return (self.active_connections / self.total_connections) * 100


@dataclass
class QueryCountByIP:
    """Query count attributed to a client IP at a point in time."""

    timestamp: datetime
    ip: str
    query_count: int


@dataclass
class ErrorEvent:
    """Parsed error or warning from logs."""

    timestamp: Optional[datetime]
    severity: Severity
    category: str
    message: str
    host: Optional[str] = None
    count: int = 1


@dataclass
class InnoDBMetrics:
    """InnoDB buffer pool snapshot."""

    timestamp: datetime
    buffer_pool_hit_rate: float
    queries_inside_innodb: int
    queries_in_queue: int
    rw_transactions_active: int


@dataclass
class QueryPattern:
    """Aggregated SQL query pattern."""

    operation: str
    table: Optional[str]
    count: int
    sample_query: str


@dataclass
class QPSByIP:
    """Aggregated QPS statistics per client IP."""

    ip: str
    total_queries: int
    sample_count: int
    avg_queries_per_sample: float
    max_queries_per_sample: int
    estimated_qps: float
    role_hint: str = ""


@dataclass
class Issue:
    """Identified operational issue."""

    severity: Severity
    title: str
    description: str
    recommendation: str


@dataclass
class AnalysisReport:
    """Complete analysis output."""

    log_file: str
    time_range_start: Optional[datetime]
    time_range_end: Optional[datetime]
    sample_interval_seconds: float
    system_metrics: list[SystemMetrics] = field(default_factory=list)
    connection_stats: list[MySQLConnectionStats] = field(default_factory=list)
    query_counts: list[QueryCountByIP] = field(default_factory=list)
    errors: list[ErrorEvent] = field(default_factory=list)
    innodb_metrics: list[InnoDBMetrics] = field(default_factory=list)
    query_patterns: list[QueryPattern] = field(default_factory=list)
    qps_by_ip: list[QPSByIP] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    host: str = ""
