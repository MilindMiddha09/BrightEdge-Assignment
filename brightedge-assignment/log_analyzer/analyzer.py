"""Core log analysis engine."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd

from log_analyzer.models import (
    AnalysisReport,
    Issue,
    QPSByIP,
    QueryCountByIP,
    Severity,
)
from log_analyzer.parsers import (
    get_host_from_df,
    load_log_csv,
    parse_errors,
    parse_innodb_metrics,
    parse_mysql_connection_stats,
    parse_query_counts_by_ip,
    parse_query_patterns,
    parse_system_metrics,
)

logger = logging.getLogger(__name__)

IP_ROLE_HINTS = {
    "192.0.2.14": "Application server (dominant QPS driver)",
    "192.0.2.12": "Service tier (variable load)",
    "203.0.113.10": "Secondary application",
    "192.0.2.23": "Service / batch worker",
    "192.0.2.10": "Application tier",
    "192.0.2.13": "Application tier",
    "192.0.2.21": "Replication client",
    "192.0.2.22": "Replication client",
    "192.0.2.26": "Replication client",
    "198.51.100.": "CDC / change-data-capture (prefix)",
    "repl_user": "Replication",
}


def _infer_ip_role(ip: str) -> str:
    for prefix, role in IP_ROLE_HINTS.items():
        if ip.startswith(prefix) or ip == prefix.rstrip("."):
            return role
    return "Client"


def _estimate_sample_interval_seconds(timestamps: list[datetime]) -> float:
    if len(timestamps) < 2:
        return 60.0
    sorted_ts = sorted(timestamps)
    deltas = [
        (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
        for i in range(len(sorted_ts) - 1)
        if (sorted_ts[i + 1] - sorted_ts[i]).total_seconds() > 0
    ]
    if not deltas:
        return 60.0
    return sum(deltas) / len(deltas)


def compute_qps_by_ip(
    query_counts: list[QueryCountByIP],
    sample_interval_seconds: float,
) -> list[QPSByIP]:
    """Aggregate query counts per IP and estimate QPS."""
    by_ip: dict[str, list[int]] = defaultdict(list)
    for qc in query_counts:
        by_ip[qc.ip].append(qc.query_count)

    results: list[QPSByIP] = []
    interval = max(sample_interval_seconds, 1.0)

    for ip, counts in sorted(by_ip.items(), key=lambda x: -sum(x[1])):
        total = sum(counts)
        avg = total / len(counts) if counts else 0
        max_c = max(counts) if counts else 0
        estimated_qps = avg / interval
        results.append(
            QPSByIP(
                ip=ip,
                total_queries=total,
                sample_count=len(counts),
                avg_queries_per_sample=round(avg, 2),
                max_queries_per_sample=max_c,
                estimated_qps=round(estimated_qps, 4),
                role_hint=_infer_ip_role(ip),
            )
        )
    return results


def _detect_issues(report: AnalysisReport) -> list[Issue]:
    issues: list[Issue] = []

    network_errors = [e for e in report.errors if e.category == "network_connectivity"]
    if network_errors:
        hosts = sorted({e.host for e in network_errors if e.host})
        total = sum(e.count for e in network_errors)
        issues.append(
            Issue(
                severity=Severity.HIGH,
                title="Network connectivity failures",
                description=(
                    f"{total} network trace failures across {len(hosts)} hosts: "
                    f"{', '.join(hosts[:5])}{'...' if len(hosts) > 5 else ''}"
                ),
                recommendation=(
                    "Verify firewall rules, routing, and security groups between "
                    "db-master and application/CDC hosts. Check VPC peering and NACLs."
                ),
            )
        )

    auth_errors = [e for e in report.errors if e.category == "authentication_failure"]
    if auth_errors:
        hosts = sorted({e.host for e in auth_errors if e.host})
        issues.append(
            Issue(
                severity=Severity.HIGH,
                title="Authentication failures on network traces",
                description=(
                    f"Password prompts received when tracing {len(hosts)} hosts: "
                    f"{', '.join(hosts)}"
                ),
                recommendation=(
                    "Use SSH keys or service accounts for automated traces; "
                    "rotate credentials and restrict password-based SSH."
                ),
            )
        )

    if report.system_metrics:
        mem_pcts = [
            (m.mem_used_kb / m.mem_total_kb * 100) if m.mem_total_kb else 0
            for m in report.system_metrics
        ]
        mysql_mem = [
            m.mysql_mem_pct for m in report.system_metrics if m.mysql_mem_pct is not None
        ]
        avg_mem = sum(mem_pcts) / len(mem_pcts) if mem_pcts else 0
        avg_mysql_mem = sum(mysql_mem) / len(mysql_mem) if mysql_mem else 0
        if avg_mysql_mem >= 70 or avg_mem >= 90:
            issues.append(
                Issue(
                    severity=Severity.MEDIUM,
                    title="High memory utilization",
                    description=(
                        f"System memory ~{avg_mem:.1f}% used; MySQL process ~{avg_mysql_mem:.1f}% RSS."
                    ),
                    recommendation=(
                        "Tune innodb_buffer_pool_size, review connection memory per thread, "
                        "and alert at 80% before OOM risk."
                    ),
                )
            )

    if report.connection_stats:
        utils = [c.utilization_pct for c in report.connection_stats]
        avg_util = sum(utils) / len(utils)
        avg_total = sum(c.total_connections for c in report.connection_stats) / len(
            report.connection_stats
        )
        if avg_util < 15 and avg_total > 40:
            issues.append(
                Issue(
                    severity=Severity.MEDIUM,
                    title="Low connection pool utilization",
                    description=(
                        f"Only {avg_util:.1f}% of connections active on average "
                        f"({avg_total:.0f} total connections)."
                    ),
                    recommendation=(
                        "Reduce max_connections and right-size application connection pools "
                        "to lower memory overhead and thread contention."
                    ),
                )
            )

    heavy_updates = [
        p
        for p in report.query_patterns
        if p.operation == "UPDATE" and "IN (" in p.sample_query.upper()
    ]
    if heavy_updates:
        issues.append(
            Issue(
                severity=Severity.MEDIUM,
                title="Large batch UPDATE queries",
                description=(
                    f"Detected {sum(p.count for p in heavy_updates)} UPDATE patterns "
                    "with large IN clauses (e.g. ix_account_internal_links_crawl)."
                ),
                recommendation=(
                    "Batch updates in smaller chunks, ensure composite indexes on "
                    "(account_id, u_url_id), and monitor InnoDB row locks."
                ),
            )
        )

    script_errs = [e for e in report.errors if e.category == "monitoring_script"]
    if script_errs:
        issues.append(
            Issue(
                severity=Severity.LOW,
                title="Monitoring script parse errors",
                description=(
                    f"Process ID list syntax error occurred {script_errs[0].count} times."
                ),
                recommendation=(
                    "Fix ops_logs.py PID parsing; add input validation and unit tests."
                ),
            )
        )

    if report.system_metrics:
        loads = [m.load_1m for m in report.system_metrics]
        if loads and max(loads) > min(loads) * 2 and max(loads) > 0.5:
            issues.append(
                Issue(
                    severity=Severity.INFO,
                    title="Load average variability",
                    description=(
                        f"1m load ranged from {min(loads):.2f} to {max(loads):.2f} "
                        "during the observation window."
                    ),
                    recommendation=(
                        "Correlate load spikes with QPS by IP and slow query log; "
                        "consider auto-scaling read replicas if sustained."
                    ),
                )
            )

    if report.innodb_metrics:
        hits = [m.buffer_pool_hit_rate for m in report.innodb_metrics]
        min_hit = min(hits) if hits else 100
        if min_hit < 99.0:
            issues.append(
                Issue(
                    severity=Severity.INFO,
                    title="InnoDB buffer pool hit rate below 99%",
                    description=f"Minimum observed hit rate: {min_hit:.1f}%.",
                    recommendation=(
                        "Consider increasing innodb_buffer_pool_size if working set exceeds pool."
                    ),
                )
            )

    return issues


class LogAnalyzer:
    """Main analyzer orchestrating parse and insight generation."""

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_path}")

    def analyze(self) -> AnalysisReport:
        logger.info("Loading log file: %s", self.log_path)
        df = load_log_csv(str(self.log_path))

        system_metrics = parse_system_metrics(df)
        connection_stats = parse_mysql_connection_stats(df)
        query_counts = parse_query_counts_by_ip(df)
        errors = parse_errors(df)
        innodb_metrics = parse_innodb_metrics(df)
        query_patterns = parse_query_patterns(df)

        all_ts = [
            t for t in df["parsed_ts"].dropna().tolist() if isinstance(t, datetime)
        ]
        time_start = min(all_ts) if all_ts else None
        time_end = max(all_ts) if all_ts else None

        sample_ts = [c.timestamp for c in connection_stats] or all_ts
        interval = _estimate_sample_interval_seconds(sample_ts)

        qps_by_ip = compute_qps_by_ip(query_counts, interval)

        report = AnalysisReport(
            log_file=str(self.log_path),
            time_range_start=time_start,
            time_range_end=time_end,
            sample_interval_seconds=interval,
            system_metrics=system_metrics,
            connection_stats=connection_stats,
            query_counts=query_counts,
            errors=errors,
            innodb_metrics=innodb_metrics,
            query_patterns=query_patterns,
            qps_by_ip=qps_by_ip,
            host=get_host_from_df(df),
        )
        report.issues = _detect_issues(report)
        return report
