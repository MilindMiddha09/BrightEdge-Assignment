"""Chart data builders and matplotlib graph generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from log_analyzer.models import AnalysisReport


def report_to_chart_data(report: AnalysisReport) -> dict[str, Any]:
    conn_labels = [
        c.timestamp.strftime("%H:%M:%S") if c.timestamp else ""
        for c in report.connection_stats
    ]
    conn_total = [c.total_connections for c in report.connection_stats]
    conn_active = [c.active_connections for c in report.connection_stats]
    conn_util = [round(c.utilization_pct, 1) for c in report.connection_stats]

    sys_labels = [
        m.timestamp.strftime("%H:%M:%S") if m.timestamp else ""
        for m in report.system_metrics
    ]
    load_1m = [m.load_1m for m in report.system_metrics]
    load_5m = [m.load_5m for m in report.system_metrics]
    load_15m = [m.load_15m for m in report.system_metrics]
    mysql_cpu = [m.mysql_cpu_pct or 0 for m in report.system_metrics]
    mysql_mem = [m.mysql_mem_pct or 0 for m in report.system_metrics]

    top_qps = report.qps_by_ip[:12]
    qps_ips = [q.ip for q in top_qps]
    qps_avg = [q.avg_queries_per_sample for q in top_qps]
    qps_est = [q.estimated_qps for q in top_qps]
    qps_roles = [q.role_hint for q in top_qps]
    qps_max = [q.max_queries_per_sample for q in top_qps]

    errors_by_cat: dict[str, int] = {}
    for e in report.errors:
        key = e.category.replace("_", " ").title()
        errors_by_cat[key] = errors_by_cat.get(key, 0) + e.count

    issues_by_sev: dict[str, int] = {}
    for issue in report.issues:
        issues_by_sev[issue.severity.value] = (
            issues_by_sev.get(issue.severity.value, 0) + 1
        )

    latest_conn = report.connection_stats[-1] if report.connection_stats else None
    latest_sys = report.system_metrics[-1] if report.system_metrics else None

    return {
        "meta": {
            "host": report.host,
            "log_file": Path(report.log_file).name,
            "time_start": report.time_range_start.isoformat()
            if report.time_range_start
            else None,
            "time_end": report.time_range_end.isoformat()
            if report.time_range_end
            else None,
            "sample_interval_seconds": report.sample_interval_seconds,
        },
        "summary": {
            "total_connections": latest_conn.total_connections if latest_conn else 0,
            "active_connections": latest_conn.active_connections if latest_conn else 0,
            "connection_util_pct": round(latest_conn.utilization_pct, 1)
            if latest_conn
            else 0,
            "mysql_cpu_pct": latest_sys.mysql_cpu_pct if latest_sys else 0,
            "mysql_mem_pct": latest_sys.mysql_mem_pct if latest_sys else 0,
            "load_1m": latest_sys.load_1m if latest_sys else 0,
            "issue_count": len(report.issues),
            "error_event_count": sum(e.count for e in report.errors),
            "top_qps_ip": report.qps_by_ip[0].ip if report.qps_by_ip else "N/A",
            "top_qps_value": report.qps_by_ip[0].estimated_qps
            if report.qps_by_ip
            else 0,
            "client_ip_count": len(report.qps_by_ip),
        },
        "connections": {
            "labels": conn_labels,
            "total": conn_total,
            "active": conn_active,
            "utilization_pct": conn_util,
        },
        "system": {
            "labels": sys_labels,
            "load_1m": load_1m,
            "load_5m": load_5m,
            "load_15m": load_15m,
            "mysql_cpu_pct": mysql_cpu,
            "mysql_mem_pct": mysql_mem,
        },
        "qps_by_ip": {
            "labels": qps_ips,
            "avg_per_sample": qps_avg,
            "estimated_qps": qps_est,
            "roles": qps_roles,
            "max_per_sample": qps_max,
        },
        "errors": {
            "labels": list(errors_by_cat.keys()),
            "counts": list(errors_by_cat.values()),
        },
        "issues": {
            "labels": list(issues_by_sev.keys()),
            "counts": list(issues_by_sev.values()),
        },
        "issues_detail": [
            {
                "severity": i.severity.value,
                "title": i.title,
                "description": i.description,
                "recommendation": i.recommendation,
            }
            for i in report.issues
        ],
        "query_patterns": [
            {
                "operation": p.operation,
                "table": p.table or "N/A",
                "count": p.count,
            }
            for p in report.query_patterns[:10]
        ],
    }


def generate_graph_pngs(report: AnalysisReport, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    data = report_to_chart_data(report)
    paths: list[Path] = []

    plt.style.use("ggplot")

    fig, ax = plt.subplots(figsize=(10, 5))
    ips = data["qps_by_ip"]["labels"]
    vals = data["qps_by_ip"]["avg_per_sample"]
    ax.barh(ips, vals, color="#2563eb")
    ax.set_xlabel("Avg queries per sample")
    ax.set_title("QPS drivers by client IP")
    ax.invert_yaxis()
    fig.tight_layout()
    p = output_dir / "qps_by_ip.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    paths.append(p)

    fig, ax = plt.subplots(figsize=(10, 5))
    labels = data["connections"]["labels"]
    ax.plot(labels, data["connections"]["total"], marker="o", label="Total", color="#2563eb")
    ax.plot(labels, data["connections"]["active"], marker="s", label="Active", color="#16a34a")
    ax.set_ylabel("Connections")
    ax.set_title("MySQL connections over time")
    ax.legend()
    plt.xticks(rotation=45, ha="right")
    fig.tight_layout()
    p = output_dir / "connections.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    paths.append(p)

    fig, ax = plt.subplots(figsize=(10, 5))
    labels = data["system"]["labels"]
    ax.plot(labels, data["system"]["load_1m"], marker="o", label="1m")
    ax.plot(labels, data["system"]["load_5m"], marker="s", label="5m")
    ax.plot(labels, data["system"]["load_15m"], marker="^", label="15m")
    ax.set_ylabel("Load average")
    ax.set_title("System load average")
    ax.legend()
    plt.xticks(rotation=45, ha="right")
    fig.tight_layout()
    p = output_dir / "load_average.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    paths.append(p)

    fig, ax1 = plt.subplots(figsize=(10, 5))
    ax2 = ax1.twinx()
    ax1.plot(labels, data["system"]["mysql_cpu_pct"], color="#dc3545", marker="o", label="CPU %")
    ax2.plot(labels, data["system"]["mysql_mem_pct"], color="#fd7e14", marker="s", label="MEM %")
    ax1.set_ylabel("CPU %")
    ax2.set_ylabel("Memory %")
    ax1.set_title("MySQL process CPU and memory")
    plt.xticks(rotation=45, ha="right")
    fig.tight_layout()
    p = output_dir / "mysql_resources.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    paths.append(p)

    if data["errors"]["labels"]:
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.bar(data["errors"]["labels"], data["errors"]["counts"], color="#dc3545")
        ax.set_ylabel("Event count")
        ax.set_title("Errors by category")
        plt.xticks(rotation=30, ha="right")
        fig.tight_layout()
        p = output_dir / "errors.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        paths.append(p)

    return paths
