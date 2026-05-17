"""Log parsing utilities using pandas and regex."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

import pandas as pd

from log_analyzer.models import (
    ErrorEvent,
    InnoDBMetrics,
    MySQLConnectionStats,
    QueryCountByIP,
    QueryPattern,
    Severity,
    SystemMetrics,
)

RE_TOP_LOAD = re.compile(
    r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)",
    re.IGNORECASE,
)
RE_CPU = re.compile(
    r"Cpu\(s\):\s*([\d.]+)%us,\s*([\d.]+)%sy,\s*[\d.]+%ni,\s*([\d.]+)%id,\s*([\d.]+)%wa",
    re.IGNORECASE,
)
RE_MEM = re.compile(
    r"Mem:\s*(\d+)k total,\s*(\d+)k used,\s*(\d+)k free",
    re.IGNORECASE,
)
RE_MYSQL_STAT = re.compile(
    r"MYSQL STAT:\s*total:\s*(\d+)\s*active:\s*(\d+)",
    re.IGNORECASE,
)
RE_QUERY_COUNT_IP = re.compile(
    r"IP:\s*([\d.]+)\s+No\.\s*of\s*Queries:\s*(\d+)",
    re.IGNORECASE,
)
RE_BUFFER_HIT = re.compile(
    r"Buffer pool hit rate\s*(\d+)\s*/\s*1000",
    re.IGNORECASE,
)
RE_INNODB_QUERIES = re.compile(
    r"(\d+)\s+queries inside InnoDB,\s*(\d+)\s+queries in queue",
    re.IGNORECASE,
)
RE_RW_TX = re.compile(
    r"(\d+)\s+RW transactions active inside InnoDB",
    re.IGNORECASE,
)
RE_MYSQL_PROCESS = re.compile(
    r"mysql\s+\d+\s+([\d.]+)\s+([\d.]+)\s+.*mysqld",
    re.IGNORECASE,
)
RE_NETWORK_ERROR = re.compile(
    r"Skipping trace for\s+([\d.]+)\.\s*Network error",
    re.IGNORECASE,
)
RE_AUTH_FAIL = re.compile(
    r"Trace failed, password prompt received\.\s*ip:\s*([\d.]+)",
    re.IGNORECASE,
)
RE_PROCESSLIST = re.compile(
    r"\((\d+),\s*(\d+),\s*'([^']*)',\s*'([^']*)',\s*(?:'([^']*)'|None)\)",
)
RE_SQL_OP = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE)\b",
    re.IGNORECASE,
)
RE_TABLE_FROM = re.compile(
    r"\b(?:FROM|INTO|UPDATE|JOIN)\s+`?(\w+)`?",
    re.IGNORECASE,
)


def _parse_timestamp(date_str: str) -> Optional[datetime]:
    if not date_str or pd.isna(date_str):
        return None
    try:
        s = str(date_str).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def load_log_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "Date" in df.columns:
        df["parsed_ts"] = df["Date"].apply(_parse_timestamp)
    else:
        df["parsed_ts"] = None
    if "Line" not in df.columns:
        raise ValueError("CSV must contain a 'Line' column")
    df["line_lower"] = df["Line"].str.lower()
    return df


def parse_system_metrics(df: pd.DataFrame) -> list[SystemMetrics]:
    metrics: list[SystemMetrics] = []
    current_ts: Optional[datetime] = None
    pending: dict = {}

    for _, row in df.iterrows():
        line = row.get("Line", "")
        ts = row.get("parsed_ts") or current_ts

        load_m = RE_TOP_LOAD.search(line)
        if load_m:
            current_ts = ts
            pending = {
                "timestamp": ts,
                "load_1m": float(load_m.group(1)),
                "load_5m": float(load_m.group(2)),
                "load_15m": float(load_m.group(3)),
            }
            continue

        cpu_m = RE_CPU.search(line)
        if cpu_m and pending:
            pending["cpu_user_pct"] = float(cpu_m.group(1))
            pending["cpu_system_pct"] = float(cpu_m.group(2))
            pending["cpu_idle_pct"] = float(cpu_m.group(3))
            pending["cpu_iowait_pct"] = float(cpu_m.group(4))
            continue

        mem_m = RE_MEM.search(line)
        if mem_m and pending:
            pending["mem_total_kb"] = int(mem_m.group(1))
            pending["mem_used_kb"] = int(mem_m.group(2))
            pending["mem_free_kb"] = int(mem_m.group(3))
            continue

        mysql_m = RE_MYSQL_PROCESS.search(line)
        if mysql_m and pending:
            pending["mysql_cpu_pct"] = float(mysql_m.group(1))
            pending["mysql_mem_pct"] = float(mysql_m.group(2))
            if pending.get("timestamp"):
                metrics.append(
                    SystemMetrics(
                        timestamp=pending["timestamp"],
                        load_1m=pending.get("load_1m", 0),
                        load_5m=pending.get("load_5m", 0),
                        load_15m=pending.get("load_15m", 0),
                        cpu_user_pct=pending.get("cpu_user_pct", 0),
                        cpu_system_pct=pending.get("cpu_system_pct", 0),
                        cpu_idle_pct=pending.get("cpu_idle_pct", 0),
                        cpu_iowait_pct=pending.get("cpu_iowait_pct", 0),
                        mem_total_kb=pending.get("mem_total_kb", 0),
                        mem_used_kb=pending.get("mem_used_kb", 0),
                        mem_free_kb=pending.get("mem_free_kb", 0),
                        mysql_cpu_pct=pending.get("mysql_cpu_pct"),
                        mysql_mem_pct=pending.get("mysql_mem_pct"),
                    )
                )
            pending = {}

    return metrics


def parse_mysql_connection_stats(df: pd.DataFrame) -> list[MySQLConnectionStats]:
    stats: list[MySQLConnectionStats] = []
    for _, row in df.iterrows():
        m = RE_MYSQL_STAT.search(row.get("Line", ""))
        if m:
            ts = row.get("parsed_ts")
            if ts:
                stats.append(
                    MySQLConnectionStats(
                        timestamp=ts,
                        total_connections=int(m.group(1)),
                        active_connections=int(m.group(2)),
                    )
                )
    return stats


def parse_query_counts_by_ip(df: pd.DataFrame) -> list[QueryCountByIP]:
    counts: list[QueryCountByIP] = []
    for _, row in df.iterrows():
        m = RE_QUERY_COUNT_IP.search(row.get("Line", ""))
        if m:
            ts = row.get("parsed_ts")
            if ts:
                counts.append(
                    QueryCountByIP(
                        timestamp=ts,
                        ip=m.group(1),
                        query_count=int(m.group(2)),
                    )
                )
    return counts


def parse_innodb_metrics(df: pd.DataFrame) -> list[InnoDBMetrics]:
    metrics: list[InnoDBMetrics] = []
    current_ts: Optional[datetime] = None
    hit_rate: Optional[float] = None
    inside: Optional[int] = None
    queue: Optional[int] = None
    rw_tx: Optional[int] = None

    for _, row in df.iterrows():
        line = row.get("Line", "")
        ts = row.get("parsed_ts")

        if "INNODB STATUS" in line.upper() or "SHOW ENGINE INNODB" in line.upper():
            current_ts = ts
            hit_rate = inside = queue = rw_tx = None
            continue

        hm = RE_BUFFER_HIT.search(line)
        if hm:
            hit_rate = int(hm.group(1)) / 10.0
            continue

        qm = RE_INNODB_QUERIES.search(line)
        if qm:
            inside = int(qm.group(1))
            queue = int(qm.group(2))
            continue

        tm = RE_RW_TX.search(line)
        if tm:
            rw_tx = int(tm.group(1))
            if current_ts and hit_rate is not None:
                metrics.append(
                    InnoDBMetrics(
                        timestamp=current_ts,
                        buffer_pool_hit_rate=hit_rate,
                        queries_inside_innodb=inside or 0,
                        queries_in_queue=queue or 0,
                        rw_transactions_active=rw_tx,
                    )
                )
            hit_rate = inside = queue = rw_tx = None

    return metrics


def parse_errors(df: pd.DataFrame) -> list[ErrorEvent]:
    errors: list[ErrorEvent] = []
    seen: dict[str, ErrorEvent] = {}

    for _, row in df.iterrows():
        line = row.get("Line", "")
        ts = row.get("parsed_ts")
        level = str(row.get("detected_level", "")).lower()

        nm = RE_NETWORK_ERROR.search(line)
        if nm:
            key = f"network:{nm.group(1)}"
            host = nm.group(1)
            if key in seen:
                seen[key].count += 1
            else:
                seen[key] = ErrorEvent(
                    timestamp=ts,
                    severity=Severity.HIGH,
                    category="network_connectivity",
                    message=f"Network trace failure to {host}",
                    host=host,
                )
            continue

        am = RE_AUTH_FAIL.search(line)
        if am:
            key = f"auth:{am.group(1)}"
            host = am.group(1)
            if key in seen:
                seen[key].count += 1
            else:
                seen[key] = ErrorEvent(
                    timestamp=ts,
                    severity=Severity.HIGH,
                    category="authentication_failure",
                    message=f"Password prompt on trace to {host}",
                    host=host,
                )
            continue

        if "ERROR: Process ID list syntax error" in line:
            key = "syntax:process_id"
            if key in seen:
                seen[key].count += 1
            else:
                seen[key] = ErrorEvent(
                    timestamp=ts,
                    severity=Severity.LOW,
                    category="monitoring_script",
                    message="Process ID list syntax error in ops script",
                )
            continue

        if level == "error" and "mysqld" in line.lower():
            key = "mysql:high_cpu_process"
            if key not in seen:
                seen[key] = ErrorEvent(
                    timestamp=ts,
                    severity=Severity.MEDIUM,
                    category="mysql_process",
                    message="MySQL process flagged at high CPU in monitoring",
                )

    errors.extend(seen.values())
    return sorted(errors, key=lambda e: (-e.count, e.category))


def parse_query_patterns(df: pd.DataFrame, max_samples: int = 20) -> list[QueryPattern]:
    pattern_map: dict[str, QueryPattern] = {}

    for _, row in df.iterrows():
        line = row.get("Line", "")
        if "system user" not in line and "app_user" not in line:
            if not RE_SQL_OP.search(line):
                continue

        sql = line
        pm = RE_PROCESSLIST.search(line)
        if pm and pm.group(5):
            sql = pm.group(5).replace("\\n", " ").strip()[:500]
        elif "[INFO]" in line:
            idx = line.find("[INFO]")
            if idx >= 0:
                sql = line[idx + 6 :].strip()[:500]

        if "insert buffer thread" in sql.lower() or "I/O thread" in sql:
            continue

        op_m = RE_SQL_OP.search(sql)
        if not op_m:
            continue
        operation = op_m.group(1).upper()

        table = None
        tbl_m = RE_TABLE_FROM.search(sql)
        if tbl_m:
            table = tbl_m.group(1)

        key = f"{operation}:{table or 'unknown'}"
        if key in pattern_map:
            pattern_map[key].count += 1
        else:
            pattern_map[key] = QueryPattern(
                operation=operation,
                table=table,
                count=1,
                sample_query=sql[:200],
            )
        if len(pattern_map) >= max_samples * 3:
            break

    return sorted(pattern_map.values(), key=lambda p: -p.count)[:max_samples]


def get_host_from_df(df: pd.DataFrame) -> str:
    if "host" in df.columns and len(df) > 0:
        hosts = df["host"].dropna().unique()
        hosts = [h for h in hosts if h]
        if hosts:
            return str(hosts[0])
    return "unknown"
