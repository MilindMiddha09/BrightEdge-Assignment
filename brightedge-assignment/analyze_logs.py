from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_analyzer import LogAnalyzer
from log_analyzer.charts import generate_graph_pngs
from log_analyzer.dashboard import run_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("analyze_logs")

DEFAULT_LOG_FILE = "Logs-sanitised-2026-04-17_For Assesment.csv"


def add_log_file_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "log_file",
        nargs="?",
        default=DEFAULT_LOG_FILE,
        help="Path to sanitized log CSV",
    )


def resolve_log_path(log_file: str) -> Path:
    log_path = Path(log_file)
    if not log_path.is_absolute():
        script_dir = Path(__file__).resolve().parent
        candidate = script_dir / log_path
        if candidate.exists():
            log_path = candidate
    return log_path


def format_human_report(analyzer: LogAnalyzer) -> str:
    report = analyzer.analyze()
    lines: list[str] = []

    lines.append("=" * 72)
    lines.append("MYSQL OPERATIONAL LOG ANALYSIS REPORT")
    lines.append("=" * 72)
    lines.append(f"Log file:     {report.log_file}")
    lines.append(f"Host:         {report.host}")
    if report.time_range_start and report.time_range_end:
        lines.append(
            f"Time range:   {report.time_range_start} -> {report.time_range_end}"
        )
    lines.append(f"Sample interval: ~{report.sample_interval_seconds:.0f}s")
    lines.append("")

    lines.append("QPS DRIVERS (by client IP)")
    lines.append("-" * 72)
    for q in report.qps_by_ip[:10]:
        lines.append(
            f"  {q.ip:16}  avg={q.avg_queries_per_sample:6.1f}  "
            f"max={q.max_queries_per_sample:3d}  est_qps={q.estimated_qps:.4f}  "
            f"({q.role_hint})"
        )
    lines.append("")

    lines.append("ISSUES")
    lines.append("-" * 72)
    for issue in report.issues:
        lines.append(f"  [{issue.severity.value}] {issue.title}")
        lines.append(f"    {issue.description}")
        lines.append(f"    -> {issue.recommendation}")
        lines.append("")

    if report.connection_stats:
        c = report.connection_stats[-1]
        lines.append(
            f"Connections: {c.total_connections} total, {c.active_connections} active "
            f"({c.utilization_pct:.1f}% util)"
        )
    lines.append("=" * 72)
    return "\n".join(lines)


def cmd_serve(args: argparse.Namespace) -> int:
    log_path = resolve_log_path(args.log_file)
    if not log_path.exists():
        logger.error("Log file not found: %s", log_path)
        return 1
    graphs_dir = Path(args.graphs_dir) if args.graphs_dir else None
    run_dashboard(log_path, host=args.host, port=args.port, graphs_dir=graphs_dir)
    return 0


def cmd_graphs(args: argparse.Namespace) -> int:
    log_path = resolve_log_path(args.log_file)
    if not log_path.exists():
        logger.error("Log file not found: %s", log_path)
        return 1
    out_dir = Path(args.output_dir)
    report = LogAnalyzer(log_path).analyze()
    paths = generate_graph_pngs(report, out_dir)
    logger.info("Wrote %d graphs to %s", len(paths), out_dir)
    for p in paths:
        print(p)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    log_path = resolve_log_path(args.log_file)
    if not log_path.exists():
        logger.error("Log file not found: %s", log_path)
        return 1
    output = format_human_report(LogAnalyzer(log_path))
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        logger.info("Wrote report to %s", args.output)
    else:
        print(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze MySQL logs — graphs & metrics dashboard on port 8080."
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Start web dashboard (default)")
    add_log_file_arg(serve_p)
    serve_p.add_argument("--host", default="0.0.0.0", help="Bind host")
    serve_p.add_argument("--port", type=int, default=8080, help="Bind port")
    serve_p.add_argument(
        "--graphs-dir",
        default="/tmp/mysql-log-graphs",
        help="Directory for matplotlib PNG exports",
    )
    serve_p.set_defaults(func=cmd_serve)

    graphs_p = sub.add_parser("graphs", help="Export matplotlib PNG graphs only")
    add_log_file_arg(graphs_p)
    graphs_p.add_argument(
        "-o", "--output-dir", default="graphs", help="Output directory for PNGs"
    )
    graphs_p.set_defaults(func=cmd_graphs)

    report_p = sub.add_parser("report", help="Print text summary")
    add_log_file_arg(report_p)
    report_p.add_argument("-o", "--output", help="Write report to file")
    report_p.set_defaults(func=cmd_report)

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.command is None:
        ns = argparse.Namespace(
            log_file=DEFAULT_LOG_FILE,
            host="0.0.0.0",
            port=8080,
            graphs_dir="/tmp/mysql-log-graphs",
        )
        return cmd_serve(ns)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
