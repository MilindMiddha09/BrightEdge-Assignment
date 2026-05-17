"""Flask web dashboard for graphs and metrics."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, render_template_string, send_from_directory

from log_analyzer.analyzer import LogAnalyzer
from log_analyzer.charts import generate_graph_pngs, report_to_chart_data
from log_analyzer.models import AnalysisReport

logger = logging.getLogger(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MySQL Log Analytics</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    :root { --bg: #f4f5f7; --card: #fff; --text: #1a1a2e; --muted: #5c5c6f; --border: #e2e4e9; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); }
    header { background: var(--card); border-bottom: 1px solid var(--border); padding: 1.25rem 2rem; }
    header h1 { font-size: 1.35rem; font-weight: 600; }
    header p { color: var(--muted); font-size: 0.875rem; margin-top: 0.25rem; }
    main { max-width: 1280px; margin: 0 auto; padding: 1.5rem 2rem 3rem; }
    .metrics { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .metric { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
    .metric .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }
    .metric .value { font-size: 1.5rem; font-weight: 600; margin-top: 0.25rem; }
    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.5rem; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
    .card h2 { font-size: 0.95rem; font-weight: 600; margin-bottom: 1rem; }
    .card.wide { grid-column: 1 / -1; }
    .chart-wrap { position: relative; height: 280px; }
    .chart-wrap.tall { height: 320px; }
    .png-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
    .png-grid img { width: 100%; border: 1px solid var(--border); border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th, td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { color: var(--muted); font-weight: 500; text-align: left; }
    .sev-HIGH { color: #dc3545; font-weight: 600; }
    .sev-MEDIUM { color: #fd7e14; font-weight: 600; }
    footer { text-align: center; color: var(--muted); font-size: 0.75rem; margin-top: 2rem; }
  </style>
</head>
<body>
  <header>
    <h1>MySQL Operational Log Analytics</h1>
    <p id="subtitle">Loading...</p>
  </header>
  <main>
    <section class="metrics" id="metric-cards"></section>
    <div class="grid">
      <article class="card wide">
        <h2>QPS drivers by client IP</h2>
        <div class="chart-wrap tall"><canvas id="chartQps"></canvas></div>
      </article>
      <article class="card">
        <h2>MySQL connections</h2>
        <div class="chart-wrap"><canvas id="chartConn"></canvas></div>
      </article>
      <article class="card">
        <h2>Connection utilization (%)</h2>
        <div class="chart-wrap"><canvas id="chartUtil"></canvas></div>
      </article>
      <article class="card">
        <h2>System load average</h2>
        <div class="chart-wrap"><canvas id="chartLoad"></canvas></div>
      </article>
      <article class="card">
        <h2>MySQL CPU &amp; memory (%)</h2>
        <div class="chart-wrap"><canvas id="chartMysql"></canvas></div>
      </article>
      <article class="card">
        <h2>Errors by category</h2>
        <div class="chart-wrap"><canvas id="chartErrors"></canvas></div>
      </article>
      <article class="card">
        <h2>Issues by severity</h2>
        <div class="chart-wrap"><canvas id="chartIssues"></canvas></div>
      </article>
      <article class="card wide" id="png-section" style="display:none">
        <h2>Static graphs (matplotlib)</h2>
        <div class="png-grid" id="png-grid"></div>
      </article>
      <article class="card wide">
        <h2>QPS driver breakdown</h2>
        <table>
          <thead><tr><th>IP</th><th>Role</th><th>Avg/sample</th><th>Est. QPS</th><th>Max/sample</th></tr></thead>
          <tbody id="qps-table"></tbody>
        </table>
      </article>
      <article class="card wide">
        <h2>Issues &amp; recommendations</h2>
        <table>
          <thead><tr><th>Severity</th><th>Issue</th><th>Recommendation</th></tr></thead>
          <tbody id="issues-table"></tbody>
        </table>
      </article>
    </div>
  </main>
  <footer>MySQL log analytics dashboard — port 8080</footer>
  <script>
    const chartDefaults = { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom' } } };

    function renderMetrics(cards) {
      document.getElementById('metric-cards').innerHTML = cards.map(function(c) {
        return '<div class="metric"><div class="label">' + c[0] + '</div><div class="value">' + c[1] + '</div></div>';
      }).join('');
    }

    async function init() {
      const data = await (await fetch('/api/charts')).json();
      const s = data.summary, m = data.meta;
      document.getElementById('subtitle').textContent =
        m.host + ' | ' + m.log_file + ' | sample ~' + m.sample_interval_seconds + 's | ' +
        (m.time_start || '') + ' to ' + (m.time_end || '');
      renderMetrics([
        ['Connections', s.total_connections + ' / ' + s.active_connections + ' active'],
        ['Pool util', s.connection_util_pct + '%'],
        ['MySQL CPU', (s.mysql_cpu_pct || 0).toFixed(1) + '%'],
        ['MySQL MEM', (s.mysql_mem_pct || 0).toFixed(1) + '%'],
        ['Load (1m)', (s.load_1m || 0).toFixed(2)],
        ['Top QPS IP', s.top_qps_ip],
        ['Est. QPS', (s.top_qps_value || 0).toFixed(4)],
        ['Issues', s.issue_count]
      ]);

      new Chart(document.getElementById('chartQps'), {
        type: 'bar',
        data: { labels: data.qps_by_ip.labels,
          datasets: [{ label: 'Avg queries/sample', data: data.qps_by_ip.avg_per_sample, backgroundColor: '#2563eb' }] },
        options: Object.assign({}, chartDefaults, { indexAxis: 'y' })
      });
      new Chart(document.getElementById('chartConn'), {
        type: 'line',
        data: { labels: data.connections.labels, datasets: [
          { label: 'Total', data: data.connections.total, borderColor: '#2563eb', tension: 0.2 },
          { label: 'Active', data: data.connections.active, borderColor: '#16a34a', tension: 0.2 }
        ]}, options: chartDefaults
      });
      new Chart(document.getElementById('chartUtil'), {
        type: 'line',
        data: { labels: data.connections.labels, datasets: [{
          label: 'Util %', data: data.connections.utilization_pct, borderColor: '#7c3aed', tension: 0.2
        }]}, options: chartDefaults
      });
      new Chart(document.getElementById('chartLoad'), {
        type: 'line',
        data: { labels: data.system.labels, datasets: [
          { label: '1m', data: data.system.load_1m, borderColor: '#2563eb', tension: 0.2 },
          { label: '5m', data: data.system.load_5m, borderColor: '#16a34a', tension: 0.2 },
          { label: '15m', data: data.system.load_15m, borderColor: '#ca8a04', tension: 0.2 }
        ]}, options: chartDefaults
      });
      new Chart(document.getElementById('chartMysql'), {
        type: 'line',
        data: { labels: data.system.labels, datasets: [
          { label: 'CPU %', data: data.system.mysql_cpu_pct, borderColor: '#dc3545', tension: 0.2 },
          { label: 'MEM %', data: data.system.mysql_mem_pct, borderColor: '#fd7e14', tension: 0.2 }
        ]}, options: chartDefaults
      });
      if (data.errors.labels.length) {
        new Chart(document.getElementById('chartErrors'), {
          type: 'bar',
          data: { labels: data.errors.labels,
            datasets: [{ label: 'Count', data: data.errors.counts, backgroundColor: '#dc3545' }] },
          options: chartDefaults
        });
      }
      if (data.issues.labels.length) {
        new Chart(document.getElementById('chartIssues'), {
          type: 'doughnut',
          data: { labels: data.issues.labels,
            datasets: [{ data: data.issues.counts, backgroundColor: ['#dc3545','#fd7e14','#ffc107','#0d6efd'] }] },
          options: chartDefaults
        });
      }
      document.getElementById('qps-table').innerHTML = data.qps_by_ip.labels.map(function(ip, i) {
        return '<tr><td>' + ip + '</td><td>' + (data.qps_by_ip.roles[i] || '') + '</td><td>' +
          data.qps_by_ip.avg_per_sample[i] + '</td><td>' + data.qps_by_ip.estimated_qps[i] + '</td><td>' +
          (data.qps_by_ip.max_per_sample ? data.qps_by_ip.max_per_sample[i] : '-') + '</td></tr>';
      }).join('');
      document.getElementById('issues-table').innerHTML = data.issues_detail.map(function(i) {
        return '<tr><td class="sev-' + i.severity + '">' + i.severity + '</td><td><strong>' +
          i.title + '</strong><br><small>' + i.description + '</small></td><td>' + i.recommendation + '</td></tr>';
      }).join('');
      const pngs = await (await fetch('/api/graphs')).json();
      if (pngs.files && pngs.files.length) {
        document.getElementById('png-section').style.display = 'block';
        document.getElementById('png-grid').innerHTML = pngs.files.map(function(f) {
          return '<figure><img src="/graphs/' + f + '" alt="' + f + '"></figure>';
        }).join('');
      }
    }
    init();
  </script>
</body>
</html>"""


def create_app(log_path: Path, graphs_dir: Optional[Path] = None) -> Flask:
    app = Flask(__name__)
    analyzer = LogAnalyzer(log_path)
    report: AnalysisReport = analyzer.analyze()
    chart_data = report_to_chart_data(report)

    gdir = graphs_dir or Path("/tmp/mysql-log-graphs")
    gdir.mkdir(parents=True, exist_ok=True)
    png_paths = generate_graph_pngs(report, gdir)
    logger.info("Generated %d PNG graphs in %s", len(png_paths), gdir)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "host": report.host})

    @app.route("/api/charts")
    def api_charts():
        return jsonify(chart_data)

    @app.route("/api/graphs")
    def api_graphs():
        files = [p.name for p in sorted(gdir.glob("*.png"))]
        return jsonify({"files": files})

    @app.route("/graphs/<path:filename>")
    def serve_graph(filename: str):
        return send_from_directory(gdir, filename)

    return app


def run_dashboard(
    log_path: Path,
    host: str = "0.0.0.0",
    port: int = 8080,
    graphs_dir: Optional[Path] = None,
) -> None:
    app = create_app(log_path, graphs_dir)
    logger.info("Dashboard at http://%s:%s", host, port)
    app.run(host=host, port=port, debug=False, threaded=True)
