# MySQL Log Analytics (BrightEdge Assignment)

Python analyzer for MySQL operational logs with an interactive dashboard on **port 8080**.

## Quick start

```bash
cd brightedge-assignment
pip install -r requirements.txt
python analyze_logs.py
# Open http://localhost:8080
```

## Docker (port 8080)

```bash
docker build -t your-dockerhub-user/mysql-log-analyzer .
docker run --rm -p 8080:8080 your-dockerhub-user/mysql-log-analyzer
# Open http://localhost:8080
```

Or with compose:

```bash
docker compose up --build
```

## CLI

| Command | Description |
|---------|-------------|
| `python analyze_logs.py` | Start dashboard on :8080 |
| `python analyze_logs.py report` | Text summary (QPS drivers, issues) |
| `python analyze_logs.py graphs -o graphs/` | Export PNG charts |

## Dashboard

- **/** — Charts: QPS by IP, connections, load, MySQL CPU/MEM, errors, issues table
- **/health** — Health check
- **/api/charts** — JSON chart data
