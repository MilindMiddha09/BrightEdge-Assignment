# MySQL log analyzer — interactive dashboard on port 8080
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim AS runtime

LABEL description="MySQL log analyzer — graphs & analytics on :8080"

RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY --from=builder /root/.local /home/appuser/.local
COPY log_analyzer/ ./log_analyzer/
COPY analyze_logs.py .
COPY ["Logs-sanitised-2026-04-17_For Assesment.csv", "./"]

ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV GRAPHS_DIR=/tmp/mysql-log-graphs

RUN mkdir -p ${GRAPHS_DIR} \
    && chown -R appuser:appuser /app ${GRAPHS_DIR}

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

ENTRYPOINT ["python", "/app/analyze_logs.py"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080", "--graphs-dir", "/tmp/mysql-log-graphs", "/app/Logs-sanitised-2026-04-17_For Assesment.csv"]
