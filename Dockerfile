# musl uses the older kernel thread interface supported by classic Range engines.
# Keep the same pinned Python base as the independent recovery console.
FROM python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8

ARG NCT_APP_VERSION=0.14.0-dev
ARG NCT_BUILD_COMMIT=uncommitted
ARG NCT_BUILD_ID

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANALYZER_DATA_DIR=/data \
    NCT_APP_VERSION=${NCT_APP_VERSION} \
    NCT_BUILD_COMMIT=${NCT_BUILD_COMMIT} \
    NCT_BUILD_ID=${NCT_BUILD_ID}

WORKDIR /app

RUN apk add --no-cache nmap nmap-scripts fping tcpdump openssh-client util-linux

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts/qualify_kubernetes_storage.py /opt/nct/tools/qualify_kubernetes_storage.py
COPY scripts/nct_kubernetes_recovery.py /opt/nct/tools/nct_kubernetes_recovery.py
COPY scripts/probe_nct_writer_lock.py /opt/nct/tools/probe_nct_writer_lock.py
COPY scripts/nct_kubernetes_failure_evidence.py /opt/nct/tools/nct_kubernetes_failure_evidence.py
COPY scripts/nct_kubernetes_upgrade.py /opt/nct/tools/nct_kubernetes_upgrade.py
COPY scripts/nct_kubernetes_health_adapter.py /opt/nct/tools/nct_kubernetes_health_adapter.py

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
