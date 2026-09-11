FROM python:3.12-slim

ARG NCT_APP_VERSION=0.12.0-dev
ARG NCT_BUILD_COMMIT=uncommitted
ARG NCT_BUILD_ID

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANALYZER_DATA_DIR=/data \
    NCT_APP_VERSION=${NCT_APP_VERSION} \
    NCT_BUILD_COMMIT=${NCT_BUILD_COMMIT} \
    NCT_BUILD_ID=${NCT_BUILD_ID}

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap fping tcpdump openssh-client util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
