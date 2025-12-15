FROM python:3.11-slim AS base

ARG SYFT_VERSION="v1.38.2"
ARG TRIVY_VERSION="v0.68.1"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_RUN_HOST=0.0.0.0 \
    PORT=8080 \
    TRIVY_SKIP_DB_UPDATE=true \
    TRIVY_NO_PROGRESS=true \
    SBOM_OUTPUT_DIR=/tmp/sboms

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin "${SYFT_VERSION}" && \
    curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
    sh -s -- -b /usr/local/bin "${TRIVY_VERSION}"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--timeout", "600", "--access-logfile", "-", "app:app"]
