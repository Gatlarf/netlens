FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETLENS_DATA_DIR=/data \
    NETLENS_BIND=0.0.0.0:8080 \
    NMAP_PRIVILEGED=1

# Install nmap and dependencies.
# setcap grants file capabilities to the nmap binary so it can perform raw
# socket operations without running as root. Note: --no-new-privileges must
# NOT be used with file capabilities because it prevents the kernel from
# honoring the permitted capabilities set on the binary, breaking raw scans.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        iproute2 \
        libcap2-bin \
        ca-certificates && \
    setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v nmap)")" && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user and group for security.
RUN groupadd -g 10001 netlens && \
    useradd -u 10001 -g netlens -d /app -s /usr/sbin/nologin netlens && \
    mkdir -p /data && \
    chown netlens:netlens /data && \
    chmod 0750 /data

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

USER netlens

VOLUME ["/data"]

EXPOSE 8080

# Healthcheck: extracts port from NETLENS_BIND (default 8080) and checks /api/health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request, sys; port=os.environ.get('NETLENS_BIND', '0.0.0.0:8080').split(':')[-1]; url=f'http://127.0.0.1:{port}/api/health'; resp=urllib.request.urlopen(url); sys.exit(0 if resp.status==200 else 1)"

CMD ["python", "-m", "app.main"]