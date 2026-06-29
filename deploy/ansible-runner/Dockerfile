# Fleet Terminal ansible-runner sidecar: validates/lints (and, later, runs)
# Ansible playbooks on behalf of the backend. Kept separate from the Go backend
# so Python + Ansible never bloat or run in the main API container.
FROM python:3.12-slim

# openssh-client is needed for Phase 2 execution (ProxyJump through the Fleet
# jump host); harmless to include now.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py

# Run as an unprivileged user; the runner never needs root.
RUN useradd --create-home --uid 10001 runner
USER runner

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
