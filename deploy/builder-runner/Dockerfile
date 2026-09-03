# syntax=docker/dockerfile:1

# Blackfriars builder-runner: the only container that touches the Docker socket.
#
# It carries no auth stack, no database driver and no web assets, because it is
# not a control plane -- it is the privileged half of the build path, kept in
# its own blast radius. Everything it has is something a build actually needs.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app DOCKER_BUILDKIT=1

# Docker CLI + buildx + compose, so builds can be driven as sibling containers.
# buildx/BuildKit is what makes cross-architecture builds work at all -- an
# amd64 image built from an arm64 host and vice versa.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

# iproute2: the host's NICs are enumerated by running this same image as a
# throwaway container in the host network namespace (see list_interfaces), so an
# operator picks a provisioning interface from a list instead of typing one.
RUN apt-get update && apt-get install -y --no-install-recommends curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py config.py jobs.py orchestrator.py ./

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
