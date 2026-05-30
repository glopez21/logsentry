# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL maintainer="w01f"
LABEL description="LogSentry — Security Log Engine"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

COPY uv.lock pyproject.toml ./

RUN pip install uv --quiet && \
    uv sync --frozen --no-dev --extra server 2>&1 | tail -1

COPY . .

# Entrypoint handles config generation at runtime
COPY deploy/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Syslog, API, and health
EXPOSE 514/udp 514/tcp 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["daemon"]
