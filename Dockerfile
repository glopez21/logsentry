# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL maintainer="w01f"
LABEL description="LogSentry — Security Log Engine"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install uv --quiet && \
    rm -rf /app/.venv && \
    uv sync --frozen --no-dev --python /usr/local/bin/python --extra server --extra augur

# Overlay vendored augur-client fix (auth_token handling on register/heartbeat).
# Upstream 99676bd is missing this; the pin is not updated in uv.lock.
COPY deploy/vendor/augur_client/client.py /app/.venv/lib/python3.12/site-packages/augur_client/client.py

# Entrypoint handles config generation at runtime
COPY deploy/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Syslog, API, and health
EXPOSE 514/udp 514/tcp 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["daemon"]
