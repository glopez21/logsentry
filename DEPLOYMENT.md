# LogSentry Deployment Guide

This guide describes a centralized deployment where hosts forward logs to a LogSentry Engine (FastAPI + Postgres). It also outlines options for K8s and the future `sentryd` agent.

## Architecture (Centralized Syslog)

- Edge: rsyslog/syslog-ng on each host forwards logs to the Engine over UDP 514 or TCP 514 (optionally TLS).
- Engine: `logsentry` container exposes UDP/TCP 514 and HTTP API on 8080; stores to Postgres; detection runs in daemon mode.
- Observability: Prometheus scrapes `/metrics`; Grafana uses `/grafana/*` endpoints; health at `/health`.

## Docker Compose (Pilot)

1. Set environment variables (example):

```
export LOGSENTRY_DB_PASSWORD='change-me'
export LOGSENTRY_API_KEY='your-api-key'
```

2. Launch:

```
docker compose up -d postgres db-init
# After init completes:
docker compose up -d logsentry
```

3. Verify:
- API: `curl -H "x-api-key: $LOGSENTRY_API_KEY" http://localhost:8080/health`
- Metrics: `curl http://localhost:8080/metrics`

## rsyslog Forwarding

- UDP:
  - See `deploy/rsyslog-forward-udp.conf`; set `LOGSENTRY_HOST` to the Engine address, copy to `/etc/rsyslog.d/90-logsentry.conf`, restart rsyslog.
- TCP/TLS:
  - See `deploy/rsyslog-forward-tcp-tls.conf`; provide CA (and optionally client cert), replace `LOGSENTRY_HOST`, restart rsyslog.

You can also generate a quick config via CLI:

```
uv run main.py gen-rsyslog --host engine.example.com --port 514 --protocol tcp --format rfc5424 -o 90-logsentry.conf
```

## Parser Pinning (Overrides)

To avoid auto-detection mistakes for specific sources, configure overrides in `logsentry.yaml` under `ingest.overrides`:

```
ingest:
  overrides:
    - { source_ip: "10.0.0.10", parser: "web_access" }
    - { contains: "nginx:", parser: "web_error" }
```

Rules are evaluated in order; the first match wins. Supported parsers include: `syslog`, `rfc5424`, `ssh`, `auth`, `cloudtrail`, `web_access`, `web_error`, `auditd`, `firewall`, `json`.

Overrides are applied to both syslog (with source IP match) and file watchers (substring match only).

## API Authentication

- Set `server.api_key` in config or via `LOGSENTRY_API_KEY` env var.
- Endpoints protected when API key is set: `/ingest`, `/api/v1/query`, `/api/v1/stats`, `/lookup/*`, `/export/*`. `/metrics` and `/health` remain open for observability.
- Provide API key with header `x-api-key: <key>` or `Authorization: Bearer <key>`.

## Postgres

- Partitioned table per month with retention function. Retention is enforced at daemon start using `storage.retention_days`.
- Indexes on `timestamp`, `severity`, `source_ip`, `event_type`, `labels` GIN, and FTS on `message`.

## Kubernetes (Preview Manifests)

Example manifests under `deploy/k8s/`:
- `configmap.yaml`: base `logsentry.yaml` (without secrets).
- `secret.yaml`: DB password and API key.
- `deployment.yaml`: `logsentry` pod with UDP/TCP 514 and 8080.
- `service.yaml`: `LoadBalancer` or `NodePort` exposing UDP/TCP 514 and TCP 8080.

Adjust:
- Provide external Postgres (recommended) via `LOGSENTRY_DSN` secret/env.
- For internet-facing syslog, place a UDP/TCP LB with TLS offload (or run a sidecar terminator like stunnel).

## Helm Chart

Helm chart provided at deploy/helm/logsentry/.

Example install:

```
helm install ls ./deploy/helm/logsentry \
  --set dsn="postgresql://logsentry:logsentry@postgres:5432/logsentry" \
  --set apiKey="<SERVER_API_KEY>" \
  --set augur.enabled=true --set augur.url="http://augur:8001" --set augur.apiKey="<KEY>" \
  --set threatpulse.enabled=true --set threatpulse.url="http://threatpulse:8080" --set threatpulse.apiKey="<KEY>"
```

## Future: sentryd Agent (Optional)

- For remote VPS or restricted environments, deploy the Rust `sentryd` agent to tail files/syslog locally and forward to the hub/engine. Reuses `logsentry.yaml`-compatible config. Keep central Engine for analysis and storage.

---

For questions or to tailor this to your infra (multi-tenant, multiple environments, or air-gapped), extend these manifests and compose files accordingly.

## Fleet Bootstrap via Augur/ThreatPulse

When you have an agent framework (e.g., `sentryd` registered to Augur, or `threatpulse-agent`) that can execute remote tasks:

1. Generate a self-contained installer script locally using `logsentry bootstrap`.
2. Push it as a remote script to run on target hosts:

Augur hub (example JSON for a RunScript task):

```
POST /api/v1/agents/{agent_id}/task
{
  "type": "RunScript",
  "script": "<contents of install_logsentry.sh>",
  "interpreter": "bash",
  "timeout_secs": 600
}
```

ThreatPulse agent controller would use its own task API in a similar fashion. The agent runs the script as root to install LogSentry (systemd or Docker) and start forwarding logs.

Templates:
- deploy/tasks/augur_runscript_template.json (replace placeholders or generate a script from /bootstrap)

## Bootstrap Scripts (Self-contained)

Generate a single installer script tailored to your environment:

Systemd VM/VPS installer script:

```
uv run main.py bootstrap --mode systemd \
  --repo https://github.com/w01f/logsentry \
  --db-dsn postgresql://logsentry:logsentry@localhost:5432/logsentry \
  --augur-url http://augur:8001 --augur-api-key <KEY> \
  --threatpulse-url http://threatpulse:8080 --threatpulse-api-key <KEY> \
  -o install_logsentry.sh
chmod +x install_logsentry.sh && sudo ./install_logsentry.sh
```

Docker installer script:

```
uv run main.py bootstrap --mode docker \
  --docker-image ghcr.io/glopez21/logsentry:latest \
  --api-key <SERVER_API_KEY> \
  --db-dsn postgresql://logsentry:logsentry@localhost:5432/logsentry \
  --augur-url http://augur:8001 --augur-api-key <KEY> \
  --threatpulse-url http://threatpulse:8080 --threatpulse-api-key <KEY> \
  -o install_logsentry_docker.sh
chmod +x install_logsentry_docker.sh && sudo ./install_logsentry_docker.sh
```
