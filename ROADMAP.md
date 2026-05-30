# LogSentry — Roadmap

Priorities: **P0** (immediate) → **P1** (next) → **P2** (future)

---

## Phase 1: Ship the Engine (v0.3.0) ✅

| Priority | Item | Status |
|----------|------|--------|
| **P0** | Systemd unit + `install.sh` | ✅ |
| **P0** | Docker Compose (LogSentry + Postgres) | ✅ |
| **P0** | rsyslog config generator | ✅ |
| **P1** | CLI `logsentry query` subcommand | ✅ |
| **P1** | Notification backends (Discord, Slack, Telegram) | ✅ |
| **P1** | Alert rule definitions in `logsentry.yaml` | ✅ |
| **P2** | Grafana JSON datasource | ✅ |
| **P2** | WebSocket live tail | ✅ |
| **P1** | CLI `logsentry ingest` — bulk backfill | ✅ |
| **P1** | Prometheus `/metrics` endpoint | ✅ |
| **P1** | API key auth on ingest/query endpoints | ✅ |
| **P1** | Auto-register hosts on ingest | ✅ |

---

## Phase 2: Data Lifecycle (v0.4.0)

| Priority | Item | Effort | Depends On |
|----------|------|--------|------------|
| **P1** | Cold storage (archive → S3/MinIO → drop) | large | Retention working |
| **P1** | Rate limiting on syslog listener | small | — |
| **P2** | Graceful SIGHUP config reload | small | — |
| **P2** | Data compression (pgzstd or TOAST tuning) | small | — |
| **P2** | Multi-region ingestion (forwarder agent) | large | — |

**Goal:** Never lose logs. Store hot in Postgres, cold in S3, query seamlessly.

---

## Phase 3: Cross-Project Integration

| Priority | Item | Effort | Depends On |
|----------|------|--------|------------|
| **P0** | ThreatPulse consumes `logsentry.detections` | small | Shared schema |
| **P0** | AlertFlow reads `logsentry.logs` for enrichment | small | Shared schema |
| **P1** | Unified event view across LogSentry + AlertFlow + ThreatPulse | medium | — |

**Goal:** All tools natively query each other's data through Postgres.

---

## Phase 4: Polish & Scale

| Priority | Item | Effort | Depends On |
|----------|------|--------|------------|
| **P2** | Horizontal scaling (read replicas) | large | Phase 1-2 |
| **P2** | ClickHouse backend option | large | Schema abstraction |

---

## Phase 5: v0.2.0 Feature Parity (unported)

These already exist in the CLI but need engine integration:

- [ ] YARA scanning in detection pipeline
- [ ] Attack timeline reconstruction in engine
- [ ] MITRE Navigator export from stored data
- [ ] Sigma rule conversion from detections
- [ ] MISP / TheHive push on detection trigger
