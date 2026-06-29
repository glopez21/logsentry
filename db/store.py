"""PostgreSQL storage layer with sync (psycopg2) and async (asyncpg) support."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.pool
import psycopg2.extras

logger = logging.getLogger("logsentry.db")


try:
    import asyncpg
except ImportError:
    asyncpg = None  # type: ignore[assignment]


class LogStore:
    """PostgreSQL-backed log storage with connection pooling."""

    def __init__(
        self,
        dsn: str,
        min_conn: int = 2,
        max_conn: int = 10,
        batch_size: int = 500,
        flush_interval: float = 5.0,
    ):
        self.dsn = dsn
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._pool: psycopg2.pool.ThreadedConnectionPool | None = None
        self._batch: list[tuple] = []

    # ── Connection lifecycle ──────────────────────────────────────

    def connect(self) -> None:
        """Initialize the connection pool."""
        self._pool = psycopg2.pool.ThreadedConnectionPool(
            maxconn=self.max_conn,
            minconn=self.min_conn,
            dsn=self.dsn,
        )
        logger.info(
            "Connected to Postgres (pool=%s-%s)", self.min_conn, self.max_conn
        )

    @property
    def max_conn(self) -> int:
        return self._pool.maxconn if self._pool else 10

    @property
    def min_conn(self) -> int:
        return self._pool.minconn if self._pool else 2

    def close(self) -> None:
        """Close all connections in the pool."""
        if self._pool:
            self._pool.closeall()
            self._pool = None
            logger.info("Postgres pool closed")

    def get_conn(self):
        """Get a connection from the pool."""
        if not self._pool:
            raise RuntimeError("LogStore not connected. Call connect() first.")
        return self._pool.getconn()

    def put_conn(self, conn) -> None:
        """Return a connection to the pool."""
        if self._pool:
            self._pool.putconn(conn)

    # ── Schema ────────────────────────────────────────────────────

    def init_schema(self) -> None:
        """Run all schema migrations."""
        from db.schema import get_all_sql

        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                for block in get_all_sql():
                    cur.execute(block)
            conn.commit()
            logger.info("Schema initialized")
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)

    def ensure_partition(self, ts: datetime) -> None:
        """Create partition for the given timestamp if it doesn't exist."""
        suffix = ts.strftime("%Y_%m")
        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT logsentry.create_partition(%s)", (suffix,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)

    def enforce_retention(self, days: int = 90) -> int:
        """Drop partitions older than `days`."""
        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT logsentry.drop_old_partitions(%s)", (days,))
                dropped: int = cur.fetchone()[0]
            conn.commit()
            logger.info("Retention enforced: dropped %s partitions", dropped)
            return dropped
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)

    # ── Insert ────────────────────────────────────────────────────

    def insert_log(
        self,
        timestamp: datetime,
        message: str,
        labels: dict | None = None,
        source: str = "syslog",
        format: str = "syslog",
        host: str = "",
        source_ip: str = "",
        user_name: str = "",
        event_type: str = "",
        severity: str = "info",
        parsed: dict | None = None,
        mitre_id: list[str] | None = None,
        raw_message: str | None = None,
    ) -> int:
        """Insert a single log entry, returning the ID."""
        self.ensure_partition(timestamp)
        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO logsentry.logs
                        (timestamp, labels, source, format, parsed, message,
                         severity, mitre_id, host, source_ip, user_name,
                         event_type, raw_message)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        timestamp,
                        json.dumps(labels or {}),
                        source,
                        format,
                        json.dumps(parsed) if parsed else None,
                        message,
                        severity,
                        mitre_id or [],
                        host,
                        source_ip,
                        user_name,
                        event_type,
                        raw_message,
                    ),
                )
                row_id: int = cur.fetchone()[0]
            conn.commit()
            return row_id
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)

    def insert_logs_batch(self, records: list[dict]) -> int:
        """Batch insert multiple log records.

        Each record should have keys matching insert_log() params.
        Returns count of inserted rows.
        """
        if not records:
            return 0

        # Ensure partitions exist for all dates
        for r in records:
            ts = r.get("timestamp")
            if ts:
                self.ensure_partition(ts)

        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                rows = []
                for r in records:
                    ts = r.get("timestamp", datetime.now(timezone.utc))
                    rows.append((
                        ts,
                        json.dumps(r.get("labels", {})),
                        r.get("source", "syslog"),
                        r.get("format", "syslog"),
                        json.dumps(r["parsed"]) if r.get("parsed") else None,
                        r.get("message", ""),
                        r.get("severity", "info"),
                        r.get("mitre_id", []),
                        r.get("host", ""),
                        r.get("source_ip", ""),
                        r.get("user_name", ""),
                        r.get("event_type", ""),
                        r.get("raw_message", ""),
                    ))

                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO logsentry.logs
                        (timestamp, labels, source, format, parsed, message,
                         severity, mitre_id, host, source_ip, user_name,
                         event_type, raw_message)
                    VALUES %s
                    """,
                    rows,
                    template="(%s, %s::jsonb, %s, %s, %s::jsonb, %s, %s, %s::text[], %s, %s, %s, %s, %s)",
                )
                inserted: int = cur.rowcount or 0
            conn.commit()
            return inserted
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)

    # ── Query ─────────────────────────────────────────────────────

    def query(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        labels: dict | None = None,
        severity: str | None = None,
        source_ip: str | None = None,
        event_type: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Query logs with filters. Returns list of dicts."""
        conditions: list[str] = []
        params: list[Any] = []

        if since:
            conditions.append("timestamp >= %s")
            params.append(since)
        if until:
            conditions.append("timestamp <= %s")
            params.append(until)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if source_ip:
            conditions.append("source_ip = %s")
            params.append(source_ip)
        if event_type:
            conditions.append("event_type = %s")
            params.append(event_type)
        if labels:
            conditions.append("labels @> %s")
            params.append(json.dumps(labels))
        if search:
            conditions.append(
                "to_tsvector('english', coalesce(message, '')) @@ plainto_tsquery('english', %s)"
            )
            params.append(search)

        where = " AND ".join(conditions) if conditions else "TRUE"

        sql = f"""
            SELECT id, timestamp, labels, source, format, parsed, message,
                   severity, mitre_id, host, source_ip, user_name, event_type
            FROM logsentry.logs
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])

        conn = self.get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
            return [dict(r) for r in rows]
        except Exception:
            raise
        finally:
            self.put_conn(conn)

    def insert_detection(
        self,
        log_id: int | None,
        rule_name: str,
        severity: str,
        description: str,
        rule_type: str = "builtin",
        mitre_id: str | None = None,
        mitre_tactic: str | None = None,
        raw_data: dict | None = None,
    ) -> int:
        """Insert a detection result."""
        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO logsentry.detections
                        (log_id, rule_name, rule_type, severity, mitre_id,
                         mitre_tactic, description, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        log_id,
                        rule_name,
                        rule_type,
                        severity,
                        mitre_id,
                        mitre_tactic,
                        description,
                        json.dumps(raw_data) if raw_data else None,
                    ),
                )
                det_id: int = cur.fetchone()[0]
            conn.commit()
            return det_id
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)

    def get_threat_intel(self, ip: str) -> dict | None:
        """Get cached threat intel for an IP if not expired."""
        conn = self.get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT data FROM logsentry.threat_intel_cache
                    WHERE ip = %s
                      AND updated_at + (ttl_seconds * interval '1 second') > now()
                    """,
                    (ip,),
                )
                row = cur.fetchone()
            return json.loads(row["data"]) if row else None  # type: ignore[no-any-return]
        except Exception:
            return None
        finally:
            self.put_conn(conn)

    def set_threat_intel(self, ip: str, data: dict, ttl: int = 86400) -> None:
        """Cache threat intel data for an IP."""
        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO logsentry.threat_intel_cache (ip, data, ttl_seconds)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (ip) DO UPDATE
                        SET data = EXCLUDED.data,
                            updated_at = now(),
                            ttl_seconds = EXCLUDED.ttl_seconds
                    """,
                    (ip, json.dumps(data), ttl),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)

    def get_stats(self) -> dict:
        """Get ingestion and storage statistics."""
        conn = self.get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT count(*) AS total FROM logsentry.logs")
                total = cur.fetchone()["total"]
                cur.execute(
                    """
                    SELECT severity, count(*) AS cnt
                    FROM logsentry.logs
                    GROUP BY severity
                    """
                )
                by_severity = {r["severity"]: r["cnt"] for r in cur.fetchall()}
                cur.execute(
                    """
                    SELECT count(*) AS total_detections
                    FROM logsentry.detections
                    """
                )
                detections = cur.fetchone()["total_detections"]
                cur.execute(
                    """
                    SELECT count(*) AS total_detections
                    FROM logsentry.detections
                    WHERE created_at >= now() - interval '24 hours'
                    """
                )
                detections_24h = cur.fetchone()["total_detections"]
            return {
                "total_logs": total,
                "by_severity": by_severity,
                "total_detections": detections,
                "detections_24h": detections_24h,
            }
        except Exception:
            return {"error": "unable to get stats"}
        finally:
            self.put_conn(conn)

    # ── Host Registration ──────────────────────────────────────────

    def upsert_host(self, hostname: str, ip_address: str = "", role: str = "", labels: dict | None = None) -> None:
        """Register or update a host in shared.hosts."""
        conn = self.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO shared.hosts (hostname, ip_address, role, labels)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (hostname) DO UPDATE
                        SET ip_address = EXCLUDED.ip_address,
                            role = CASE WHEN EXCLUDED.role != '' THEN EXCLUDED.role ELSE shared.hosts.role END,
                            labels = shared.hosts.labels || EXCLUDED.labels,
                            updated_at = now()
                    """,
                    (hostname, ip_address, role, json.dumps(labels or {})),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.put_conn(conn)


class AsyncLogStore:
    """Async PostgreSQL storage using asyncpg. Mirrors LogStore interface."""

    def __init__(
        self,
        dsn: str,
        min_conn: int = 2,
        max_conn: int = 10,
        batch_size: int = 500,
        flush_interval: float = 5.0,
    ):
        if asyncpg is None:
            raise RuntimeError("asyncpg not installed. Install with: pip install 'logsentry[async]'")
        self.dsn = dsn
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(
            dsn=self.dsn,
            min_size=self.min_conn,
            max_size=self.max_conn,
        )
        logger.info("Connected to Postgres (async pool=%s-%s)", self.min_conn, self.max_conn)

    @property
    def min_conn(self) -> int:
        return self._pool._min_size if self._pool else 2  # type: ignore[union-attr]

    @property
    def max_conn(self) -> int:
        return self._pool._max_size if self._pool else 10  # type: ignore[union-attr]

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("Async Postgres pool closed")

    async def init_schema(self) -> None:
        from db.schema import get_all_sql
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            for block in get_all_sql():
                await conn.execute(block)
        logger.info("Async schema initialized")

    async def ensure_partition(self, ts: datetime) -> None:
        suffix = ts.strftime("%Y_%m")
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute("SELECT logsentry.create_partition($1)", suffix)

    async def enforce_retention(self, days: int = 90) -> int:
        if not self._pool:
            return 0
        async with self._pool.acquire() as conn:
            row = await conn.fetchval("SELECT logsentry.drop_old_partitions($1)", days)
            return row or 0

    async def insert_log(self, **kwargs: Any) -> int:
        ts = kwargs.get("timestamp", datetime.now(timezone.utc))
        await self.ensure_partition(ts)
        if not self._pool:
            raise RuntimeError("Not connected")
        async with self._pool.acquire() as conn:
            row_id = await conn.fetchval(
                """
                INSERT INTO logsentry.logs
                    (timestamp, labels, source, format, parsed, message,
                     severity, mitre_id, host, source_ip, user_name,
                     event_type, raw_message)
                VALUES ($1, $2::jsonb, $3, $4, $5::jsonb, $6, $7, $8::text[], $9, $10, $11, $12, $13)
                RETURNING id
                """,
                ts,
                json.dumps(kwargs.get("labels", {})),
                kwargs.get("source", "syslog"),
                kwargs.get("format", "syslog"),
                json.dumps(kwargs["parsed"]) if kwargs.get("parsed") else None,
                kwargs.get("message", ""),
                kwargs.get("severity", "info"),
                kwargs.get("mitre_id", []),
                kwargs.get("host", ""),
                kwargs.get("source_ip", ""),
                kwargs.get("user_name", ""),
                kwargs.get("event_type", ""),
                kwargs.get("raw_message", ""),
            )
            return int(row_id) if row_id is not None else 0

    async def insert_logs_batch(self, records: list[dict]) -> int:
        if not records or not self._pool:
            return 0

        seen_months: set[str] = set()
        for r in records:
            ts = r.get("timestamp")
            if ts:
                suffix = ts.strftime("%Y_%m")
                if suffix not in seen_months:
                    await self.ensure_partition(ts)
                    seen_months.add(suffix)

        async with self._pool.acquire() as conn:
            rows = []
            for r in records:
                ts = r.get("timestamp", datetime.now(timezone.utc))
                rows.append((
                    ts,
                    json.dumps(r.get("labels", {})),
                    r.get("source", "syslog"),
                    r.get("format", "syslog"),
                    json.dumps(r["parsed"]) if r.get("parsed") else None,
                    r.get("message", ""),
                    r.get("severity", "info"),
                    r.get("mitre_id", []),
                    r.get("host", ""),
                    r.get("source_ip", ""),
                    r.get("user_name", ""),
                    r.get("event_type", ""),
                    r.get("raw_message", ""),
                ))
            await conn.executemany(
                """
                INSERT INTO logsentry.logs
                    (timestamp, labels, source, format, parsed, message,
                     severity, mitre_id, host, source_ip, user_name,
                     event_type, raw_message)
                VALUES ($1, $2::jsonb, $3, $4, $5::jsonb, $6, $7, $8::text[], $9, $10, $11, $12, $13)
                """,
                rows,
            )
            return len(rows)

    async def query(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
        labels: dict | None = None,
        severity: str | None = None,
        source_ip: str | None = None,
        event_type: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        if not self._pool:
            return []
        conditions: list[str] = []
        params: list[Any] = []
        idx = 1

        if since:
            conditions.append(f"timestamp >= ${idx}")
            params.append(since)
            idx += 1
        if until:
            conditions.append(f"timestamp <= ${idx}")
            params.append(until)
            idx += 1
        if severity:
            conditions.append(f"severity = ${idx}")
            params.append(severity)
            idx += 1
        if source_ip:
            conditions.append(f"source_ip = ${idx}")
            params.append(source_ip)
            idx += 1
        if event_type:
            conditions.append(f"event_type = ${idx}")
            params.append(event_type)
            idx += 1
        if labels:
            conditions.append(f"labels @> ${idx}::jsonb")
            params.append(json.dumps(labels))
            idx += 1
        if search:
            conditions.append(
                f"to_tsvector('english', coalesce(message, '')) @@ plainto_tsquery('english', ${idx})"
            )
            params.append(search)
            idx += 1

        where = " AND ".join(conditions) if conditions else "TRUE"
        params.append(limit)
        params.append(offset)

        sql = f"""
            SELECT id, timestamp, labels, source, format, parsed, message,
                   severity, mitre_id, host, source_ip, user_name, event_type
            FROM logsentry.logs
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ${idx} OFFSET ${idx + 1}
        """

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
            return [dict(r) for r in rows]

    async def insert_detection(self, **kwargs: Any) -> int:
        if not self._pool:
            raise RuntimeError("Not connected")
        async with self._pool.acquire() as conn:
            row = await conn.fetchval(
                """
                INSERT INTO logsentry.detections
                    (log_id, rule_name, rule_type, severity, mitre_id,
                     mitre_tactic, description, raw_data)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                RETURNING id
                """,
                kwargs.get("log_id"),
                kwargs.get("rule_name", ""),
                kwargs.get("rule_type", "builtin"),
                kwargs.get("severity", "medium"),
                kwargs.get("mitre_id"),
                kwargs.get("mitre_tactic"),
                kwargs.get("description", ""),
                json.dumps(kwargs["raw_data"]) if kwargs.get("raw_data") else None,
            )
            return int(row) if row is not None else 0

    async def get_threat_intel(self, ip: str) -> dict | None:
        if not self._pool:
            return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT data FROM logsentry.threat_intel_cache
                WHERE ip = $1
                  AND updated_at + (ttl_seconds * interval '1 second') > now()
                """,
                ip,
            )
            return json.loads(row["data"]) if row else None

    async def set_threat_intel(self, ip: str, data: dict, ttl: int = 86400) -> None:
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO logsentry.threat_intel_cache (ip, data, ttl_seconds)
                VALUES ($1, $2::jsonb, $3)
                ON CONFLICT (ip) DO UPDATE
                    SET data = EXCLUDED.data, updated_at = now(), ttl_seconds = EXCLUDED.ttl_seconds
                """,
                ip,
                json.dumps(data),
                ttl,
            )

    async def get_stats(self) -> dict:
        if not self._pool:
            return {"error": "not connected"}
        async with self._pool.acquire() as conn:
            total = await conn.fetchval("SELECT count(*) FROM logsentry.logs")
            sev_rows = await conn.fetch(
                "SELECT severity, count(*) AS cnt FROM logsentry.logs GROUP BY severity"
            )
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}
            detections = await conn.fetchval("SELECT count(*) FROM logsentry.detections")
            detections_24h = await conn.fetchval(
                "SELECT count(*) FROM logsentry.detections WHERE created_at >= now() - interval '24 hours'"
            )
            return {
                "total_logs": total,
                "by_severity": by_severity,
                "total_detections": detections,
                "detections_24h": detections_24h,
            }

    async def upsert_host(self, hostname: str, ip_address: str = "", role: str = "", labels: dict | None = None) -> None:
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO shared.hosts (hostname, ip_address, role, labels)
                VALUES ($1, $2, $3, $4::jsonb)
                ON CONFLICT (hostname) DO UPDATE
                    SET ip_address = EXCLUDED.ip_address,
                        role = CASE WHEN EXCLUDED.role != '' THEN EXCLUDED.role ELSE shared.hosts.role END,
                        labels = shared.hosts.labels || EXCLUDED.labels,
                        updated_at = now()
                """,
                hostname,
                ip_address,
                role,
                json.dumps(labels or {}),
            )
