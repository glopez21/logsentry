"""PostgreSQL schema definitions and migration runner."""

SCHEMA_SQL = """
-- 1. Create extension for full-text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 2. Create schemas for all tools (idempotent)
CREATE SCHEMA IF NOT EXISTS logsentry;
CREATE SCHEMA IF NOT EXISTS alertflow;
CREATE SCHEMA IF NOT EXISTS threatpulse;
CREATE SCHEMA IF NOT EXISTS shared;

-- 3. Core logs table (partitioned by day)
CREATE TABLE IF NOT EXISTS logsentry.logs (
    id          BIGSERIAL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    labels      JSONB NOT NULL DEFAULT '{}',
    source      TEXT,
    format      TEXT,
    parsed      JSONB,
    message     TEXT,
    severity    TEXT DEFAULT 'info',
    mitre_id    TEXT[] DEFAULT '{}',
    host        TEXT,
    source_ip   TEXT,
    user_name   TEXT,
    event_type  TEXT,
    raw_message TEXT,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- 4. Create partitions for current + next 2 months
SELECT logsentry.create_partition(to_char(now(), 'YYYY_MM'));
SELECT logsentry.create_partition(to_char(now() + interval '1 month', 'YYYY_MM'));
SELECT logsentry.create_partition(to_char(now() + interval '2 months', 'YYYY_MM'));

-- 5. Indexes on the parent (propagate to partitions)
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logsentry.logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_labels ON logsentry.logs USING GIN (labels);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logsentry.logs (severity);
CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logsentry.logs (source_ip);
CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logsentry.logs (event_type);
CREATE INDEX IF NOT EXISTS idx_logs_mitre ON logsentry.logs USING GIN (mitre_id);

-- 6. Full-text search index
CREATE INDEX IF NOT EXISTS idx_logs_fts ON logsentry.logs
    USING GIN (to_tsvector('english', coalesce(message, '')));

-- 7. Detections table — results of each detection pipeline run
CREATE TABLE IF NOT EXISTS logsentry.detections (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    log_id      BIGINT,
    rule_name   TEXT NOT NULL,
    rule_type   TEXT NOT NULL DEFAULT 'builtin',
    severity    TEXT NOT NULL DEFAULT 'medium',
    mitre_id    TEXT,
    mitre_tactic TEXT,
    description TEXT,
    raw_data    JSONB,
    suppressed  BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_detections_created ON logsentry.detections (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON logsentry.detections (severity);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON logsentry.detections (rule_name);

-- 8. Threat intelligence cache
CREATE TABLE IF NOT EXISTS logsentry.threat_intel_cache (
    ip          TEXT PRIMARY KEY,
    data        JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ttl_seconds INT NOT NULL DEFAULT 86400
);
CREATE INDEX IF NOT EXISTS idx_threat_intel_expires
    ON logsentry.threat_intel_cache (updated_at + (ttl_seconds * interval '1 second'));

-- 9. Shared cross-project tables
CREATE TABLE IF NOT EXISTS shared.hosts (
    id          SERIAL PRIMARY KEY,
    hostname    TEXT UNIQUE NOT NULL,
    ip_address  TEXT,
    role        TEXT,
    labels      JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shared.apps (
    id          SERIAL PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    host_id     INT REFERENCES shared.hosts(id),
    port        INT,
    labels      JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT now()
);
"""


PARTITION_CREATE_FN = """
CREATE OR REPLACE FUNCTION logsentry.create_partition(suffix TEXT)
RETURNS void AS $$
DECLARE
    partition_name TEXT := 'logsentry.logs_' || suffix;
    year_month TEXT := suffix;
    year INT := substring(year_month FROM 1 FOR 4)::INT;
    month INT := substring(year_month FROM 6 FOR 2)::INT;
    start_date DATE := make_date(year, month, 1);
    end_date DATE := make_date(year, month + 1, 1);
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class WHERE relname = 'logs_' || suffix
    ) THEN
        EXECUTE format(
            'CREATE TABLE %s PARTITION OF logsentry.logs
             FOR VALUES FROM (%L) TO (%L)',
            partition_name,
            start_date::TEXT,
            end_date::TEXT
        );
        RAISE NOTICE 'Created partition: %', partition_name;
    END IF;
END;
$$ LANGUAGE plpgsql;
"""


DROP_PARTITION_FN = """
CREATE OR REPLACE FUNCTION logsentry.drop_partition(suffix TEXT)
RETURNS void AS $$
DECLARE
    partition_name TEXT := 'logsentry.logs_' || suffix;
BEGIN
    EXECUTE format('DROP TABLE IF EXISTS %s CASCADE', partition_name);
    RAISE NOTICE 'Dropped partition: %', partition_name;
END;
$$ LANGUAGE plpgsql;
"""


RETENTION_FN = """
CREATE OR REPLACE FUNCTION logsentry.drop_old_partitions(retention_days INT DEFAULT 90)
RETURNS INT AS $$
DECLARE
    rec RECORD;
    cutoff_date DATE := now()::DATE - retention_days;
    year_month TEXT;
    partition_date DATE;
    dropped INT := 0;
BEGIN
    FOR rec IN
        SELECT inhrelid::regclass::TEXT AS partition_name
        FROM pg_inherits
        WHERE inhparent = 'logsentry.logs'::regclass
    LOOP
        year_month := replace(rec.partition_name, 'logs_', '');
        CONTINUE WHEN year_month !~ '^[0-9]{4}_[0-9]{2}$';
        partition_date := to_date(year_month || '_01', 'YYYY_MM_DD');
        IF partition_date < cutoff_date THEN
            EXECUTE format('DROP TABLE IF EXISTS %s CASCADE', rec.partition_name);
            dropped := dropped + 1;
        END IF;
    END LOOP;
    RETURN dropped;
END;
$$ LANGUAGE plpgsql;
"""


# Default labels added to every ingested log
DEFAULT_LABELS = {
    "service": "logsentry",
    "source": "syslog",
}


def get_all_sql() -> list[str]:
    """Return all SQL statements to initialize the schema."""
    return [
        PARTITION_CREATE_FN,
        SCHEMA_SQL,
        DROP_PARTITION_FN,
        RETENTION_FN,
    ]
