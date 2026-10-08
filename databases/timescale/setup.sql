-- ============================================================
-- NIDS S1 — TimescaleDB enhancements on top of the PostgreSQL
-- `alertes` table. Run AFTER postgres/schema.sql.
-- ============================================================

CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Promote `alertes` to a hypertable partitioned by horodatage.
-- `if_not_exists => TRUE` makes it safe to re-run.
SELECT create_hypertable(
    'alertes', 'horodatage',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

-- ------------------------------------------------------------
-- Continuous aggregate — events per minute, per severity.
-- The dashboard's time-series chart reads from this view;
-- it's updated incrementally in the background, so even on
-- a 100M-row table the query stays <10 ms.
-- ------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS alertes_1min
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 minute', horodatage) AS bucket,
       couleur,
       COUNT(*) AS nombre
FROM alertes
GROUP BY bucket, couleur
WITH NO DATA;

SELECT add_continuous_aggregate_policy('alertes_1min',
    start_offset      => INTERVAL '2 hours',
    end_offset        => INTERVAL '1 minute',
    schedule_interval => INTERVAL '1 minute',
    if_not_exists     => TRUE);

-- ------------------------------------------------------------
-- Continuous aggregate — events per hour, per severity.
-- Fuels the Statistics and Network Traffic 24-hour views.
-- ------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS alertes_1hour
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 hour', horodatage) AS bucket,
       couleur,
       COUNT(*) AS nombre
FROM alertes
GROUP BY bucket, couleur
WITH NO DATA;

SELECT add_continuous_aggregate_policy('alertes_1hour',
    start_offset      => INTERVAL '1 day',
    end_offset        => INTERVAL '1 hour',
    schedule_interval => INTERVAL '10 minutes',
    if_not_exists     => TRUE);

-- ------------------------------------------------------------
-- Compression — rows older than 7 days are compressed ~10x.
-- Writes still work; reads stay fast.
-- ------------------------------------------------------------
ALTER TABLE alertes SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'couleur, verdict_regle',
    timescaledb.compress_orderby   = 'horodatage DESC'
);

SELECT add_compression_policy('alertes', INTERVAL '7 days', if_not_exists => TRUE);

-- ------------------------------------------------------------
-- Retention — automatically drop chunks older than 90 days.
-- Comment this out if you want to keep forever.
-- ------------------------------------------------------------
SELECT add_retention_policy('alertes', INTERVAL '90 days', if_not_exists => TRUE);
