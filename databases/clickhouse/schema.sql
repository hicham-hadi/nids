-- ============================================================
-- NIDS S1 — ClickHouse schema
-- Database: nids   Table: alertes (MergeTree, partitioned by day)
-- ============================================================

CREATE DATABASE IF NOT EXISTS nids;

CREATE TABLE IF NOT EXISTS nids.alertes (
    id             UInt64,
    horodatage     DateTime,
    ip_source      String,
    port_source    UInt16,
    ip_dest        String,
    port_dest      UInt16,
    proto          UInt8,
    nb_paquets     UInt32,
    nb_octets      UInt64,
    duree          Float64,
    debit          Float64,
    syn            UInt16,
    ack            UInt16,
    fin            UInt16,
    rst            UInt16,
    verdict_regle  LowCardinality(String),
    detail_regle   String,
    verdict_ml     LowCardinality(String),
    confiance_ml   Float32,
    anomalie_if    Int8,
    couleur        LowCardinality(String),
    explication    String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(horodatage)
ORDER BY (horodatage, ip_source, couleur)
TTL horodatage + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- A projection that pre-sorts by `couleur, horodatage` so severity
-- filters stay fast without scanning every chunk.
ALTER TABLE nids.alertes
    ADD PROJECTION IF NOT EXISTS p_by_couleur (
        SELECT * ORDER BY couleur, horodatage
    );

-- A materialized view that keeps per-minute roll-ups.
CREATE MATERIALIZED VIEW IF NOT EXISTS nids.alertes_1min
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, couleur)
AS
SELECT toStartOfMinute(horodatage) AS bucket,
       couleur,
       count() AS nombre
FROM nids.alertes
GROUP BY bucket, couleur;
