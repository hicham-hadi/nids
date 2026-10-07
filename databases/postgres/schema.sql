-- ============================================================
-- NIDS S1 — PostgreSQL schema
-- Database: nids_alertes   User: nids
-- ============================================================

CREATE TABLE IF NOT EXISTS alertes (
    id             BIGSERIAL   PRIMARY KEY,
    horodatage     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_source      INET        NOT NULL,
    port_source    INTEGER,
    ip_dest        INET        NOT NULL,
    port_dest      INTEGER,
    proto          SMALLINT,
    nb_paquets     INTEGER,
    nb_octets      BIGINT,
    duree          DOUBLE PRECISION,
    debit          DOUBLE PRECISION,
    syn            INTEGER,
    ack            INTEGER,
    fin            INTEGER,
    rst            INTEGER,
    verdict_regle  TEXT,
    detail_regle   TEXT,
    verdict_ml     TEXT,
    confiance_ml   DOUBLE PRECISION,
    anomalie_if    SMALLINT,
    couleur        TEXT        CHECK (couleur IN ('VERT','ORANGE','ROUGE')),
    explication    TEXT
);

-- Indexes tailored to the dashboard queries.
CREATE INDEX IF NOT EXISTS idx_alertes_time
    ON alertes (horodatage DESC);
CREATE INDEX IF NOT EXISTS idx_alertes_ip_src
    ON alertes (ip_source);
CREATE INDEX IF NOT EXISTS idx_alertes_couleur
    ON alertes (couleur);
CREATE INDEX IF NOT EXISTS idx_alertes_verdict_regle
    ON alertes (verdict_regle);
CREATE INDEX IF NOT EXISTS idx_alertes_verdict_ml
    ON alertes (verdict_ml);
CREATE INDEX IF NOT EXISTS idx_alertes_time_couleur
    ON alertes (horodatage DESC, couleur);

-- Convenience view used by the dashboard's temporal chart.
CREATE OR REPLACE VIEW v_alertes_minute AS
SELECT date_trunc('minute', horodatage) AS minute,
       couleur,
       COUNT(*) AS nombre
FROM alertes
GROUP BY 1, 2
ORDER BY 1;

-- Role grants.
GRANT ALL ON ALL TABLES    IN SCHEMA public TO nids;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO nids;
