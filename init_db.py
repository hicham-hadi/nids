import sqlite3

FICHIER_DB = "nids_alertes.db"

with sqlite3.connect(FICHIER_DB) as connexion:
    curseur = connexion.cursor()

    curseur.execute("""
    CREATE TABLE IF NOT EXISTS alertes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        horodatage TEXT NOT NULL,
        ip_source TEXT NOT NULL,
        port_source INTEGER,
        ip_dest TEXT NOT NULL,
        port_dest INTEGER,
        proto INTEGER,
        nb_paquets INTEGER,
        nb_octets INTEGER,
        duree REAL,
        debit REAL,
        syn INTEGER,
        ack INTEGER,
        fin INTEGER,
        rst INTEGER,
        verdict_regle TEXT,
        detail_regle TEXT,
        verdict_ml TEXT,
        confiance_ml REAL,
        anomalie_if INTEGER,
        couleur TEXT NOT NULL,
        explication TEXT
    )
    """)

    # Index pour accélérer les futures requêtes du Module 7
    curseur.execute("CREATE INDEX IF NOT EXISTS idx_alertes_horodatage ON alertes(horodatage)")
    curseur.execute("CREATE INDEX IF NOT EXISTS idx_alertes_ip_source ON alertes(ip_source)")
    curseur.execute("CREATE INDEX IF NOT EXISTS idx_alertes_couleur ON alertes(couleur)")
    curseur.execute("CREATE INDEX IF NOT EXISTS idx_alertes_verdict_regle ON alertes(verdict_regle)")

    connexion.commit()

print("Base de données créée : nids_alertes.db (avec index)")
