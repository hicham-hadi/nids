import sqlite3
from datetime import datetime

FICHIER_DB = "nids_alertes.db"


def enregistrer_alerte(ip_src, port_src, ip_dst, port_dst, proto, fl,
                       verdict_regle, detail_regle,
                       verdict_ml, confiance_ml, anomalie_if,
                       couleur, explication):
    """Enregistre un verdict complet (avec toutes les features ML) dans la base."""
    with sqlite3.connect(FICHIER_DB) as connexion:
        curseur = connexion.cursor()
        curseur.execute("""
            INSERT INTO alertes (
                horodatage, ip_source, port_source, ip_dest, port_dest, proto,
                nb_paquets, nb_octets, duree, debit, syn, ack, fin, rst,
                verdict_regle, detail_regle,
                verdict_ml, confiance_ml, anomalie_if,
                couleur, explication
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(timespec="seconds"),
            ip_src, port_src, ip_dst, port_dst, proto,
            fl["nb_paquets"], fl["nb_octets"],
            fl["dernier_ts"] - fl["premier_ts"],
            fl["nb_octets"] / (fl["dernier_ts"] - fl["premier_ts"]) if (fl["dernier_ts"] - fl["premier_ts"]) > 0 else fl["nb_octets"],
            fl["syn"], fl["ack"], fl["fin"], fl["rst"],
            verdict_regle, detail_regle,
            verdict_ml, confiance_ml, int(anomalie_if),
            couleur, explication
        ))
        connexion.commit()
