from scapy.all import sniff, IP, TCP, UDP
import joblib
import time
import numpy as np
import pandas as pd

# ============================================================
#  MODULE 4 (temps réel) — Détection par Machine Learning
#  Suivi de connexion + délai de grâce après FIN/RST
#  (évite qu'un paquet de clôture tardif crée un flux fantôme)
# ============================================================

print("Chargement des modèles...")
modele = joblib.load("modele_ids.joblib")
encodeur = joblib.load("encodeur.joblib")
scaler = joblib.load("scaler.joblib")
detecteur = joblib.load("detecteur_anomalies.joblib")
print("Les 4 modèles sont chargés avec succès !\n")

CIBLE = "192.168.211.50"
SEUIL_CONFIANCE = 80
TIMEOUT_INACTIVITE = 6
TIMEOUT_APRES_FERMETURE = 2   # grâce après FIN/RST avant de finaliser
DUREE_MAX_FLUX = 10
INTERVALLE_BALAYAGE = 1

flux = {}
dernier_balayage = time.time()
compteur_doublons = 0

FEATURES_NOMS = ["nb_paquets", "nb_octets", "duree", "debit", "proto",
                  "port_dst", "syn", "ack", "fin", "rst"]


def nouveau_flux(ts):
    return {"nb_paquets": 0, "nb_octets": 0, "premier_ts": ts, "dernier_ts": ts,
            "syn": 0, "ack": 0, "fin": 0, "rst": 0,
            "dernier_paquet": None, "fermeture_vue": False}


def predire_flux(cle, fl, raison):
    ip_src, ip_dst, port_src, port_dst, proto = cle
    duree = fl["dernier_ts"] - fl["premier_ts"]
    debit = fl["nb_octets"] / duree if duree > 0 else fl["nb_octets"]

    features = pd.DataFrame([[
        fl["nb_paquets"], fl["nb_octets"], duree, debit, proto,
        port_dst, fl["syn"], fl["ack"], fl["fin"], fl["rst"]
    ]], columns=FEATURES_NOMS)

    features_norm = scaler.transform(features)
    prediction = modele.predict(features_norm)[0]
    proba = modele.predict_proba(features_norm)[0]
    nom_classe = encodeur.inverse_transform([prediction])[0]
    confiance = np.max(proba) * 100

    anomalie = detecteur.predict(features.values)[0]
    tag_anomalie = "ANOMALIE" if anomalie == -1 else "normal"

    if confiance >= SEUIL_CONFIANCE:
        verdict = nom_classe.upper()
    else:
        verdict = f"INCERTAIN (peut-être {nom_classe})"

    print(f"  Flux {ip_src}:{port_src} -> {ip_dst}:{port_dst} | "
          f"paquets={fl['nb_paquets']} syn={fl['syn']} fin={fl['fin']} rst={fl['rst']} "
          f"octets={fl['nb_octets']} [{raison}]")
    print(f"    -> Random Forest    : {verdict} (confiance {confiance:.1f}%)")
    print(f"    -> Isolation Forest : {tag_anomalie}")


def balayer_flux_stagnants():
    maintenant = time.time()
    a_supprimer = []
    for cle, fl in flux.items():
        silence = maintenant - fl["dernier_ts"]
        if fl["fermeture_vue"] and silence >= TIMEOUT_APRES_FERMETURE:
            predire_flux(cle, fl, "connexion terminée")
            a_supprimer.append(cle)
        elif silence >= TIMEOUT_INACTIVITE:
            predire_flux(cle, fl, "inactivité")
            a_supprimer.append(cle)
        elif (maintenant - fl["premier_ts"]) >= DUREE_MAX_FLUX:
            predire_flux(cle, fl, "flux continu (durée max atteinte)")
            a_supprimer.append(cle)
    for cle in a_supprimer:
        del flux[cle]


def traiter_paquet(paquet):
    global compteur_doublons, dernier_balayage

    if IP in paquet:
        ip_src = paquet[IP].src
        ip_dst = paquet[IP].dst

        if ip_dst != CIBLE:
            return

        proto = paquet[IP].proto
        port_src = 0
        port_dst = 0
        flags = ""
        seq = None
        if TCP in paquet:
            port_src = paquet[TCP].sport
            port_dst = paquet[TCP].dport
            flags = str(paquet[TCP].flags)
            seq = paquet[TCP].seq
        elif UDP in paquet:
            port_src = paquet[UDP].sport
            port_dst = paquet[UDP].dport

        cle = (ip_src, ip_dst, port_src, port_dst, proto)
        ts = time.time()
        if cle not in flux:
            flux[cle] = nouveau_flux(ts)
        fl = flux[cle]

        identifiant = (seq, flags)
        if TCP in paquet and seq is not None and fl["dernier_paquet"] == identifiant:
            compteur_doublons += 1
            return

        fl["dernier_paquet"] = identifiant
        fl["nb_paquets"] += 1
        fl["nb_octets"] += len(paquet)
        fl["dernier_ts"] = ts
        if "S" in flags: fl["syn"] += 1
        if "A" in flags: fl["ack"] += 1
        if "F" in flags: fl["fin"] += 1
        if "R" in flags: fl["rst"] += 1

        # ---- Ne plus classer immédiatement : on marque, on attend la grâce ----
        if "F" in flags or "R" in flags:
            fl["fermeture_vue"] = True

    if time.time() - dernier_balayage >= INTERVALLE_BALAYAGE:
        balayer_flux_stagnants()
        dernier_balayage = time.time()


filtre = "host 192.168.211.128 and host 192.168.211.50"
print("=== DÉTECTION TEMPS RÉEL PAR IA — suivi de connexion (Ctrl+C pour arrêter) ===")
sniff(iface="ens33", filter=filtre, prn=traiter_paquet, store=False)
