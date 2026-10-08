from scapy.all import sniff, IP, TCP, UDP, Raw
import joblib
import time
import numpy as np
import pandas as pd
from collections import Counter
from db import enregistrer_alerte
# ============================================================
#  MODULE 5 — FUSION RÈGLES + MACHINE LEARNING (version finale)
# ============================================================

print("Chargement des modèles IA...")
modele = joblib.load("modele_ids.joblib")
encodeur = joblib.load("encodeur.joblib")
scaler = joblib.load("scaler.joblib")
detecteur = joblib.load("detecteur_anomalies.joblib")
print("Modèles chargés avec succès !\n")

CIBLE = "192.168.211.50"
SEUIL_CONFIANCE = 80
TIMEOUT_INACTIVITE = 2
TIMEOUT_APRES_FERMETURE = 2
DUREE_MAX_FLUX = 10
INTERVALLE_BALAYAGE = 1
FENETRE_GLISSANTE = 15
PORT_FTP = 21
PORT_SSH = 22

SEUIL_PORTSCAN = 15
SEUIL_DOS_PAQUETS = 500
SEUIL_DOS_RATIO_SYN = 0.7
SEUIL_BF_FTP = 5
SEUIL_BF_SSH_PAQUETS = 15

flux = {}
ports_ip = {}
syn_ip = {}
total_paquets_ip = {}
ftp_echecs_ip = {}
ssh_paquets_ip = {}

dernier_balayage = time.time()
compteur_doublons = 0

FEATURES_NOMS = ["nb_paquets", "nb_octets", "duree", "debit", "proto",
                  "port_dst", "syn", "ack", "fin", "rst"]


def nouveau_flux(ts):
    return {"nb_paquets": 0, "nb_octets": 0, "premier_ts": ts, "dernier_ts": ts,
            "syn": 0, "ack": 0, "fin": 0, "rst": 0,
            "dernier_paquet": None, "fermeture_vue": False}


def nettoyer(liste, maintenant):
    return [ts for ts in liste if maintenant - ts <= FENETRE_GLISSANTE]


def nettoyer_ports(liste, maintenant):
    return [(ts, p) for ts, p in liste if maintenant - ts <= FENETRE_GLISSANTE]


def purger_fenetres(maintenant):
    # Purge réelle des fenêtres glissantes (sinon les listes grossissent sans fin
    # et chaque évaluation devient plus lente -> paquets perdus pendant un flood)
    for table in (ports_ip, syn_ip, total_paquets_ip):
        for ip in list(table):
            table[ip] = nettoyer_ports(table[ip], maintenant)
            if not table[ip]:
                del table[ip]
    for table in (ftp_echecs_ip, ssh_paquets_ip):
        for ip in list(table):
            table[ip] = nettoyer(table[ip], maintenant)
            if not table[ip]:
                del table[ip]


def etat_regles(ip_src):
    maintenant = time.time()

    # ---- Règle DoS en PREMIER, comptée par port destination ----
    # Un SYN flood vise UN port (ports source variables) ; un scan rapide envoie
    # beaucoup de SYN mais répartis sur des ports différents -> pas un DoS.
    syn_par_port = Counter(p for _, p in nettoyer_ports(syn_ip.get(ip_src, []), maintenant))
    if syn_par_port:
        port_vise, nb_syn = syn_par_port.most_common(1)[0]
        total_port = sum(1 for _, p in nettoyer_ports(total_paquets_ip.get(ip_src, []), maintenant)
                         if p == port_vise)
        ratio_syn = nb_syn / total_port if total_port else 0
        if nb_syn > SEUIL_DOS_PAQUETS and ratio_syn >= SEUIL_DOS_RATIO_SYN:
            return "DOS", (f"{nb_syn} SYN vers le port {port_vise} en {FENETRE_GLISSANTE}s "
                           f"({int(ratio_syn*100)}%)")

    # ---- Port Scan : ports DESTINATION distincts ----
    ports_recents = nettoyer_ports(ports_ip.get(ip_src, []), maintenant)
    nb_ports = len(set(p for _, p in ports_recents))
    if nb_ports > SEUIL_PORTSCAN:
        return "PORTSCAN", f"{nb_ports} ports contactés en {FENETRE_GLISSANTE}s"

    ftp_recents = nettoyer(ftp_echecs_ip.get(ip_src, []), maintenant)
    if len(ftp_recents) > SEUIL_BF_FTP:
        return "BRUTEFORCE", f"{len(ftp_recents)} échecs FTP (530) en {FENETRE_GLISSANTE}s"

    ssh_recents = nettoyer(ssh_paquets_ip.get(ip_src, []), maintenant)
    if len(ssh_recents) > SEUIL_BF_SSH_PAQUETS and nb_ports <= SEUIL_PORTSCAN:
        return "BRUTEFORCE", f"{len(ssh_recents)} paquets vers le port 22 en {FENETRE_GLISSANTE}s"

    return "NORMAL", "aucune signature détectée"


def evaluer_ml(fl, port_dst, proto):
    duree = fl["dernier_ts"] - fl["premier_ts"]
    debit = fl["nb_octets"] / duree if duree > 0 else fl["nb_octets"]

    features = pd.DataFrame([[
        fl["nb_paquets"], fl["nb_octets"], duree, debit, proto,
        port_dst, fl["syn"], fl["ack"], fl["fin"], fl["rst"]
    ]], columns=FEATURES_NOMS)

    features_norm = scaler.transform(features)
    prediction = modele.predict(features_norm)[0]
    proba = modele.predict_proba(features_norm)[0]
    nom_classe = encodeur.inverse_transform([prediction])[0].upper()
    confiance = np.max(proba) * 100

    anomalie = detecteur.predict(features.values)[0]
    est_anomalie = (anomalie == -1)

    return nom_classe, confiance, est_anomalie


def fusionner(verdict_regle, verdict_ml, confiance_ml, anomalie_ml):
    ml_confiant = confiance_ml >= SEUIL_CONFIANCE

    if verdict_regle != "NORMAL":
        if ml_confiant and verdict_ml == verdict_regle:
            return "ROUGE", "Attaque confirmée (règle + IA d'accord)"
        else:
            return "ROUGE", "Attaque détectée par signature (règle)"
    else:
        if ml_confiant and verdict_ml != "NORMAL":
            return "ORANGE", f"Suspect : l'IA détecte {verdict_ml} ({confiance_ml:.0f}%)"
        elif verdict_ml == "NORMAL" and confiance_ml >= 85 and anomalie_ml:
            # Le RF est très confiant que c'est normal -> VERT,
            # mais on note que l'Isolation Forest a quand même vu une anomalie
            return "VERT", f"Trafic normal (note : profil légèrement atypique détecté)"
        elif anomalie_ml:
            return "ORANGE", "Suspect : comportement anormal (Isolation Forest)"
        else:
            return "VERT", "Trafic normal"

def afficher_verdict(cle, fl, raison_fin, nb_flux=1, regles=None):
    ip_src, ip_dst, port_src, port_dst, proto = cle
    verdict_regle, detail_regle = regles if regles else etat_regles(ip_src)
    verdict_ml, confiance_ml, anomalie_ml = evaluer_ml(fl, port_dst, proto)
    couleur, explication = fusionner(verdict_regle, verdict_ml, confiance_ml, anomalie_ml)
    if nb_flux > 1:
        explication += f" [agrégat de {nb_flux} flux, ports source variables]"
    symbole = {"ROUGE": "🔴", "ORANGE": "🟠", "VERT": "🟢"}[couleur]
    origine = f"{ip_src}:*({nb_flux} flux)" if nb_flux > 1 else f"{ip_src}:{port_src}"
    print(f"\n{symbole} [{couleur}] Flux {origine} -> {ip_dst}:{port_dst} "
          f"| paquets={fl['nb_paquets']} [{raison_fin}]")
    print(f"    Règles : {verdict_regle} ({detail_regle})")
    print(f"    IA     : {verdict_ml} (confiance {confiance_ml:.1f}%, "
          f"anomalie={'oui' if anomalie_ml else 'non'})")
    print(f"    -> {explication}")

    # ---- Enregistrement dans la base de données ----
    enregistrer_alerte(
        ip_src, port_src, ip_dst, port_dst, proto, fl,
        verdict_regle, detail_regle,
        verdict_ml, confiance_ml, anomalie_ml,
        couleur, explication
    )

def fusionner_flux(liste):
    # Somme des flux d'un même (ip_src, ip_dst, port_dst, proto) -> UN seul flux
    total = nouveau_flux(min(fl["premier_ts"] for fl in liste))
    total["dernier_ts"] = max(fl["dernier_ts"] for fl in liste)
    for fl in liste:
        for champ in ("nb_paquets", "nb_octets", "syn", "ack", "fin", "rst"):
            total[champ] += fl[champ]
    return total


def balayer_flux_stagnants():
    maintenant = time.time()
    purger_fenetres(maintenant)
    expires = []
    for cle, fl in flux.items():
        silence = maintenant - fl["dernier_ts"]
        if fl["fermeture_vue"] and silence >= TIMEOUT_APRES_FERMETURE:
            expires.append((cle, fl, "connexion terminée"))
        elif silence >= TIMEOUT_INACTIVITE:
            expires.append((cle, fl, "inactivité"))
        elif (maintenant - fl["premier_ts"]) >= DUREE_MAX_FLUX:
            expires.append((cle, fl, "flux continu"))
    for cle, _, _ in expires:
        del flux[cle]

    # ---- Agrégation : flux sans ACK (SYN flood, UDP flood...) vers le même
    # port destination = UNE seule attaque, peu importe le port source.
    # Les connexions établies (ack > 0) restent évaluées une par une.
    groupes = {}
    individuels = []
    for cle, fl, raison in expires:
        if fl["ack"] == 0:
            ip_src, ip_dst, _, port_dst, proto = cle
            groupes.setdefault((ip_src, ip_dst, port_dst, proto), []).append((cle, fl, raison))
        else:
            individuels.append((cle, fl, raison))

    regles_ip = {}   # règles évaluées une seule fois par IP et par balayage
    def regles(ip_src):
        if ip_src not in regles_ip:
            regles_ip[ip_src] = etat_regles(ip_src)
        return regles_ip[ip_src]

    for membres in groupes.values():
        if len(membres) == 1:
            individuels.append(membres[0])
            continue
        cle0 = membres[0][0]
        fl_total = fusionner_flux([fl for _, fl, _ in membres])
        afficher_verdict(cle0, fl_total, "flux agrégés", nb_flux=len(membres),
                         regles=regles(cle0[0]))

    for cle, fl, raison in individuels:
        afficher_verdict(cle, fl, raison, regles=regles(cle[0]))


def traiter_paquet(paquet):
    global compteur_doublons, dernier_balayage

    if IP in paquet:
        ip_src = paquet[IP].src
        ip_dst = paquet[IP].dst
        maintenant = time.time()

        if TCP in paquet and paquet[TCP].sport == PORT_FTP and Raw in paquet:
            charge = bytes(paquet[Raw].load)
            if b"530" in charge:
                attaquant = ip_dst
                ftp_echecs_ip.setdefault(attaquant, []).append(maintenant)

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

        ports_ip.setdefault(ip_src, []).append((maintenant, port_dst))
        # RST "pur" exclu du ratio DoS : pendant un SYN flood, le noyau de
        # l'attaquant répond RST à chaque SYN-ACK de la cible, ce qui ferait
        # chuter le ratio SYN sous le seuil (~50%) alors que c'est bien un flood.
        if flags != "R":
            total_paquets_ip.setdefault(ip_src, []).append((maintenant, port_dst))
        if "S" in flags:
            syn_ip.setdefault(ip_src, []).append((maintenant, port_dst))
        if port_dst == PORT_SSH:
            ssh_paquets_ip.setdefault(ip_src, []).append(maintenant)

        cle = (ip_src, ip_dst, port_src, port_dst, proto)
        ts = maintenant
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

        if "F" in flags or "R" in flags:
            fl["fermeture_vue"] = True

    if time.time() - dernier_balayage >= INTERVALLE_BALAYAGE:
        balayer_flux_stagnants()
        dernier_balayage = time.time()


filtre = "host 192.168.211.128 and host 192.168.211.50"
print("=== MODULE 5 : DÉTECTION FUSIONNÉE (Ctrl+C pour arrêter) ===\n")
sniff(iface="ens33", filter=filtre, prn=traiter_paquet, store=False)
