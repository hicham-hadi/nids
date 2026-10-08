from scapy.all import sniff, IP, TCP, Raw
import time

# ============================================================
#  MODULE 3 (v4) — Détection par règles, version corrigée
#  Correction : analyse UNIQUEMENT le trafic vers la cible
#  -> supprime les faux Port Scan dus aux réponses du serveur
#  -> permet une détection SSH comportementale correcte
# ============================================================

CIBLE = "192.168.211.50"     # on n'analyse que le trafic DESTINÉ à la cible

ports_par_ip = {}       # {ip_src : set(ports)}                 -> Port Scan
stats_par_flux = {}     # {(ip_src, port_dst) : {syn, total}}   -> DoS & SSH
echecs_ftp = {}         # {ip_src : nb "530"}                   -> Brute Force FTP

debut_fenetre = time.time()

# ---- Paramètres ----
FENETRE = 5
SEUIL_PORTSCAN = 15
SEUIL_DOS_PAQUETS = 500
SEUIL_DOS_RATIO_SYN = 0.7
SEUIL_BF_FTP = 5        # échecs 530 prouvés
SEUIL_BF_SSH = 5        # connexions SSH (seuil abaissé : hydra fait peu d'essais)
PORT_FTP = 21
PORT_SSH = 22


def nouveau_flux():
    return {"total": 0, "syn": 0}


def analyser_et_alerter():
    print("\n########## ANALYSE DE SÉCURITÉ (fenêtre de 5s) ##########")
    alertes = []

    # ---- Règle 1 : DoS / SYN Flood (évaluée en premier) ----
    for (ip_src, port_dst), s in stats_par_flux.items():
        ratio = s["syn"] / s["total"] if s["total"] > 0 else 0
        if s["total"] > SEUIL_DOS_PAQUETS and ratio >= SEUIL_DOS_RATIO_SYN:
            alertes.append(
                f"[DoS/FLOOD]       {ip_src} -> {CIBLE}:{port_dst} | "
                f"{s['total']} paquets, {int(ratio*100)}% SYN"
            )

    # ---- Règle 2 : PORT SCAN (ports destination distincts) ----
    for ip_src, ports in ports_par_ip.items():
        if len(ports) > SEUIL_PORTSCAN:
            alertes.append(
                f"[PORT SCAN]       {ip_src} a contacté {len(ports)} ports différents "
                f"(seuil={SEUIL_PORTSCAN})"
            )

    # ---- Règle 3a : BRUTE FORCE FTP (preuve applicative) ----
    for ip_src, nb in echecs_ftp.items():
        if nb > SEUIL_BF_FTP:
            alertes.append(
                f"[BRUTE FORCE FTP] {ip_src} -> {CIBLE}:21 | "
                f"{nb} échecs '530' détectés (PREUVE applicative)"
            )

    # ---- Règle 3b : BRUTE FORCE SSH (comportement réseau) ----
    for (ip_src, port_dst), s in stats_par_flux.items():
        if port_dst == PORT_SSH and s["syn"] > SEUIL_BF_SSH:
            nb_ports = len(ports_par_ip.get(ip_src, set()))
            if nb_ports <= SEUIL_PORTSCAN:   # exclut le cas d'un scan
                alertes.append(
                    f"[BRUTE FORCE SSH?] {ip_src} -> {CIBLE}:22 | "
                    f"{s['syn']} tentatives de connexion (comportement suspect, trafic chiffré)"
                )

    if alertes:
        for a in alertes:
            print("  /!\\ ALERTE : " + a)
    else:
        print("  Trafic normal — aucune attaque détectée.")
    print("#######################################################\n")


def traiter_paquet(paquet):
    global debut_fenetre, ports_par_ip, stats_par_flux, echecs_ftp

    if IP in paquet and TCP in paquet:
        ip_src = paquet[IP].src
        ip_dst = paquet[IP].dst
        port_src = paquet[TCP].sport
        port_dst = paquet[TCP].dport
        flags = str(paquet[TCP].flags)

        # --- CORRECTION CLÉ : Brute Force FTP se lit AVANT le filtre ---
        # (la réponse 530 vient DU serveur, donc ip_src = cible)
        if port_src == PORT_FTP and Raw in paquet:
            charge = bytes(paquet[Raw].load)
            if b"530" in charge:
                attaquant = ip_dst   # le client qui reçoit le 530
                echecs_ftp[attaquant] = echecs_ftp.get(attaquant, 0) + 1

        # --- On n'analyse QUE le trafic VERS la cible pour le reste ---
        if ip_dst != CIBLE:
            return

        # --- Port Scan ---
        if ip_src not in ports_par_ip:
            ports_par_ip[ip_src] = set()
        ports_par_ip[ip_src].add(port_dst)

        # --- Stats par flux (DoS + SSH) ---
        cle = (ip_src, port_dst)
        if cle not in stats_par_flux:
            stats_par_flux[cle] = nouveau_flux()
        # RST "pur" (réponse du noyau de l'attaquant aux SYN-ACK) exclu du ratio DoS
        if flags != "R":
            stats_par_flux[cle]["total"] += 1
        if flags == "S":
            stats_par_flux[cle]["syn"] += 1

    if time.time() - debut_fenetre >= FENETRE:
        analyser_et_alerter()
        ports_par_ip = {}
        stats_par_flux = {}
        echecs_ftp = {}
        debut_fenetre = time.time()


filtre = "host 192.168.211.128 and host 192.168.211.50"
print("=== MODULE 3 v4 : détection corrigée (Ctrl+C pour arrêter) ===")
sniff(iface="ens33", filter=filtre, prn=traiter_paquet, store=False)
