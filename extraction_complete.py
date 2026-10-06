from scapy.all import sniff, IP, TCP, UDP, ICMP
import time

# ============================================================
#  MODULE 2 (complet) — Extraction des caractéristiques (features)
#  Capture le 5-tuple + flags + tailles + horodatages,
#  puis regroupe les paquets en flux et calcule des statistiques.
# ============================================================

flux = {}                 # dictionnaire de tous les flux
debut_fenetre = time.time()
FENETRE = 5               # durée d'une fenêtre d'analyse (secondes)

# Traduction des numéros de protocole en noms lisibles
PROTOCOLES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def nouveau_flux(ts):
    """Crée la structure vide d'un nouveau flux, avec toutes ses features."""
    return {
        "nb_paquets": 0,          # nombre total de paquets
        "nb_octets": 0,           # volume total en octets
        "premier_ts": ts,         # horodatage du premier paquet
        "dernier_ts": ts,         # horodatage du dernier paquet
        "flags": {},              # comptage de chaque flag TCP (S, SA, RA...)
        "ports_dst": set(),       # ensemble des ports destination vus
    }


def traiter_paquet(paquet):
    global flux, debut_fenetre

    if IP not in paquet:
        return  # on ignore les paquets sans couche IP

    # ---- Le 5-tuple ----
    ip_src = paquet[IP].src
    ip_dst = paquet[IP].dst
    proto_num = paquet[IP].proto
    proto_nom = PROTOCOLES.get(proto_num, str(proto_num))

    port_src = 0
    port_dst = 0
    flag_str = ""

    if TCP in paquet:
        port_src = paquet[TCP].sport
        port_dst = paquet[TCP].dport
        flag_str = str(paquet[TCP].flags)   # ex : "S", "SA", "RA"
    elif UDP in paquet:
        port_src = paquet[UDP].sport
        port_dst = paquet[UDP].dport

    # ---- Informations supplémentaires ----
    taille = len(paquet)          # taille du paquet en octets
    ts = time.time()              # horodatage

    # ---- Clé du flux = le 5-tuple ----
    cle = (ip_src, ip_dst, port_src, port_dst, proto_num)

    # ---- Création ou mise à jour du flux ----
    if cle not in flux:
        flux[cle] = nouveau_flux(ts)

    f = flux[cle]
    f["nb_paquets"] += 1
    f["nb_octets"] += taille
    f["dernier_ts"] = ts
    f["ports_dst"].add(port_dst)
    if flag_str:
        f["flags"][flag_str] = f["flags"].get(flag_str, 0) + 1

    # ---- Fin de la fenêtre : on affiche les features calculées ----
    if time.time() - debut_fenetre >= FENETRE:
        afficher_features()
        flux = {}
        debut_fenetre = time.time()


def afficher_features():
    print("\n========== FEATURES DES FLUX (fenêtre de 5s) ==========")
    print(f"Nombre de flux : {len(flux)}\n")
    for cle, f in flux.items():
        ip_src, ip_dst, port_src, port_dst, proto_num = cle
        proto_nom = PROTOCOLES.get(proto_num, str(proto_num))
        duree = f["dernier_ts"] - f["premier_ts"]
        debit = f["nb_octets"] / duree if duree > 0 else f["nb_octets"]

        print(f"[{proto_nom}] {ip_src}:{port_src} -> {ip_dst}:{port_dst}")
        print(f"    paquets = {f['nb_paquets']} | octets = {f['nb_octets']} "
              f"| durée = {duree:.3f}s | débit = {debit:.0f} o/s")
        print(f"    flags = {f['flags']}")
    print("=======================================================\n")


filtre = "host 192.168.211.128 and host 192.168.211.50"
print("=== MODULE 2 : extraction complète des features (Ctrl+C pour arrêter) ===")
sniff(iface="ens33", filter=filtre, prn=traiter_paquet, store=False)
