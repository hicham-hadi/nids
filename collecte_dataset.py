from scapy.all import sniff, IP, TCP, UDP
import time
import csv
import sys

# ============================================================
#  COLLECTEUR DE DATASET — Option B (5-tuple + filtrage doublons)
# ============================================================

if len(sys.argv) < 2:
    print("Usage : sudo python3 collecte_dataset.py <label>")
    print("Exemple : sudo python3 collecte_dataset.py normal")
    sys.exit()

LABEL = sys.argv[1]
FICHIER = "dataset_maison.csv"
FENETRE = 5

flux = {}
debut_fenetre = time.time()
compteur_doublons = 0


def nouveau_flux(ts):
    return {"nb_paquets": 0, "nb_octets": 0, "premier_ts": ts, "dernier_ts": ts,
            "syn": 0, "ack": 0, "fin": 0, "rst": 0, "dernier_seq": None}


def enregistrer_flux():
    with open(FICHIER, "a", newline="") as f:
        writer = csv.writer(f)
        for cle, fl in flux.items():
            ip_src, ip_dst, port_src, port_dst, proto = cle
            duree = fl["dernier_ts"] - fl["premier_ts"]
            debit = fl["nb_octets"]/duree if duree > 0 else fl["nb_octets"]
            writer.writerow([
                fl["nb_paquets"], fl["nb_octets"], round(duree, 4), round(debit, 2),
                proto, port_dst,
                fl["syn"], fl["ack"], fl["fin"], fl["rst"],
                LABEL
            ])
    print(f"[{LABEL}] {len(flux)} flux enregistrés ({compteur_doublons} doublons filtrés au total)")


def traiter_paquet(paquet):
    global debut_fenetre, flux, compteur_doublons
    if IP in paquet:
        ip_src = paquet[IP].src
        ip_dst = paquet[IP].dst
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

        # ---- FILTRAGE DES DUPLICATIONS/RETRANSMISSIONS ----
        if TCP in paquet and seq is not None and fl["dernier_seq"] == seq:
            compteur_doublons += 1
            return

        fl["dernier_seq"] = seq
        fl["nb_paquets"] += 1
        fl["nb_octets"] += len(paquet)
        fl["dernier_ts"] = ts
        if "S" in flags: fl["syn"] += 1
        if "A" in flags: fl["ack"] += 1
        if "F" in flags: fl["fin"] += 1
        if "R" in flags: fl["rst"] += 1

    if time.time() - debut_fenetre >= FENETRE:
        enregistrer_flux()
        flux = {}
        debut_fenetre = time.time()


filtre = "host 192.168.211.128 and host 192.168.211.50"
print(f"=== COLLECTE label='{LABEL}' (Ctrl+C pour arrêter) ===")
sniff(iface="ens33", filter=filtre, prn=traiter_paquet, store=False)
