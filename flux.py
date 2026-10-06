from scapy.all import sniff, IP, TCP, UDP
import time

# Dictionnaire des flux de la fenêtre en cours
flux = {}
debut = time.time()
FENETRE = 10  # secondes

def afficher_resume():
    print("\n===== RÉSUMÉ DES 10 DERNIÈRES SECONDES =====")
    print(f"Nombre de flux différents : {len(flux)}")
    for cle, nb in flux.items():
        ip_src, ip_dst, port_dst, proto = cle
        print(f"  {ip_src} -> {ip_dst}:{port_dst} | proto={proto} | paquets={nb}")
    print("============================================\n")

def traiter_paquet(paquet):
    global debut, flux

    if IP in paquet:
        ip_src = paquet[IP].src
        ip_dst = paquet[IP].dst
        proto = paquet[IP].proto
        port_dst = 0
        if TCP in paquet:
            port_dst = paquet[TCP].dport
        elif UDP in paquet:
            port_dst = paquet[UDP].dport

        cle = (ip_src, ip_dst, port_dst, proto)
        flux[cle] = flux.get(cle, 0) + 1

    # Fin de la fenêtre de 10 secondes ?
    if time.time() - debut >= FENETRE:
        afficher_resume()
        flux = {}              # on remet tout à zéro
        debut = time.time()    # on redémarre le chrono

filtre = "host 192.168.211.128 and host 192.168.211.50"
print("=== Analyse par fenêtres de 10s démarrée (Ctrl+C pour arrêter) ===")
sniff(iface="ens33", filter=filtre, prn=traiter_paquet, store=False)
