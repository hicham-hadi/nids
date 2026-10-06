from scapy.all import sniff

def traiter_paquet(paquet):
    print(paquet.summary())

print("=== Capture démarrée sur ens33 (Ctrl+C pour arrêter) ===")
sniff(iface="ens33", prn=traiter_paquet, store=False)
