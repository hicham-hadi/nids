import numpy as np
import pandas as pd

from detection_fusion import (
    modele, encodeur, scaler, detecteur,
    FEATURES_NOMS, SEUIL_CONFIANCE,
    SEUIL_DOS_PAQUETS, SEUIL_DOS_RATIO_SYN, SEUIL_BF_SSH_PAQUETS, PORT_SSH,
    fusionner,
)

# ============================================================
#  ÉVALUATION HORS LIGNE — FUSION RÈGLES + IA SUR dataset_maison.csv
#
#  dataset_maison.csv ne contient qu'un flux isolé par ligne
#  (pas d'IP, pas de fenêtre temporelle multi-flux) : le Port Scan
#  (plusieurs ports depuis une même IP) et le Brute Force FTP
#  (inspection de la charge utile "530") ne sont donc pas
#  détectables par signature ici. Ces attaques ne peuvent être
#  repérées que par le modèle IA, entraîné sur ces mêmes features.
# ============================================================

FICHIER_DATASET = "dataset_maison.csv"
FICHIER_RESULTATS = "dataset_maison_fusion_resultats.csv"


def evaluer_regles(df):
    ratio_syn = np.where(df["nb_paquets"] > 0, df["syn"] / df["nb_paquets"], 0)
    masque_dos = (df["nb_paquets"] > SEUIL_DOS_PAQUETS) & (ratio_syn >= SEUIL_DOS_RATIO_SYN)
    masque_bf = (df["port_dst"] == PORT_SSH) & (df["syn"] > SEUIL_BF_SSH_PAQUETS) & ~masque_dos

    verdicts = np.where(masque_dos, "DOS", np.where(masque_bf, "BRUTEFORCE", "NORMAL"))

    details = np.full(len(df), "aucune signature détectée", dtype=object)
    details[masque_dos.to_numpy()] = [
        f"{n} paquets, {int(r*100)}% SYN"
        for n, r in zip(df.loc[masque_dos, "nb_paquets"], ratio_syn[masque_dos.to_numpy()])
    ]
    details[masque_bf.to_numpy()] = [
        f"{s} paquets vers le port 22" for s in df.loc[masque_bf, "syn"]
    ]
    return verdicts, details


def evaluer_ml(df):
    features = df[FEATURES_NOMS]
    features_norm = scaler.transform(features)

    predictions = modele.predict(features_norm)
    probas = modele.predict_proba(features_norm)
    noms_classes = np.char.upper(encodeur.inverse_transform(predictions).astype(str))
    confiances = probas.max(axis=1) * 100

    anomalies = detecteur.predict(features.values) == -1
    return noms_classes, confiances, anomalies


def executer():
    df = pd.read_csv(FICHIER_DATASET, header=None, names=FEATURES_NOMS + ["label"])

    verdict_regle, detail_regle = evaluer_regles(df)
    verdict_ml, confiance_ml, anomalie_ml = evaluer_ml(df)

    resultats = df.copy()
    resultats["verdict_regle"] = verdict_regle
    resultats["detail_regle"] = detail_regle
    resultats["verdict_ml"] = verdict_ml
    resultats["confiance_ml"] = np.round(confiance_ml, 1)
    resultats["anomalie_ml"] = anomalie_ml

    couleur_fusion, explication_fusion = zip(*resultats.apply(
        lambda r: fusionner(r["verdict_regle"], r["verdict_ml"], r["confiance_ml"], r["anomalie_ml"]),
        axis=1,
    ))
    resultats["couleur_fusion"] = couleur_fusion
    resultats["explication_fusion"] = explication_fusion

    resultats.to_csv(FICHIER_RESULTATS, index=False)
    print(f"Résultats fusionnés enregistrés dans {FICHIER_RESULTATS} ({len(resultats)} flux)\n")

    afficher_rapport(resultats)
    return resultats


def afficher_rapport(resultats):
    print("========== RAPPORT DE FUSION (signature + IA) sur dataset_maison.csv ==========\n")

    print("-- Répartition des verdicts fusionnés par label réel --")
    print(pd.crosstab(resultats["label"], resultats["couleur_fusion"]), "\n")

    ml_positif = (resultats["confiance_ml"] >= SEUIL_CONFIANCE) & (resultats["verdict_ml"] != "NORMAL") | resultats["anomalie_ml"]

    print("-- Détection par attaque réelle (hors 'normal') --")
    print(f"  {'label':<12}{'total':<8}{'signature':<16}{'IA':<16}{'fusion':<16}")
    attaques = resultats[resultats["label"] != "normal"]
    for label, groupe in attaques.groupby("label"):
        total = len(groupe)
        par_regle = (groupe["verdict_regle"] != "NORMAL").sum()
        par_ml = ml_positif.loc[groupe.index].sum()
        par_fusion = (groupe["couleur_fusion"] != "VERT").sum()
        print(f"  {label:<12}{total:<8}"
              f"{f'{par_regle}/{total} ({par_regle/total:.0%})':<16}"
              f"{f'{par_ml}/{total} ({par_ml/total:.0%})':<16}"
              f"{f'{par_fusion}/{total} ({par_fusion/total:.0%})':<16}")

    print("\n-- Faux positifs sur le trafic normal --")
    normal = resultats[resultats["label"] == "normal"]
    total_normal = len(normal)
    fp_regle = (normal["verdict_regle"] != "NORMAL").sum()
    fp_ml = ml_positif.loc[normal.index].sum()
    fp_fusion_rouge = (normal["couleur_fusion"] == "ROUGE").sum()
    fp_fusion_non_vert = (normal["couleur_fusion"] != "VERT").sum()
    print(f"  total normal = {total_normal}")
    print(f"  signature FP = {fp_regle} ({fp_regle/total_normal:.1%})")
    print(f"  IA FP        = {fp_ml} ({fp_ml/total_normal:.1%})")
    print(f"  fusion FP (ROUGE)         = {fp_fusion_rouge} ({fp_fusion_rouge/total_normal:.1%})")
    print(f"  fusion FP (ROUGE+ORANGE)  = {fp_fusion_non_vert} ({fp_fusion_non_vert/total_normal:.1%})")

    print("\n=================================================================================\n")


if __name__ == "__main__":
    executer()
