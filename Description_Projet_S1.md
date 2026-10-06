# S1 — Système Hybride de Détection d'Intrusions Réseau (NIDS)

## Description Générale du Projet

**Nom du projet :** S1  
**Type :** Projet de Fin d'Année (PFA) / Stage  
**Organisme d'accueil :** OCP Group  
**Réalisé par :** Hicham HADI — Étudiant à l'École Polytechnique de Marrakech  
**Technologies principales :** Python, Scapy, scikit-learn, SQLite, Dash/Plotly  

S1 est un système de détection d'intrusions réseau (NIDS — Network Intrusion Detection System) hybride, conçu pour détecter en temps réel quatre types d'attaques réseau courantes. Son originalité réside dans la combinaison de deux approches complémentaires : un moteur de règles de signatures (détection déterministe) et un module de Machine Learning (détection probabiliste), dont les verdicts sont fusionnés pour produire un diagnostic final coloré (vert / orange / rouge) par flux réseau analysé.

Le système fonctionne entièrement en temps réel : il capture les paquets sur une interface réseau, extrait les caractéristiques pertinentes, applique les deux moteurs de détection en parallèle, fusionne leurs conclusions, persiste les alertes dans une base SQLite, et les affiche dans un tableau de bord web interactif.

---

## Attaques Détectées

Le système est entraîné et configuré pour identifier quatre types d'attaques :

1. **Port Scan** — Balayage de ports : un attaquant sonde un grand nombre de ports sur la cible pour découvrir les services ouverts. Détecté lorsqu'une IP source contacte plus de 15 ports distincts en 15 secondes.

2. **DoS / SYN Flood** — Déni de service par saturation SYN : l'attaquant envoie massivement des paquets TCP SYN sans compléter le handshake, épuisant les ressources de la cible. Détecté lorsque plus de 500 paquets sont envoyés avec un ratio SYN supérieur à 70%.

3. **Brute Force FTP** — Tentatives d'authentification par force brute sur le service FTP (port 21). Détecté par l'analyse applicative des réponses « 530 Login incorrect » renvoyées par le serveur.

4. **Brute Force SSH** — Tentatives d'authentification par force brute sur le service SSH (port 22). Détecté par analyse comportementale du volume de paquets vers le port 22, le trafic étant chiffré et donc non inspectable au niveau applicatif.

---

## Architecture Modulaire

Le projet est structuré en 7 modules indépendants, développés et validés séquentiellement :

### Module 1 — Capture de paquets (`capture.py`)

Point d'entrée du système. Utilise la bibliothèque **Scapy** pour capturer les paquets bruts sur l'interface réseau `ens33` (VMware). Chaque paquet capturé est transmis à la chaîne de traitement en temps réel.

**Fichier :** `capture.py` (7 lignes)  
**Dépendance :** Scapy

### Module 2 — Extraction des caractéristiques (`extraction_complete.py`)

Transforme les paquets bruts en flux réseau exploitables. Regroupe les paquets par 5-tuple (IP source, IP destination, port source, port destination, protocole) dans des fenêtres temporelles de 5 secondes, et calcule pour chaque flux :

- Nombre de paquets et volume en octets
- Durée du flux et débit (octets/seconde)
- Distribution des flags TCP (SYN, ACK, FIN, RST)
- Ensemble des ports destination contactés

**Fichier :** `extraction_complete.py` (98 lignes)

### Module 3 — Moteur de règles / Signatures (`detection_complete.py`)

Moteur de détection déterministe basé sur des seuils et des patterns connus. Implémente quatre règles :

| Règle | Critère | Seuil |
|-------|---------|-------|
| Port Scan | Nombre de ports distincts contactés par une IP | > 15 ports |
| DoS/SYN Flood | Volume de paquets + ratio de SYN | > 500 paquets, > 70% SYN |
| Brute Force FTP | Réponses serveur « 530 » (inspection de payload) | > 5 échecs |
| Brute Force SSH | Volume de paquets vers le port 22 | > 5 tentatives SYN |

Correction majeure appliquée : filtrage unidirectionnel (seul le trafic **vers** la cible est analysé) pour éliminer les faux positifs causés par le trafic bidirectionnel (réponses du serveur).

**Fichier :** `detection_complete.py` (127 lignes)

### Module 4 — Détection par Machine Learning (`detection_ml.py`)

Moteur de détection probabiliste utilisant deux modèles complémentaires :

- **Random Forest** (classification multi-classe) : classifie chaque flux en Normal, Port Scan, DoS, ou Brute Force avec un score de confiance. Seuil de confiance fixé à 80%.
- **Isolation Forest** (détection d'anomalies) : identifie les comportements atypiques qui ne correspondent à aucun pattern connu, servant de filet de sécurité pour les attaques inédites.

Les 10 features utilisées en entrée des modèles :
`nb_paquets`, `nb_octets`, `duree`, `debit`, `proto`, `port_dst`, `syn`, `ack`, `fin`, `rst`

Les modèles sont sérialisés en fichiers `.joblib` :
- `modele_ids.joblib` — Random Forest entraîné
- `encodeur.joblib` — LabelEncoder pour les classes
- `scaler.joblib` — StandardScaler pour la normalisation
- `detecteur_anomalies.joblib` — Isolation Forest

Le module intègre un suivi de connexion intelligent : les flux ne sont évalués qu'à leur clôture (FIN/RST), après un délai d'inactivité, ou lorsqu'une durée maximale est atteinte, évitant les classifications prématurées.

**Fichier :** `detection_ml.py` (145 lignes)

### Module 5 — Fusion et corrélation (`detection_fusion.py`)

Cœur du système hybride. Combine les verdicts des modules 3 (règles) et 4 (ML) pour produire un diagnostic final selon une matrice de décision à trois couleurs :

| Verdict Règles | Verdict ML | Résultat |
|----------------|------------|----------|
| Attaque détectée | ML confirme | 🔴 **ROUGE** — Attaque confirmée (règle + IA d'accord) |
| Attaque détectée | ML non confiant | 🔴 **ROUGE** — Attaque détectée par signature |
| Normal | ML détecte une attaque (confiance ≥ 80%) | 🟠 **ORANGE** — Suspect (IA seule) |
| Normal | Normal mais Isolation Forest signale une anomalie | 🟠 **ORANGE** — Comportement anormal |
| Normal | Normal, pas d'anomalie | 🟢 **VERT** — Trafic normal |

Le module utilise une **fenêtre glissante de 15 secondes** pour l'évaluation des règles, indépendante du cycle de vie des flux individuels. Cette approche corrige un problème majeur de faux négatifs rencontré avec les fenêtres fixes.

**Fichier :** `detection_fusion.py` (235 lignes)

### Module 6 — Persistance SQLite (`init_db.py` + `db.py`)

Stockage durable de chaque verdict dans une base de données SQLite (`nids_alertes.db`). La table `alertes` contient 21 colonnes couvrant :

- Métadonnées réseau (IPs, ports, protocole)
- Features du flux (paquets, octets, durée, débit, flags TCP)
- Verdict des règles et du ML
- Score de confiance et flag d'anomalie
- Couleur finale et explication en langage naturel

Quatre index sont créés pour optimiser les requêtes du tableau de bord : `horodatage`, `ip_source`, `couleur`, `verdict_regle`.

**Fichiers :** `init_db.py` (43 lignes), `db.py` (33 lignes)

### Module 7 — Tableau de bord web (`dashboard.py`)

Interface de visualisation en temps réel construite avec **Dash/Plotly**. Le dashboard comprend quatre zones principales :

1. **Cartes KPI** — Compteurs en temps réel : total d'alertes, alertes rouges, alertes orange, alertes vertes
2. **Graphique temporel** — Série chronologique des alertes par couleur
3. **Graphique circulaire** — Répartition par type d'attaque
4. **Tableau d'alertes** — Liste détaillée avec lignes colorées selon la sévérité

Rafraîchissement automatique des données depuis la base SQLite.

**Fichier :** `dashboard.py` (54 143 octets)  
**Stylesheet :** `assets/style.css` (16 418 octets)

---

## Stack Technique

| Composant | Technologie |
|-----------|------------|
| Capture réseau | Scapy |
| Machine Learning | scikit-learn 1.6.1 (Random Forest, Isolation Forest, StandardScaler, LabelEncoder) |
| Sérialisation des modèles | joblib |
| Calcul numérique | NumPy, Pandas |
| Base de données | SQLite3 |
| Dashboard web | Dash, Plotly |
| Langage | Python 3 |

---

## Environnement de Laboratoire

Le système est développé et testé dans un environnement virtualisé VMware :

- **Machine cible (serveur)** — Ubuntu VM à l'adresse `192.168.211.50`, héberge le NIDS et les services FTP/SSH
- **Machine attaquante** — Kali Linux VM à l'adresse `192.168.211.128`, exécute les outils d'attaque (Nmap, hping3, Hydra)
- **Réseau** — VMware VMnet1 (réseau privé hôte uniquement)
- **Interface de capture** — `ens33`

---

## Dataset d'entraînement

Un dataset personnalisé (`dataset_maison.csv`, ~508 Ko) a été constitué à partir de captures réelles dans l'environnement de lab, puis utilisé pour entraîner les modèles sur Google Colab. La cohérence entre les versions de scikit-learn (1.6.1) sur Colab et sur la VM Ubuntu est critique pour la compatibilité des fichiers `.joblib`.

---

## Arborescence du Projet

```
nids/
├── capture.py                  # Module 1 — Capture de paquets
├── flux.py                     # Analyse par fenêtres de flux (utilitaire)
├── extraction_complete.py      # Module 2 — Extraction des features
├── detection_complete.py       # Module 3 — Moteur de règles
├── detection_ml.py             # Module 4 — Détection ML
├── detection_fusion.py         # Module 5 — Fusion règles + ML
├── init_db.py                  # Module 6 — Initialisation de la BDD
├── db.py                       # Module 6 — Fonctions d'écriture en BDD
├── dashboard.py                # Module 7 — Tableau de bord Dash
├── collecte_dataset.py         # Script de collecte du dataset
├── dataset_maison.csv          # Dataset d'entraînement
├── modele_ids.joblib            # Modèle Random Forest sérialisé
├── encodeur.joblib              # LabelEncoder sérialisé
├── scaler.joblib                # StandardScaler sérialisé
├── detecteur_anomalies.joblib   # Isolation Forest sérialisé
├── nids_alertes.db              # Base de données SQLite des alertes
├── nids_alertes_backup.db       # Sauvegarde de la BDD
└── assets/
    └── style.css                # Feuille de style du dashboard
```

---

## Leçons Clés et Défis Résolus

1. **Cohérence des features** — Les 10 features exactes utilisées à l'entraînement doivent être reproduites à l'identique en inférence temps réel ; toute divergence produit des prédictions incohérentes.

2. **Fenêtre glissante vs. fenêtre fixe** — Les faux négatifs du moteur de règles provenaient de fenêtres d'évaluation plus courtes que les délais entre flux ; corrigé par une fenêtre glissante de 15 secondes évaluée indépendamment des flux.

3. **Filtrage unidirectionnel** — Les faux positifs de type Port Scan étaient causés par les réponses du serveur ; corrigé en n'analysant que le trafic à destination de la cible (`ip_dst == CIBLE`).

4. **Détection SSH comportementale** — Le trafic SSH étant chiffré, la détection par brute force repose sur le volume de paquets vers le port 22, et non sur l'inspection du contenu applicatif.

5. **Compatibilité scikit-learn** — La version 1.6.1 doit correspondre exactement entre l'environnement d'entraînement (Colab) et l'environnement d'inférence (Ubuntu VM).

---

## État d'Avancement

| Module | Statut |
|--------|--------|
| Module 1 — Capture | Terminé et validé |
| Module 2 — Extraction | Terminé et validé |
| Module 3 — Règles | Terminé et validé |
| Module 4 — ML | Terminé et validé |
| Module 5 — Fusion | Terminé et validé |
| Module 6 — BDD SQLite | Terminé et validé |
| Module 7 — Dashboard | En cours de finalisation |
