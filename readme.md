# 🛡️ IDS Rules Optimizer : Optimisation Structurelle & Sémantique pour le Filtrage Réseau

**Dépôt :** [https://github.com/Tiger-Foxx/ids-rules-optimizer](https://github.com/Tiger-Foxx/ids-rules-optimizer)  
**Auteur Principal :** Tiger-Foxx (Projet de Recherche)  
**Technologie :** Python 3 (Pré-traitement) / C++ (Moteur Runtime - *À venir*)  
**Statut :** 🟢 Module d'Optimisation (Core) Terminé & Validé.

---

## 📑 Table des Matières

1.  [Introduction et Contexte Scientifique](#1-introduction-et-contexte-scientifique)
2.  [Objectifs et Hypothèse de Recherche](#2-objectifs-et-hypothèse-de-recherche)
3.  [Architecture Globale du Système](#3-architecture-globale-du-système)
4.  [Méthodologie d'Optimisation (Le Cœur)](#4-méthodologie-doptimisation-le-cœur)
    *   [4.1. Nettoyage Intelligent](#41-nettoyage-intelligent)
    *   [4.2. Modélisation Vectorielle](#42-modélisation-vectorielle)
    *   [4.3. Fusion Géométrique (IP Engine)](#43-fusion-géométrique-ip-engine)
    *   [4.4. Fusion Sémantique (Content Engine)](#44-fusion-sémantique-content-engine)
5.  [Détails Techniques et Algorithmes](#5-détails-techniques-et-algorithmes)
6.  [Résultats et Métriques](#6-résultats-et-métriques)
7.  [Interface avec le Moteur C++](#7-interface-avec-le-moteur-c)
8.  [Limitations et Compromis Assumés](#8-limitations-et-compromis-assumés)
9.  [Installation et Utilisation](#9-installation-et-utilisation)

---

## 1. Introduction et Contexte Scientifique

### Le Problème de l'Empilage ("Security Stacking")
Dans les infrastructures modernes, les paquets traversent une chaîne séquentielle de dispositifs de sécurité :
`Pare-feu L3/L4` $\rightarrow$ `IDS/IPS (Snort/Suricata)` $\rightarrow$ `WAF (ModSecurity)`

Chaque dispositif ajoute :
*   Une latence de traitement (parsing, matching).
*   Des copies mémoire (Zero-Copy impossible sur une chaîne hétérogène).
*   Une consommation CPU redondante (vérifier 3 fois que l'IP n'est pas blacklistée).

**Conséquence :** Une chute drastique du débit utile (jusqu'à -80% observé) et une augmentation de la latence (Jitter).

### Le Concept de "Rejet Précoce"
L'idée est de déplacer la décision de blocage (`DROP`) le plus en amont possible.
Si un paquet est destiné à être rejeté par l'IPS (étape 2) à cause de son contenu, pourquoi gaspiller des cycles CPU dans le Pare-feu (étape 1) ?

Notre projet vise à **unifier mathématiquement** toutes ces règles dans un graphe de décision unique, placé en tête de pont.

---

## 2. Objectifs et Hypothèse de Recherche

### Hypothèse
Il est possible de compiler un ensemble hétérogène de règles (Firewall + IPS) en une **structure de données unifiée** (Arbres + Automates) qui soit :
1.  Plus compacte (moins de règles à vérifier).
2.  Plus rapide (complexité logarithmique $O(\log N)$ au lieu de linéaire $O(N)$).
3.  Strictement équivalente en termes de sécurité (pas de faux négatifs induits).

### Pourquoi ce n'est pas juste "Snort en mieux" ?
Les moteurs comme Snort optimisent le *matching* (trouver un pattern), mais pas la *structure logique* des règles.
*   **Snort :** Lit 10 règles similaires comme 10 entités distinctes.
*   **Notre Optimiseur :** Fusionne ces 10 règles en 1 seule entité mathématique complexe.

**Conséquence :** Nos règles optimisées **NE SONT PLUS** compatibles avec Snort. Elles sont destinées à un moteur C++ dédié (`FoxEngine`), capable de comprendre ces structures fusionnées.

---

## 3. Architecture Globale du Système

Le projet est divisé en deux composants distincts pour séparer l'intelligence (lente) de l'exécution (rapide).

### A. Le Prétraiteur (Python) - *Ce dépôt*
*   **Rôle :** Compilateur de règles ("Offline").
*   **Entrée :** Fichiers textes standards (`snort3-community.rules`).
*   **Traitement :** Analyse sémantique, Algèbre d'ensembles, Théorie des graphes.
*   **Sortie :** Artefacts binaires et scripts optimisés.
*   **Contrainte :** Aucune limite de temps (peut prendre 10 min pour compiler 10k règles).

### B. Le Moteur Runtime (C++) - *Futur dépôt*
*   **Rôle :** Exécution temps réel ("Online").
*   **Entrée :** Artefacts générés par le Python.
*   **Technos :** `NFQUEUE` (interception), `Hyperscan` (Intel Regex), `mmap` (chargement binaire).
*   **Contrainte :** Performance absolue (Zero-Copy).

---

## 4. Méthodologie d'Optimisation (Le Cœur)

Voici comment nous transformons 4000 règles en 300 entités efficaces.

### 4.1. Nettoyage Intelligent (`src/cleaner.py`)
Pour garantir la performance, nous nous limitons au filtrage **Stateless** (sans mémoire inter-paquets) pour cette PoC.

*   **Suppression :**
    *   `flowbits`, `tag` : Nécessitent de stocker un état pour chaque flux (mémoire ++).
    *   `threshold`, `detection_filter` : Nécessitent des compteurs temporels.
    *   `byte_test`, `byte_jump` : Nécessitent une VM arithmétique complexe.
*   **Conservation :**
    *   `flow:to_server/client` : Conservé car déductible du réassemblage TCP.
    *   `flags`, `itype` : Conservés (critiques pour la sécurité).

### 4.2. Modélisation Vectorielle (`src/models.py`)
Nous abandonnons les chaînes de caractères. Chaque règle devient un vecteur mathématique :
$$ R = \{ Proto, \text{SrcIPs}, \text{DstIPs}, \text{SrcPorts}, \text{DstPorts}, \text{Flags}, \text{Patterns} \} $$

*   Les IPs sont gérées comme des **Ensembles Mathématiques** (`netaddr.IPSet`).
*   `$EXTERNAL_NET` devient `UNIVERSE \setminus \{192.168.0.0/16, ...\}`.
*   Cela permet de calculer des intersections et des unions exactes.

### 4.3. Fusion Géométrique (IP Engine) : "Hypercube Convergence"
C'est notre algorithme de réduction spatiale.
*   **Problème :** Comment fusionner des règles sans créer de trous de sécurité ?
    *   *Exemple dangereux :* Fusionner une règle `SYN-Only` avec une règle `ALL-TCP`.
*   **Solution :** Signature de Fusion Stricte.
    *   On ne fusionne que si `Proto + Flags + IcmpType + Direction` sont identiques.
*   **Algorithme :** Boucle de convergence (Point Fixe).
    1.  Fusionne les Sources (si Dst/Ports identiques).
    2.  Fusionne les Destinations (si Src/Ports identiques).
    3.  Fusionne les Services (Ports).
    *   Répète tant que le nombre de règles diminue.

### 4.4. Fusion Sémantique (Content Engine) : "Trie Factorization"
C'est l'algorithme de compression des signatures.
*   **Problème :** Hyperscan est rapide, mais 10 000 patterns consomment trop de mémoire.
*   **Solution Hybride :**
    1.  **Règles Simples (1 pattern) :** Utilisation d'un **Arbre de Préfixes (Trie)**.
        *   `admin.php`, `admin.html` $\rightarrow$ Regex factorisée `admin\.(php|html)`.
        *   Paramètre `self.min_prefix_len = 4` : Empêche de fusionner des mots trop courts (ex: "get" et "got") qui créeraient des regex inefficaces.
    2.  **Règles Complexes (Multi-patterns) :** Hachage Strict.
        *   On ne fusionne que si *toute la séquence* de patterns est identique.

---

## 5. Détails Techniques et Algorithmes

### Gestion de la Sécurité (Le "Produit Cartésien")
Une erreur classique en optimisation de pare-feu est de fusionner simultanément Sources et Destinations :
*   R1: A -> B
*   R2: C -> D
*   Fusion Naïve : {A,C} -> {B,D}
*   **Faille :** Cela autorise A -> D (qui était interdit).

**Notre solution :** L'algorithme `src/ip_engine.py` utilise une approche itérative par dimension. On ne fusionne une dimension que si **toutes les autres sont invariantes**.

### Le Format "MessagePack"
Pourquoi pas JSON ?
*   **JSON :** Texte, lent à parser, verbeux.
*   **MessagePack :** Binaire, compact, chargement quasi-instantané en C++.
*   Le fichier `rules_config.msgpack` contient la "carte" du réseau pour le moteur C++.

---

## 6. Résultats et Métriques

**Dataset de Test :** `snort3-community.rules` (Version 2025)

| Métrique | Valeur | Commentaire |
| :--- | :--- | :--- |
| **Règles Brutes** | 4017 | Fichier texte original |
| **Après Nettoyage** | 3185 | Périmètre "Stateless" conservé |
| **Après Fusion IP** | 3137 | Réduction modeste (les règles IPS sont très spécifiques) |
| **Après Fusion Patterns** | **1835** | **Réduction finale de -42.4%** |

**Analyse :**
Nous avons divisé par presque 2 le nombre d'entités logiques que le processeur doit évaluer. C'est un gain théorique massif pour le débit.

*   **Règles "Firewall Pures" (85 règles) :** Ce sont des règles sans contenu (ex: IP Reputation). Elles seront traitées par `iptables` (Kernel) pour une vitesse lumière.
*   **Règles "Inspection" (1750 règles) :** Elles nécessitent Hyperscan.

---

## 7. Interface avec le Moteur C++

Le moteur C++ (`FoxEngine`) est conçu pour être "idiot et rapide". Il ne réfléchit pas, il exécute les ordres contenus dans les artefacts.

### Les 3 Fichiers Livrés

1.  **`firewall.sh` (Script Bash)**
    *   **Rôle :** Délestage Kernel.
    *   **Action :** Configure `iptables` pour bloquer silencieusement les IPs/Ports connus avant même qu'ils n'atteignent l'espace utilisateur.
    *   **Gain :** Zéro coût CPU pour l'application.

2.  **`patterns.txt` (Texte)**
    *   **Rôle :** Base de données Hyperscan.
    *   **Format :** `ID:/regex/flags`.
    *   **Contenu :** Les regex factorisées (ex: `1:/virus(A|B)/`).

3.  **`rules_config.msgpack` (Binaire)**
    *   **Rôle :** Cerveau Logique.
    *   **Contenu :** Arbres de décision. "Si IP src $\in$ {A,B,C} et Port=80 $\rightarrow$ Alors scanne avec le pattern ID 1".
    *   **Usage :** Chargé en RAM au démarrage.

### Protocole de Comparaison (Benchmark)
Pour prouver l'efficacité de notre optimisation, nous utiliserons le **MÊME moteur C++** avec deux configurations :

1.  **Mode Baseline (Témoin) :**
    *   On désactive la fusion dans Python.
    *   Output : 3185 règles unitaires.
    *   Le C++ charge 3185 entrées.
2.  **Mode Optimisé (Expérience) :**
    *   On active la fusion.
    *   Output : 1835 règles fusionnées.
    *   Le C++ charge 1835 entrées.

**Mesure :** Différence de débit (Gbps) et Latence (µs) sur un trafic de test (ex: `tcpreplay`). La différence sera purement imputable à notre algorithme.

---

## 8. Limitations et Compromis Assumés

1.  **Incompatibilité Snort :** Nos règles optimisées ne peuvent plus être lues par Snort. C'est un choix assumé pour briser les limites de performance.
2.  **Perte de Traçabilité Granulaire :** Si un paquet est bloqué par une règle fusionnée "Malware Web", on ne saura pas forcément si c'était "Malware A" ou "Malware B".
    *   *Justification :* En défense opérationnelle, l'important est de bloquer la menace, pas forcément de connaître son nom de baptême exact à la microseconde près.
3.  **Scope Stateless :** Les attaques complexes nécessitant une corrélation temporelle longue (ex: Brute Force lent) ne sont pas couvertes par cette PoC.

---

## 9. Installation et Utilisation

### Pré-requis
*   Python 3.10+
*   Libs : `netaddr`, `intervaltree`, `z3-solver`, `msgpack`, `tqdm`

### Lancement
1.  Placer le fichier de règles dans `inputs/`.
2.  Exécuter :
    ```bash
    python main.py --rules snort3-community.rules
    ```
3.  Récupérer les artefacts dans `outputs/`.

---

*Ce projet est une contribution académique à l'étude des structures de données haute performance pour la cybersécurité.*