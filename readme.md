# 📘 MASTERPLAN : OPTIMISATION DU FILTRAGE RÉSEAU PAR AGRÉGATION STRUCTURELLE

**Type de projet :** Recherche Scientifique / Preuve de Concept (PoC)  
**Objectif :** Maximisation du débit et réduction de latence dans les chaînes de sécurité.  
**Statut :** Phase de conception validée - Prêt pour implémentation.

---

## 1. CONTEXTE ET PROBLÉMATIQUE SCIENTIFIQUE

### 1.1. Le Constat Industriel
Les infrastructures modernes empilent les dispositifs de sécurité (Pare-feu $\rightarrow$ IPS $\rightarrow$ WAF).
*   **Problème :** Chaque dispositif ajoute une latence de traitement et des copies mémoire.
*   **Mesures :** L'empilage peut réduire le débit utile jusqu'à **80%**.
*   **Inefficacité :** Un paquet malveillant traverse souvent toute la chaîne pour être rejeté par le dernier maillon. C'est un gaspillage de ressources CPU et énergétiques ("Parcours Inutile").

### 1.2. L'Hypothèse de Recherche
Il est possible de **fusionner mathématiquement** les règles de tous les dispositifs en un seul **Moteur de Filtrage Précoce**.
*   Ce moteur se place en tête de chaîne.
*   Il décide immédiatement : `DROP` ou `PASS`.
*   **Levier d'optimisation :** En acceptant de ne pas savoir *quelle* règle précise a matché (on veut juste bloquer les menaces), on débloque des possibilités de fusion de règles (algébriques et sémantiques) impossibles à réaliser dans les moteurs standards (Snort/Suricata).

---

## 2. ARCHITECTURE DU SYSTÈME

Le projet se divise en deux blocs totalement distincts :

1.  **Le Prétraiteur (Rule Optimizer) - Python :**
    *   S'exécute "Hors Ligne" (avant le lancement).
    *   Temps d'exécution : Non contraint (peut prendre 1h si nécessaire).
    *   Rôle : Digérer des milliers de règles brutes et produire des **structures binaires optimales**.
    *   Technos : Graph Theory, SMT Solvers (Z3), Suffix Trees.

2.  **Le Filtreur (Engine) - C++ :**
    *   S'exécute "En Temps Réel" (Runtime).
    *   Performance : Critique (Zero-copy, Lock-free).
    *   Rôle : Charger les binaires en RAM et filtrer les paquets à la volée.
    *   Technos : Hyperscan, mmap, NFQUEUE/XDP.

---

## 3. STRUCTURE DÉTAILLÉE DU MODULE D'OPTIMISATION (PYTHON)

Ce module est le cœur de l'intelligence du projet.

```text
research_optimizer/
│
├── README.md                # Documentation scientifique des algorithmes
├── requirements.txt         # netaddr, z3-solver, intervaltree, msgpack
├── main.py                  # Orchestrateur (CLI)
│
├── inputs/                  # Entrée : Fichiers .rules (Snort/ET Open)
├── outputs/                 # Sortie : Artefacts pour le moteur C++
│
└── src/                     # COEUR DU CODE
    ├── __init__.py
    │
    ├── cleaner.py           # [FILTRE]
    │                        Rôle : Nettoyage syntaxique et sémantique.
    │                        Action : Supprime flowbits, threshold, règles stateful complexes.
    │
    ├── parser.py            # [TRADUCTION]
    │                        Rôle : Parsing Snort vers DSL Interne (Objets Python).
    │                        Action : Normalise les IPs, Ports, négations.
    │
    ├── models.py            # [STRUCTURE]
    │                        Rôle : Définition des classes (Rule, Pattern, IPRange).
    │                        Concept : Représentation vectorielle d'une règle.
    │
    ├── ip_engine.py         # [GÉOMÉTRIE]
    │                        Rôle : Fusion 2D (IP x Port).
    │                        Algo : Sweep-line / Interval Trees.
    │                        Output : Isole les règles "Pure Drop" (sans payload).
    │
    ├── content_engine.py    # [SÉMANTIQUE]
    │                        Rôle : Fusion des signatures (Patterns).
    │                        Algo : Suffix Trees, Clustering (Levenshtein), Regex Synthesis.
    │                        But : 10 000 patterns -> 300 regex optimisées.
    │
    ├── inference.py         # [LOGIQUE FORMELLE]
    │                        Rôle : Détection de redondance (Subsomption).
    │                        Algo : SMT Solver (Z3). "Prouver que Règle A englobe Règle B".
    │
    └── exporter.py          # [COMPILATION]
                             Rôle : Génération des artefacts finaux.
                             Sorties : 
                               - filter_structures.bin (Arbres IP)
                               - patterns.txt (Hyperscan)
                               - firewall.sh (iptables offload)
                               - metadata.json (Lien logique)
```

---

## 4. LES ARTEFACTS DE SORTIE (L'INTERFACE PYTHON -> C++)

Le C++ ne parse pas de texte. Il charge ces fichiers directement en mémoire (RAM).

| Fichier | Format | Usage par le C++ |
| :--- | :--- | :--- |
| **`firewall.sh`** | Script Bash | Exécuté au boot. Injecte les règles "IP/Port DROP" directes dans le Kernel (iptables). Déleste le CPU. |
| **`filter_structures.bin`** | Binaire (MsgPack/Struct) | Chargé via `mmap`. Contient les Arbres (Tries) et HashMaps pour le filtrage IP/Port/Proto ultra-rapide. |
| **`patterns.txt`** | Texte (Regex) | Lu pour compiler la base de données **Hyperscan** (Payload matching). |
| **`metadata.json`** | JSON | Table de liaison. *"Si match dans le Nœud 4 de l'arbre IP -> Scanner avec le Groupe Pattern 12"*. |

---

## 5. PLAN DE DÉVELOPPEMENT COMPLET

Nous allons procéder module par module pour garantir la qualité.

### **PHASE 1 : Fondations & Nettoyage (Jours 1-2)**
*   **Objectif :** Avoir une base de règles saine.
*   **Tâches :**
    1.  Mise en place de l'environnement (venv, libs).
    2.  Implémentation de `cleaner.py` (Regex strictes pour écarter les règles stateful/stats).
    3.  Test sur le dataset *Snort Community*.

### **PHASE 2 : Modélisation & Parsing (Jours 3-4)**
*   **Objectif :** Transformer le texte en objets mathématiques manipulables.
*   **Tâches :**
    1.  Coder `models.py` (Structure des vecteurs).
    2.  Coder `parser.py` (Gestion des `any`, variables, négations `!`).
    3.  Validation : Re-générer des règles texte pour vérifier l'intégrité.

### **PHASE 3 : Optimisation Structurelle - IP/Ports (Jours 5-7)**
*   **Objectif :** Réduire l'espace de recherche géométrique.
*   **Tâches :**
    1.  Implémenter `ip_engine.py` avec `intervaltree` et `netaddr`.
    2.  Algo de fusion : `192.168.1.0/24` + `192.168.0.0/24` $\rightarrow$ `/23`.
    3.  Algo de détection "Pure Drop" (Extraction vers Firewall).

### **PHASE 4 : Optimisation Sémantique - Patterns (Jours 8-12)**
*   **Objectif :** Le cœur de la compression.
*   **Tâches :**
    1.  Implémenter `content_engine.py`.
    2.  Arbres de suffixes pour trouver les facteurs communs.
    3.  Clustering : Grouper les patterns similaires.
    4.  Génération de Regex compatibles Hyperscan (éviter les `.*` explosifs).

### **PHASE 5 : Inférence & Subsomption (Jours 13-15)**
*   **Objectif :** Nettoyage logique formel.
*   **Tâches :**
    1.  Intégrer **Z3 Solver** dans `inference.py`.
    2.  Définir les contraintes logiques.
    3.  Supprimer les règles mathématiquement inutiles (A englobe B).

### **PHASE 6 : Export & Validation (Jours 16-17)**
*   **Objectif :** Prêt pour le C++.
*   **Tâches :**
    1.  Coder `exporter.py`.
    2.  Générer les binaires et JSON.
    3.  Produire un rapport de statistiques (ex: "10 000 règles $\rightarrow$ 280 structures").

---

## 6. VALIDATION SCIENTIFIQUE (MÉTHODOLOGIE)

Pour prouver l'efficacité dans le papier :

1.  **Dataset de test :** Snort Community Rules (~4000 règles pertinentes).
2.  **Baseline (Témoin) :** On lance l'optimiseur en mode "Pass-through" (Désactivé).
    *   Output : 4000 structures unitaires.
3.  **Expérience (Optimisé) :** On lance l'optimiseur complet.
    *   Output : ~300 structures fusionnées.
4.  **Mesure :** Le moteur C++ (le même binaire) exécutera les deux sets. La différence de FPS (Frames Per Second) sera purement due à notre algorithme d'optimisation.
