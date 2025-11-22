import os
import argparse
from src.content_engine import ContentEngine
from src.exporter import Exporter
from src.parser import SnortParser
from src.cleaner import RuleCleaner
from src.ip_engine import IPEngine
# Configuration des chemins
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, 'inputs')
OUTPUT_DIR = os.path.join(BASE_DIR, 'outputs')

def main():
    parser = argparse.ArgumentParser(description="Optimiseur de Règles Réseau - Research PoC")
    parser.add_argument('--rules', type=str, required=True, help="Nom du fichier dans le dossier inputs/")
    args = parser.parse_args()

    input_file = os.path.join(INPUT_DIR, args.rules)
    clean_file = os.path.join(OUTPUT_DIR, 'cleaned_baseline.rules')

    # 1. Vérification
    if not os.path.exists(input_file):
        print(f"[ERREUR] Fichier introuvable : {input_file}")
        return

    # 2. Phase 1 : Nettoyage
    print(">>> PHASE 1 : NETTOYAGE & FILTRAGE")
    cleaner = RuleCleaner()
    cleaner.process_file(input_file, clean_file)
    

    print("\n>>> Prêt pour la PHASE 2 : Parsing & Modélisation")
    
    print("\n>>> PHASE 2 : PARSING & MODÉLISATION")
    parser = SnortParser()
    rules_objects = parser.parse_file(clean_file)
    
    print(f"Règles parsées avec succès : {len(rules_objects)}")
    # Vérification sur une règle complexe (ex: sid 144)
    for r in rules_objects:
        if r.id == 144:
            print(f"\n[DEBUG] Règle SID 144 parsée :")
            print(f"  Proto: {r.proto}")
            print(f"  Dst Port: {r.dst_ports}")
            print(f"  Flow: {r.direction}, Established={r.established}")
            print(f"  Patterns: {len(r.patterns)}")
            for p in r.patterns:
                type_p = "PCRE" if p.is_regex else "CONTENT"
                print(f"    - {type_p}: {p.string_val}")
            break
    
    # 4. Phase 3 : Optimisation Géométrique
    print("\n>>> PHASE 3 : OPTIMISATION GÉOMÉTRIQUE (IP/Ports)")
    ip_opt = IPEngine()
    fw_rules, deep_rules = ip_opt.optimize(rules_objects)
    
    # Calcul du gain
    total_before = len(rules_objects)
    total_after = len(fw_rules) + len(deep_rules)
    reduction = total_before - total_after
    
    print(f"Règles Firewall Pures (-> iptables) : {len(fw_rules)}")
    print(f"Règles Inspection (-> Hyperscan)    : {len(deep_rules)}")
    print(f"------------------------------------------------")
    print(f"Règles Totales après fusion IP      : {total_after}")
    print(f"Réduction initiale                  : -{reduction} règles (Doublons/Merges)")

    print("\n>>> Prêt pour la PHASE 4 : Fusion Sémantique (Patterns)")
    
    # Récupération des résultats de la phase 3
    # Attention: ip_opt.optimize retourne (firewall_rules, inspection_rules)
    # On ne touche PAS aux firewall_rules (elles sont finies).
    # On va optimiser les inspection_rules.
    
    print("\n>>> PHASE 4 : FUSION SÉMANTIQUE (PATTERNS)")
    content_opt = ContentEngine()
    
    # On optimise SEULEMENT les règles d'inspection
    final_inspection_rules = content_opt.optimize(deep_rules)
    
    # Bilan Final
    final_total = len(fw_rules) + len(final_inspection_rules)
    total_reduction = total_before - final_total
    percent = (total_reduction / total_before) * 100
    
    print("\n" + "="*50)
    print("BILAN D'OPTIMISATION")
    print("="*50)
    print(f"Règles Initiales      : {total_before}")
    print(f"Règles Finales        : {final_total}")
    print(f"  - Firewall Pures    : {len(fw_rules)} (-> iptables)")
    print(f"  - Patterns Optimisés: {len(final_inspection_rules)} (-> Hyperscan)")
    print(f"GAIN TOTAL            : {total_reduction} règles supprimées (-{percent:.1f}%)")
    print("="*50)
    
    print("\n>>> Prêt pour la PHASE 5 : EXPORT (C++)")
    
    # 5. Phase 5 : Exportation
    print("\n>>> PHASE 5 : EXPORTATION (C++)")
    
    # On définit le dossier de sortie
    # On utilise OUTPUT_DIR défini en haut du fichier main.py
    exporter = Exporter(OUTPUT_DIR)
    
    # On exporte les règles finales
    # fw_rules = Règles pures (Phase 3)
    # final_inspection_rules = Règles patterns optimisées (Phase 4)
    exporter.export_all(fw_rules, final_inspection_rules)
    
    print("\n" + "="*50)
    print("✅ SUCCÈS : PRÉTRAITEMENT TERMINÉ")
    print(f"Artefacts disponibles dans : {OUTPUT_DIR}")
    print("="*50)

if __name__ == "__main__":
    main()