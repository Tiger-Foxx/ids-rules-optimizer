import os
import argparse
from src.cleaner import RuleCleaner

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

if __name__ == "__main__":
    main()