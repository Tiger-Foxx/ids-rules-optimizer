import re
from tqdm import tqdm

class RuleCleaner:
    def __init__(self):
        # 1. CE QU'ON REJETTE ABSOLUMENT (Stats de flux & Mémoire inter-paquets)
        self.STATEFUL_KEYWORDS = [
            "flowbits",         # Mémoire entre plusieurs paquets
            "threshold",        # Compteurs de temps
            "detection_filter", # Compteurs de temps
            "stream_size",      # Taille du flux global
            "tag",              # Tagging de session
            "rate_filter",      # Limite de débit
        ]

        # 2. CE QU'ON REJETTE POUR SIMPLIFIER LE MOTEUR C++ (Calculs complexes)
        # Pour la PoC, on se concentre sur l'optimisation Pattern Matching + IP
        self.COMPLEX_LOGIC_KEYWORDS = [
            "byte_test",        # Opérations mathématiques sur payload
            "byte_jump",        # Sauts de pointeur complexes
            "byte_extract",     # Extraction de variable
            "ssl_state",        # Analyse protocolaire SSL fine
            "dsize",            # Taille de paquet (facile mais souvent lié aux stats)
            "isdataat"          # Vérification de curseur
        ]

    def analyze_rule(self, line):
        """
        Analyse intelligente d'une règle.
        Retourne: (Keep/Reject, Raison)
        """
        line_lower = line.lower().strip()
        
        # 1. Ignorer commentaires/vides
        if not line_lower or line_lower.startswith('#'):
            return False, "Ignored"

        # 2. Vérification : Stats de Flux (Flowbits...)
        for kw in self.STATEFUL_KEYWORDS:
            if kw in line_lower:
                # Cas particulier : on accepte 'flow', mais pas 'flowbits'
                # Le mot "flow:" est géré plus bas, ici on cherche les mots exacts
                return False, f"Stateful ({kw})"

        # 3. Vérification : Logique Trop Complexe pour PoC
        for kw in self.COMPLEX_LOGIC_KEYWORDS:
            if kw in line_lower:
                return False, f"Too Complex ({kw})"

        # 4. Analyse fine de l'option 'flow'
        # On accepte "flow:to_server", "flow:established", etc.
        # On refuse si ça contient des trucs bizarres (rare)
        # Ici, comme on a déjà viré les stats, la présence de "flow:" est généralement OK.
        
        # 5. Vérification : La règle a-t-elle du contenu ou est-ce une règle IP pure ?
        # On garde tout le reste.
        return True, "OK"

    def process_file(self, input_path, output_path):
        print(f"[*] Démarrage du nettoyage intelligent sur : {input_path}")
        
        stats = {
            "total": 0,
            "kept": 0,
            "rejected": 0,
            "details": {}
        }
        kept_rules = []

        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            stats["total"] = len(lines)

            for line in tqdm(lines, desc="Analyse des règles", unit="règle"):
                keep, reason = self.analyze_rule(line)
                
                if keep:
                    stats["kept"] += 1
                    kept_rules.append(line)
                else:
                    if reason != "Ignored":
                        stats["rejected"] += 1
                        # Compter les raisons pour le rapport
                        cat = reason.split('(')[0].strip()
                        stats["details"][cat] = stats["details"].get(cat, 0) + 1

        # Écriture
        with open(output_path, 'w', encoding='utf-8') as f_out:
            f_out.writelines(kept_rules)

        self._print_stats(stats, output_path)

    def _print_stats(self, stats, output_path):
        print("\n" + "="*60)
        print("RAPPORT DE NETTOYAGE INTELLIGENT")
        print("="*60)
        print(f"Total lu          : {stats['total']}")
        print(f"REJETÉ (Stats)    : {stats['details'].get('Stateful', 0)} rules (flowbits, threshold...)")
        print(f"REJETÉ (Complexe) : {stats['details'].get('Too Complex', 0)} rules (byte_test, ssl_state...)")
        print("-" * 40)
        print(f"✅ CONSERVÉ       : {stats['kept']} règles")
        print("   (Contient: IP, Ports, Content, PCRE, flow:to_server...)")
        print("="*60)