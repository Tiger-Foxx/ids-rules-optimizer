import re
from collections import defaultdict
from typing import Dict, Set, Tuple, List
import netaddr
from .models import RuleVector, Pattern


# =============================================================================
# STRUCTURES DE DONNÉES POUR LA FACTORISATION TRIE
# =============================================================================

class TrieNode:
    """
    Nœud Trie pour la factorisation par préfixe commun.
    Optimisé avec __slots__ pour réduire l'empreinte mémoire.
    """
    __slots__ = ['children', 'is_end', 'pattern_keys']
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end: bool = False
        self.pattern_keys: Set[Tuple] = set()


# =============================================================================
# MOTEUR D'OPTIMISATION SÉMANTIQUE AVANCÉE
# =============================================================================

class ContentEngine:
    """
    Moteur d'optimisation des règles de contenu (patterns) avec FACTORISATION TRIE.
    
    STRATÉGIE D'OPTIMISATION SÉMANTIQUE (Recommandation Expert IA)
    ==============================================================
    
    L'agrégation contextuelle seule NE RÉDUIT PAS la complexité de l'automate
    Hyperscan. Les expressions OR géantes (2991 IDs) maintiennent N automates
    atomiques actifs → ZÉRO gain de performance réel.
    
    SOLUTION : Factorisation Lexicale Globale par Trie
    --------------------------------------------------
    
    Transformation : "GET /admin" + "GET /config" → "GET /(admin|config)"
    
    AVANT (2 patterns atomiques):
        Pattern 1: /GET \/admin/
        Pattern 2: /GET \/config/
        → Hyperscan compile 2 automates distincts
    
    APRÈS (1 pattern factorisé):
        Pattern X: /GET \/(?:admin|config)/
        → Hyperscan compile 1 automate avec alternation interne
        → Réduction RÉELLE du travail de scan
    
    PIPELINE :
    1. Extraction Globale : Tous les patterns uniques → normalisation
    2. Ségrégation : Littéraux (candidats Trie) vs PCRE complexes
    3. Factorisation Trie : Préfixe commun ≥4 chars, branching ≥2
    4. Réinjection : Mise à jour des règles avec patterns factorisés
    5. Agrégation Finale : Déduplication + agrégation contextuelle
    """
    
    def __init__(self):
        # Heuristiques de performance (recommandation expert)
        self.MIN_PREFIX_LEN = 4    # Longueur min du préfixe commun
        self.MIN_BRANCHING_FACTOR = 2  # Nombre min de patterns à fusionner

    def _validate_regex_parentheses(self, regex: str) -> bool:
        """
        Vérifie que les parenthèses sont équilibrées dans la regex.
        
        Gère les cas échappés : \\( et \\) ne comptent pas.
        Retourne True si valide, False sinon.
        """
        depth = 0
        i = 0
        while i < len(regex):
            char = regex[i]
            
            # Vérifier si c'est un caractère échappé
            if char == '\\' and i + 1 < len(regex):
                # Skip le caractère échappé
                i += 2
                continue
            
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth < 0:
                    return False  # Trop de parenthèses fermantes
            
            i += 1
        
        return depth == 0  # True si toutes les parenthèses sont fermées

    def optimize(self, rules: List[RuleVector]) -> List[RuleVector]:
        """
        Pipeline d'optimisation avec FUSION SÛRE.
        
        Stratégie :
        1. Déduplication exacte des patterns identiques
        2. Fusion SÛRE : patterns avec préfixe commun ≥50% de leur longueur
        3. Agrégation par contexte réseau (IP/Port)
        """
        print(f"[*] Démarrage de l'Optimisation Sémantique (Fusion Sûre)...")
        
        # Filtrer les règles avec patterns
        rules_with_patterns = [r for r in rules if r.patterns]
        print(f"    - Règles avec patterns : {len(rules_with_patterns)}")
        
        # Stats initiales
        initial_patterns = set()
        for r in rules_with_patterns:
            for p in r.patterns:
                initial_patterns.add((p.string_val, str(p.modifiers)))
        print(f"    - Patterns uniques initiaux : {len(initial_patterns)}")

        # =================================================================
        # PHASE 1 : DÉDUPLICATION EXACTE
        # =================================================================
        deduplicated_rules = self._deduplicate_exact(rules_with_patterns)
        print(f"    - Après déduplication exacte : {len(deduplicated_rules)}")

        # =================================================================
        # PHASE 2 : FUSION SÛRE (préfixe commun ≥50%)
        # =================================================================
        fused_rules = self._safe_prefix_fusion(deduplicated_rules)
        
        # Compter les patterns après fusion
        patterns_after_fusion = set()
        for r in fused_rules:
            for p in r.patterns:
                patterns_after_fusion.add((p.string_val, str(p.modifiers)))
        
        fusion_gain = len(initial_patterns) - len(patterns_after_fusion)
        print(f"    - Après fusion sûre : {len(patterns_after_fusion)} patterns (-{fusion_gain})")

        # =================================================================
        # PHASE 3 : AGRÉGATION PAR CONTEXTE RÉSEAU
        # =================================================================
        final_rules = self._aggregate_by_network_context(fused_rules)
        print(f"    - Règles finales : {len(final_rules)}")

        # Stats finales
        final_patterns = set()
        for r in final_rules:
            for p in r.patterns:
                final_patterns.add((p.string_val, str(p.modifiers)))
        
        reduction = len(initial_patterns) - len(final_patterns)
        percent = (reduction / len(initial_patterns) * 100) if initial_patterns else 0
        print(f"    >>> GAIN TOTAL : {len(initial_patterns)} -> {len(final_patterns)} patterns (-{percent:.1f}%)")

        return final_rules

    def _safe_prefix_fusion(self, rules: List[RuleVector]) -> List[RuleVector]:
        """
        Fusion SÛRE : fusionne les patterns qui partagent un préfixe commun
        d'au moins 50% de leur longueur minimale.
        
        Exemple :
        - "GET /admin/dashboard.php" + "GET /admin/settings.php"
        - Préfixe commun : "GET /admin/" (11 chars)
        - Longueur min : 25 chars
        - Ratio : 44% < 50% => PAS fusionné
        
        - "attack_payload_variant1" + "attack_payload_variant2"
        - Préfixe commun : "attack_payload_variant" (22 chars)
        - Longueur min : 23 chars
        - Ratio : 95% >= 50% => FUSIONNÉ
        """
        MIN_PREFIX_RATIO = 0.5  # Le préfixe doit faire au moins 50% du pattern
        MIN_PREFIX_LEN = 15     # Le préfixe doit faire au moins 15 caractères
        MIN_GROUP_SIZE = 3      # Il faut au moins 3 patterns pour fusionner
        
        # Extraire tous les patterns uniques avec leurs règles
        pattern_to_rules: Dict[str, List[RuleVector]] = {}
        for rule in rules:
            for p in rule.patterns:
                if not p.is_regex:  # Seulement les littéraux
                    key = p.string_val
                    if key not in pattern_to_rules:
                        pattern_to_rules[key] = []
                    pattern_to_rules[key].append(rule)
        
        # Trouver les groupes de patterns avec préfixe commun long
        patterns_list = list(pattern_to_rules.keys())
        fused_patterns = {}  # old_pattern -> new_pattern (ou None si pas fusionné)
        processed = set()
        
        for i, p1 in enumerate(patterns_list):
            if p1 in processed:
                continue
            
            # Trouver tous les patterns qui partagent un préfixe long avec p1
            group = [p1]
            for j, p2 in enumerate(patterns_list):
                if i == j or p2 in processed:
                    continue
                
                # Calculer le préfixe commun
                prefix_len = 0
                for c1, c2 in zip(p1, p2):
                    if c1 == c2:
                        prefix_len += 1
                    else:
                        break
                
                min_len = min(len(p1), len(p2))
                ratio = prefix_len / min_len if min_len > 0 else 0
                
                if prefix_len >= MIN_PREFIX_LEN and ratio >= MIN_PREFIX_RATIO:
                    group.append(p2)
            
            # Si le groupe est assez grand, fusionner
            if len(group) >= MIN_GROUP_SIZE:
                # Trouver le préfixe commun à TOUT le groupe
                common_prefix = group[0]
                for p in group[1:]:
                    new_prefix = ""
                    for c1, c2 in zip(common_prefix, p):
                        if c1 == c2:
                            new_prefix += c1
                        else:
                            break
                    common_prefix = new_prefix
                
                if len(common_prefix) >= MIN_PREFIX_LEN:
                    # Créer le pattern fusionné
                    suffixes = [p[len(common_prefix):] for p in group]
                    suffixes = [s for s in suffixes if s]  # Enlever les vides
                    
                    if suffixes:
                        # Échapper pour regex
                        escaped_prefix = re.escape(common_prefix)
                        escaped_suffixes = sorted([re.escape(s) for s in suffixes], key=len, reverse=True)
                        fused_regex = f"{escaped_prefix}(?:{'|'.join(escaped_suffixes)})"
                        
                        for p in group:
                            fused_patterns[p] = fused_regex
                            processed.add(p)
        
        # Créer les nouvelles règles avec patterns fusionnés
        if not fused_patterns:
            print(f"        [INFO] Aucun groupe de patterns similaires trouvé")
            return rules
        
        print(f"        [INFO] {len(fused_patterns)} patterns fusionnés en groupes")
        
        # Appliquer les fusions
        updated_rules = []
        for rule in rules:
            new_patterns = []
            for p in rule.patterns:
                if p.string_val in fused_patterns:
                    # Remplacer par le pattern fusionné
                    new_patterns.append(Pattern(
                        string_val=fused_patterns[p.string_val],
                        is_regex=True,
                        modifiers=p.modifiers
                    ))
                else:
                    new_patterns.append(p)
            
            rule.patterns = new_patterns
            updated_rules.append(rule)
        
        return updated_rules

    # =========================================================================
    # PHASE 1 & 2 : EXTRACTION ET SÉGRÉGATION
    # =========================================================================

    def _extract_and_normalize_patterns(self, rules: List[RuleVector]) -> Dict[Tuple, dict]:
        """
        Extrait et normalise tous les patterns atomiques de toutes les règles.
        
        Retourne un dict {(string, is_regex, flags): pattern_info}
        """
        patterns = {}
        
        for r in rules:
            if not hasattr(r, 'patterns') or not r.patterns:
                continue
                
            for p in r.patterns:
                if not p.string_val:
                    continue
                
                # Normalisation des flags
                flags = ''
                modifiers_str = str(p.modifiers).lower() if p.modifiers else ''
                if 'nocase' in modifiers_str:
                    flags += 'i'
                
                # Clé unique stable (string, is_regex, flags)
                key = (p.string_val, p.is_regex, flags)
                
                if key not in patterns:
                    patterns[key] = {
                        'string': p.string_val,
                        'is_regex': p.is_regex,
                        'flags': flags,
                        'key': key
                    }
        
        return patterns

    def _segregate_patterns(self, atomic_patterns: Dict[Tuple, dict]) -> Tuple[Dict, Dict]:
        """
        Sépare les patterns littéraux (candidats Trie) des PCRE complexes.
        
        Seuls les littéraux (is_regex=False) sont candidats à la factorisation.
        Les PCRE sont préservés tels quels.
        """
        simple = {}
        complex_p = {}
        
        for key, p_obj in atomic_patterns.items():
            if not p_obj['is_regex']:
                simple[key] = p_obj
            else:
                complex_p[key] = p_obj
        
        return simple, complex_p

    # =========================================================================
    # PHASE 3 : ALGORITHME DE FACTORISATION TRIE
    # =========================================================================

    def _factorize_patterns(self, simple_patterns: Dict[Tuple, dict]) -> Dict[Tuple, Pattern]:
        """
        Groupe les patterns par flags et lance la factorisation Trie.
        
        Retourne un mapping {original_key → fused_Pattern}
        """
        # Grouper par flags (nocase vs case-sensitive)
        groups_by_flags = defaultdict(list)
        for key, p_obj in simple_patterns.items():
            groups_by_flags[p_obj['flags']].append(p_obj)
        
        factorized_map = {}
        
        for flags, group in groups_by_flags.items():
            if len(group) >= self.MIN_BRANCHING_FACTOR:
                self._run_trie_factorization(group, flags, factorized_map)
        
        return factorized_map

    def _run_trie_factorization(self, patterns_list: List[dict], flags: str, 
                                  factorized_map: Dict[Tuple, Pattern]):
        """
        Construction du Trie et factorisation par préfixe commun.
        """
        root = TrieNode()

        # 1. Construction du Trie
        for p_obj in patterns_list:
            s = p_obj['string']
            node = root
            
            for char in s:
                if char not in node.children:
                    node.children[char] = TrieNode()
                node = node.children[char]
                # Tracking des clés de patterns le long du chemin
                node.pattern_keys.add(p_obj['key'])
            
            node.is_end = True

        # 2. Traversée et Factorisation
        self._traverse_and_factorize(root, "", flags, factorized_map)

    def _traverse_and_factorize(self, node: TrieNode, current_prefix: str, 
                                  flags: str, factorized_map: Dict[Tuple, Pattern]):
        """
        Parcours récursif du Trie pour identifier les points de factorisation.
        
        Condition de factorisation :
        - Préfixe >= MIN_PREFIX_LEN caractères
        - >= MIN_BRANCHING_FACTOR patterns passent par ce nœud
        """
        # Vérifier la condition de factorisation
        if (len(current_prefix) >= self.MIN_PREFIX_LEN and 
            len(node.pattern_keys) >= self.MIN_BRANCHING_FACTOR):
            
            # FACTORISATION DÉTECTÉE !
            keys_to_factorize = node.pattern_keys.copy()
            
            # 1. Collecter les suffixes restants
            suffixes = []
            self._collect_suffixes(node, "", suffixes)

            # 2. Construction de la Regex Factorisée
            prefix_escaped = re.escape(current_prefix)
            
            # Gestion du suffixe vide (le préfixe est lui-même un pattern complet)
            prefix_is_pattern = "" in suffixes
            if prefix_is_pattern:
                suffixes.remove("")

            # Échappement et tri des suffixes (plus long d'abord pour matching gourmand)
            # FILTRE CRITIQUE : Exclure les suffixes trop courts (< 15 chars)
            # Les suffixes courts comme "-Agent:" matchent tout le trafic HTTP
            MIN_SUFFIX_LEN = 15
            escaped_suffixes = sorted(
                list(set(re.escape(s) for s in suffixes if s and len(s) >= MIN_SUFFIX_LEN)), 
                key=len, 
                reverse=True
            )
            
            # Si pas assez de suffixes longs, abandonner cette factorisation
            if len(escaped_suffixes) < self.MIN_BRANCHING_FACTOR:
                for char, child in node.children.items():
                    self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)
                return
            
            # =================================================================
            # CORRECTION ANTI-FAUX-POSITIFS : Ne JAMAIS générer (?:|...)
            # =================================================================
            # Le format (?:|alt1|alt2) permet de matcher juste le préfixe seul,
            # ce qui crée des faux positifs massifs (ex: "User-Agent:" seul)
            # 
            # NOUVELLE STRATÉGIE :
            # - Si prefix seul EST un pattern : NE PAS le factoriser, skip
            # - Sinon : factoriser normalement avec (?:alt1|alt2)
            
            if prefix_is_pattern:
                # Le préfixe seul est un pattern → Dangereux de factoriser
                # On abandonne cette factorisation pour éviter (?:|...)
                for char, child in node.children.items():
                    self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)
                return
            
            # Construction de l'alternation SANS alternative vide
            if escaped_suffixes:
                alternation = "|".join(escaped_suffixes)
                fused_regex = f"{prefix_escaped}(?:{alternation})"
            else:
                # Pas de suffixes valides → pas de factorisation
                return

            # =================================================================
            # VALIDATION : Vérifier les parenthèses équilibrées
            # =================================================================
            if not self._validate_regex_parentheses(fused_regex):
                # Pattern malformé ! On abandonne cette factorisation
                # et on continue la descente pour factoriser plus bas
                for char, child in node.children.items():
                    self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)
                return

            # Création du Pattern factorisé
            fused_pattern = Pattern(
                string_val=fused_regex,
                is_regex=True,  # C'est maintenant une regex
                modifiers={'nocase': 'true'} if 'i' in flags else {}
            )
            
            # Mise à jour du mapping pour toutes les clés concernées
            for key in keys_to_factorize:
                if key not in factorized_map:
                    factorized_map[key] = fused_pattern
            
            # Arrêt de la descente : ce sous-arbre est consommé
            return

        # Descente récursive si pas factorisé
        for char, child in node.children.items():
            self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)

    def _collect_suffixes(self, node: TrieNode, current_suffix: str, suffixes: List[str]):
        """
        Collecte récursive de tous les suffixes à partir d'un nœud.
        Inclut les terminaisons internes (nœuds is_end au milieu du Trie).
        """
        if node.is_end:
            suffixes.append(current_suffix)

        for char, child in node.children.items():
            self._collect_suffixes(child, current_suffix + char, suffixes)

    # =========================================================================
    # PHASE 4 : RÉINJECTION
    # =========================================================================

    def _reinject_patterns(self, rules: List[RuleVector], 
                            factorized_map: Dict[Tuple, Pattern]) -> List[RuleVector]:
        """
        Remplace les patterns atomiques par leurs versions factorisées.
        """
        updated_rules = []
        
        for r in rules:
            if not hasattr(r, 'patterns') or not r.patterns:
                updated_rules.append(r)
                continue

            new_patterns = []
            patterns_changed = False
            seen_fused = set()  # Pour éviter les doublons de patterns factorisés
            
            for p in r.patterns:
                if not p.string_val:
                    continue

                # Reconstitution de la clé
                flags = ''
                modifiers_str = str(p.modifiers).lower() if p.modifiers else ''
                if 'nocase' in modifiers_str:
                    flags += 'i'
                key = (p.string_val, p.is_regex, flags)

                # Remplacement si factorisé
                if key in factorized_map:
                    fused = factorized_map[key]
                    fused_id = id(fused)
                    
                    # Éviter les doublons (plusieurs patterns originaux → même factorisé)
                    if fused_id not in seen_fused:
                        new_patterns.append(fused)
                        seen_fused.add(fused_id)
                    
                    patterns_changed = True
                else:
                    new_patterns.append(p)
            
            if patterns_changed:
                # Construction de la nouvelle règle
                new_rule = RuleVector(
                    id=r.id,
                    original_text=r.original_text + " [FACTORIZED]",
                    proto=r.proto,
                    src_ips=r.src_ips,
                    src_ports=r.src_ports,
                    dst_ips=r.dst_ips,
                    dst_ports=r.dst_ports,
                    direction=r.direction,
                    established=r.established,
                    tcp_flags=r.tcp_flags,
                    icmp_type=r.icmp_type,
                    icmp_code=r.icmp_code,
                    action=r.action,
                    patterns=new_patterns
                )
                updated_rules.append(new_rule)
            else:
                updated_rules.append(r)
        
        return updated_rules

    # =========================================================================
    # PHASE 5 : DÉDUPLICATION ET AGRÉGATION
    # =========================================================================

    def _deduplicate_exact(self, rules: List[RuleVector]) -> List[RuleVector]:
        """
        Déduplication exacte des règles après factorisation.
        Utilise le hash des objets Pattern pour comparaison.
        """
        groups = defaultdict(list)
        
        for r in rules:
            if not r.patterns:
                continue

            k_dst_pt = tuple(sorted(str(c) for c in r.dst_ports.iter_cidrs()))
            
            # Utilisation de frozenset sur les objets Pattern (hashables)
            try:
                k_patterns = frozenset(r.patterns)
            except TypeError:
                # Fallback si Pattern pas hashable
                k_patterns = frozenset(
                    (p.string_val, p.is_regex, tuple(sorted(p.modifiers.items())) if p.modifiers else ())
                    for p in r.patterns
                )
            
            sig = (r.proto, k_dst_pt, r.direction, k_patterns, r.action)
            groups[sig].append(r)
            
        results = []
        for sig, group in groups.items():
            if len(group) > 1:
                results.append(self._merge_contexts(group))
            else:
                results.append(group[0])
        
        return results

    def _merge_contexts(self, rules: List[RuleVector]) -> RuleVector:
        """
        Fusionne N règles identiques (mêmes patterns) en une seule.
        Fusionne les IPs sources/destinations (union mathématique).
        """
        base = rules[0]
        
        new_src_ips = netaddr.IPSet()
        new_dst_ips = netaddr.IPSet()
        new_src_ports = netaddr.IPSet()
        
        for r in rules:
            new_src_ips.update(r.src_ips)
            new_dst_ips.update(r.dst_ips)
            new_src_ports.update(r.src_ports)
            
        return RuleVector(
            id=base.id,
            original_text=f"MERGED ({len(rules)} rules) " + base.original_text,
            proto=base.proto,
            src_ips=new_src_ips,
            src_ports=new_src_ports,
            dst_ips=new_dst_ips,
            dst_ports=base.dst_ports,
            direction=base.direction,
            established=base.established,
            tcp_flags=base.tcp_flags,
            icmp_type=base.icmp_type,
            icmp_code=base.icmp_code,
            action=base.action,
            patterns=base.patterns
        )

    def _aggregate_by_network_context(self, rules: List[RuleVector]) -> List[RuleVector]:
        """
        AGRÉGATION NIVEAU 1 : DÉSACTIVÉE pour les patterns différents.
        
        ANALYSE DU PROBLÈME
        ===================
        Fusionner des règles avec patterns DIFFÉRENTS en logique OR détruit
        la sémantique originale des règles Snort.
        
        Exemple:
        - Règle A: Détecte "Netscape overflow" (pattern binaire spécifique)
        - Règle B: Détecte "SQL injection" (pattern "SELECT")
        - Règle C: Détecte "XSS" (pattern "<script>")
        
        Agrégation OR → (A | B | C) = "si UN pattern matche, DROP"
        
        Problèmes:
        1. Perte de traçabilité (quelle menace a été détectée ?)
        2. Faux positifs si un pattern est trop générique
        3. Impossible de tuner une règle sans affecter les autres
        
        SOLUTION RETENUE
        ================
        - Déduplication exacte : règles avec MÊMES patterns → fusionner IPs ✅
        - Fusion IP dans phase 3 (Hypercube Convergence) : OK ✅
        - Agrégation de patterns différents : DÉSACTIVÉE ❌
        
        La complexité O(N) est gérée par le CompositeRuleIndex qui pré-filtre
        par (IP, Port) en O(1). Le nombre de règles n'impacte pas les perfs runtime.
        
        GAIN PRÉSERVÉ
        =============
        - Phase 3 (Fusion IP) : -57 règles
        - Déduplication exacte : -770 règles  
        - Factorisation Trie : -44% patterns atomiques
        """
        # Retourner les règles sans agrégation de patterns différents
        # La déduplication exacte (mêmes patterns) est déjà faite dans _deduplicate_exact()
        print(f"    [INFO] Agrégation patterns différents DÉSACTIVÉE (préservation sémantique)")
        print(f"    [INFO] Déduplication exacte + Fusion IP restent actives")
        return rules

    def _merge_rules_with_different_patterns(self, rules: List[RuleVector]) -> RuleVector:
        """
        FONCTION DÉSACTIVÉE - Préservation sémantique.
        
        Cette fonction fusionnait des règles avec patterns DIFFÉRENTS en OR.
        Problème : cela détruit la sémantique originale des règles Snort.
        
        Gardée pour référence historique, mais ne doit plus être appelée.
        """
        raise NotImplementedError(
            "Fusion de patterns différents désactivée. "
            "Utilisez _deduplicate_exact() pour fusionner règles avec mêmes patterns."
        )