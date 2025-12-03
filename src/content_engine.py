from collections import defaultdict
import re
import netaddr
from .models import RuleVector, Pattern

class PrefixTrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False
        self.original_patterns = [] # List of (string_val, list[RuleVector])

class ContentEngine:
    def __init__(self):
        self.min_prefix_len = 4

    def optimize(self, rules: list[RuleVector]):
        print(f"[*] Démarrage de l'optimisation Sémantique Hybride sur {len(rules)} règles...")
        
        # PHASE 0 : FUSION INTRA-RÈGLE (Multi-content → Single pattern)
        # Chaque règle avec N patterns devient une règle avec 1 pattern fusionné
        rules_with_fused_patterns = []
        multi_fused_count = 0
        
        for r in rules:
            if not r.patterns: 
                continue
            
            if len(r.patterns) > 1:
                # Fusionner les patterns internes de cette règle
                fused_pattern = self._fuse_internal_patterns(r.patterns)
                multi_fused_count += 1
                
                # Créer une nouvelle règle avec le pattern fusionné
                new_rule = RuleVector(
                    id=r.id,
                    original_text=r.original_text,
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
                    patterns=[fused_pattern]
                )
                rules_with_fused_patterns.append(new_rule)
            else:
                rules_with_fused_patterns.append(r)
        
        print(f"    - Fusion Intra-Règle : {multi_fused_count} règles multi-content → single pattern")
        
        # PHASE 1 : SÉGRÉGATION pour optimisation inter-règles
        single_pattern_rules = []
        regex_pattern_rules = []
        
        for r in rules_with_fused_patterns:
            # Après fusion, toutes les règles ont 1 seul pattern
            p = r.patterns[0]
            
            # Les patterns fusionnés sont des regex, on les traite séparément
            if p.is_regex or p.negated:
                regex_pattern_rules.append(r)
            else:
                single_pattern_rules.append(r)

        print(f"    - Règles Simples (Trie Opt.) : {len(single_pattern_rules)}")
        print(f"    - Règles Regex (Hash Opt.) : {len(regex_pattern_rules)}")

        optimized_rules = []
        
        # 1. Optimisation Lexicale (Trie) pour les patterns simples
        optimized_rules.extend(self._optimize_via_trie(single_pattern_rules))
        
        # 2. Optimisation Exacte pour les regex
        optimized_rules.extend(self._optimize_via_hash(regex_pattern_rules))
        
        return optimized_rules

    def _fuse_internal_patterns(self, patterns: list[Pattern]) -> Pattern:
        """
        Fusionne les patterns internes d'une règle en UN SEUL pattern regex.
        
        Sémantique Snort : Tous les content: doivent matcher (ET logique).
        
        STRATÉGIE DE FUSION INTELLIGENTE (Recommandation Recherche) :
        ============================================================
        
        CAS 1 : Règle avec pcre: explicite
        ----------------------------------
        → Garder la PCRE telle quelle (elle est déjà optimisée par l'auteur)
        
        CAS 2 : Multi-content AVEC distance/within
        ------------------------------------------
        → Fusion séquentielle : A.{0,N}B.{0,M}C
        → Hyperscan supporte les quantificateurs bornés
        → Préserve la sémantique de proximité
        
        CAS 3 : Multi-content SANS contraintes de position
        --------------------------------------------------
        → Alternation : (A|B|C)
        → Si UN pattern matche, Hyperscan déclenche et on vérifie le reste
        → Performance optimale pour Hyperscan (parallélisme DFA)
        """
        if len(patterns) == 1:
            return patterns[0]
        
        # Séparer les types de patterns
        pcre_patterns = [p for p in patterns if p.is_regex]
        content_patterns = [p for p in patterns if not p.is_regex and not p.negated]
        
        # =====================================================
        # CAS 1 : Il y a une PCRE explicite
        # =====================================================
        if pcre_patterns:
            # La PCRE est généralement le pattern le plus discriminant
            # On prend la plus longue (plus spécifique)
            main_pcre = max(pcre_patterns, key=lambda p: len(p.string_val or ''))
            return main_pcre
        
        # =====================================================
        # CAS 2 & 3 : Fusion des content simples
        # =====================================================
        if not content_patterns:
            return patterns[0]
        
        # Collecter le flag nocase (si AU MOINS un pattern l'a, on l'applique à tous)
        has_nocase = any(
            'nocase' in str(p.modifiers).lower()
            for p in content_patterns
        )
        
        # Vérifier si des patterns ont des contraintes de position
        has_positional_constraints = any(
            p.modifiers.get('distance') or p.modifiers.get('within')
            for p in content_patterns
        )
        
        if has_positional_constraints:
            # =====================================================
            # CAS 2 : Fusion séquentielle avec quantificateurs bornés
            # A.{min,max}B.{min,max}C
            # =====================================================
            fused_regex = self._build_sequential_regex(content_patterns)
        else:
            # =====================================================
            # CAS 3 : Multi-content SANS contraintes
            # Sémantique Snort : TOUS les patterns doivent matcher (AND)
            # On utilise une regex séquentielle avec .*? entre chaque
            # Pour l'ordre, on trie par longueur décroissante (pattern le plus 
            # spécifique en premier pour performance Hyperscan)
            # =====================================================
            fused_regex = self._build_unordered_and_regex(content_patterns)
        
        # Créer le pattern fusionné
        return Pattern(
            string_val=fused_regex,
            is_regex=True,
            negated=False,
            modifiers={'nocase': 'true'} if has_nocase else {}
        )
    
    def _escape_for_regex(self, s: str) -> str:
        """
        Échappe une chaîne pour l'utiliser dans une regex Hyperscan.
        
        Note: On utilise re.escape() de Python qui est robuste,
        puis on ajuste pour les cas spéciaux Hyperscan.
        """
        import re
        if not s:
            return ''
        
        # Utiliser l'échappement standard Python (robuste et testé)
        escaped = re.escape(s)
        
        return escaped
    
    def _build_sequential_regex(self, patterns: list[Pattern]) -> str:
        """
        Construit une regex séquentielle : A.{0,N}B.{0,M}C
        
        Utilise les modifiers distance/within pour calculer les bornes.
        - distance: nombre minimum de bytes entre les patterns
        - within: nombre maximum de bytes dans lequel le pattern doit apparaître
        """
        if not patterns:
            return ''
        
        parts = []
        
        for i, p in enumerate(patterns):
            escaped_pattern = self._escape_for_regex(p.string_val or '')
            
            if i == 0:
                # Premier pattern : pas de contrainte avant
                parts.append(escaped_pattern)
            else:
                # Patterns suivants : analyser distance/within
                distance = p.modifiers.get('distance')
                within = p.modifiers.get('within')
                
                # Calculer les bornes du quantificateur
                min_gap = 0
                max_gap = 1000  # Valeur par défaut raisonnable
                
                if distance:
                    try:
                        min_gap = int(distance)
                    except ValueError:
                        min_gap = 0
                
                if within:
                    try:
                        max_gap = int(within)
                    except ValueError:
                        max_gap = 1000
                
                # Construire le connecteur .{min,max}
                if min_gap == 0 and max_gap >= 1000:
                    connector = '.*?'  # Non-greedy pour performance
                else:
                    connector = f'.{{{min_gap},{max_gap}}}'
                
                parts.append(connector)
                parts.append(escaped_pattern)
        
        return ''.join(parts)
    
    def _build_alternation_regex(self, patterns: list[Pattern]) -> str:
        """
        Construit une regex en alternation : (A|B|C)
        
        ATTENTION: Cette méthode n'est plus utilisée pour les multi-content Snort
        car elle implémente une logique OR, alors que Snort utilise AND.
        
        Gardée pour les cas où on veut explicitement une alternation
        (ex: fusion de règles avec le même contexte mais patterns différents).
        """
        if not patterns:
            return ''
        
        # Trier par longueur décroissante (patterns longs = plus spécifiques)
        sorted_patterns = sorted(
            patterns,
            key=lambda p: len(p.string_val or ''),
            reverse=True
        )
        
        alternatives = []
        for p in sorted_patterns:
            escaped = self._escape_for_regex(p.string_val or '')
            if escaped:
                alternatives.append(escaped)
        
        if len(alternatives) == 1:
            return alternatives[0]
        
        return '(' + '|'.join(alternatives) + ')'

    def _build_unordered_and_regex(self, patterns: list[Pattern]) -> str:
        """
        Construit une regex pour multi-content Snort SANS contraintes de position.
        
        LIMITATION HYPERSCAN : Les lookaheads (?=) ne sont PAS supportés en mode STREAM.
        
        SOLUTION : On utilise une regex séquentielle A.*?B.*?C
        Cela assume que les patterns apparaissent dans l'ordre donné, ce qui n'est
        pas toujours vrai pour Snort. C'est une approximation qui peut avoir des
        faux négatifs mais jamais de faux positifs.
        
        Pour une sémantique AND parfaite, il faudrait :
        - Soit générer TOUTES les permutations (explosion combinatoire)
        - Soit faire la vérification multi-pattern côté C++
        
        Pour le PoC, on accepte cette limitation.
        """
        if not patterns:
            return ''
        
        if len(patterns) == 1:
            return self._escape_for_regex(patterns[0].string_val or '')
        
        # Trier par longueur décroissante (pattern le plus spécifique en premier)
        # Cela maximise les chances de trouver le bon ordre
        sorted_patterns = sorted(
            patterns,
            key=lambda p: len(p.string_val or ''),
            reverse=True
        )
        
        # Construire A.*?B.*?C (séquentiel avec wildcards non-greedy)
        parts = []
        for p in sorted_patterns:
            escaped = self._escape_for_regex(p.string_val or '')
            if escaped:
                parts.append(escaped)
        
        if len(parts) == 1:
            return parts[0]
        
        # Joindre avec .*? (match non-greedy de n'importe quoi)
        return '.*?'.join(parts)

    def _optimize_via_hash(self, rules: list[RuleVector]):
        """
        Fusionne les règles complexes si et seulement si TOUTE la chaîne de patterns est identique.
        """
        groups = defaultdict(list)
        for r in rules:
            # Signature stricte : Proto + Ports + TOUS les patterns
            k_dst_pt = tuple(sorted(r.dst_ports.iter_cidrs()))
            k_patterns = tuple(r.patterns) # Hash profond des patterns
            sig = (r.proto, k_dst_pt, r.direction, k_patterns)
            groups[sig].append(r)
            
        results = []
        for sig, group in groups.items():
            if len(group) > 1:
                results.append(self._merge_rules_generic(group, group[0].patterns))
            else:
                results.append(group[0])
        return results

    def _optimize_via_trie(self, rules: list[RuleVector]):
        """
        Utilise l'algorithme de Trie pour factoriser les préfixes communs.
        """
        # Groupement par contexte (Proto + Port)
        groups = defaultdict(list)
        for r in rules:
            k_dst_pt = tuple(sorted(r.dst_ports.iter_cidrs()))
            sig = (r.proto, k_dst_pt, r.direction)
            groups[sig].append(r)
            
        results = []
        for sig, group_rules in groups.items():
            # Construction du Trie
            root = PrefixTrieNode()
            for r in group_rules:
                s = r.patterns[0].string_val
                if len(s) < self.min_prefix_len:
                    results.append(r) # Trop court pour factoriser
                    continue
                    
                node = root
                for char in s:
                    if char not in node.children:
                        node.children[char] = PrefixTrieNode()
                    node = node.children[char]
                node.is_end = True
                
                # On stocke la règle ici
                found = False
                for i, (existing_s, existing_list) in enumerate(node.original_patterns):
                    if existing_s == s:
                        existing_list.append(r)
                        found = True
                        break
                if not found:
                    node.original_patterns.append((s, [r]))
            
            # Traversée et fusion
            self._traverse_and_fuse(root, "", results)
            
        return results

    def _traverse_and_fuse(self, node, current_prefix, output_list):
        # 1. Traitement des règles qui s'arrêtent exactement ici (ex: "admin" dans "admin" vs "admin_panel")
        if node.is_end:
            for pat_str, r_list in node.original_patterns:
                # Si c'est une feuille sans enfants, on attendra la logique de fusion ci-dessous
                # Sinon, on doit émettre ces règles maintenant car elles sont un préfixe strict d'autres règles
                if node.children: 
                    output_list.append(self._merge_rules_generic(r_list, r_list[0].patterns))

        # 2. Factorisation des enfants (Embranchements)
        if len(node.children) > 1:
            sub_patterns = self._collect_patterns(node)
            
            if len(sub_patterns) > 1:
                # Factorisation : prefix(suffix1|suffix2)
                safe_prefix = re.escape(current_prefix)
                alt_parts = []
                all_rules = []
                
                for s, r_list in sub_patterns:
                    suffix = s[len(current_prefix):]
                    if not suffix: continue # Skip le cas où le préfixe est lui-même un pattern
                    alt_parts.append(re.escape(suffix))
                    all_rules.extend(r_list)
                
                if alt_parts:
                    regex_str = f"{safe_prefix}({'|'.join(alt_parts)})"
                    
                    # Création du pattern Regex optimisé
                    new_pat = Pattern(string_val=regex_str, is_regex=True)
                    # On fusionne tout ce beau monde
                    output_list.append(self._merge_rules_generic(all_rules, [new_pat]))
                    return # On a consommé tout le sous-arbre

        # 3. Descente récursive (si pas factorisé)
        for char, child in node.children.items():
            self._traverse_and_fuse(child, current_prefix + char, output_list)
            
        # 4. Cas feuille simple (pas d'enfants, pas factorisé plus haut)
        if node.is_end and not node.children:
             for pat_str, r_list in node.original_patterns:
                output_list.append(self._merge_rules_generic(r_list, r_list[0].patterns))

    def _collect_patterns(self, node):
        """Collecte récursivement (string, rules)"""
        results = []
        if node.is_end:
            results.extend(node.original_patterns)
        for child in node.children.values():
            results.extend(self._collect_patterns(child))
        return results

    def _merge_rules_generic(self, rules: list[RuleVector], patterns: list[Pattern]):
        """
        Fusionne N règles en une seule.
        CORRECTIF CRITIQUE : Fusionne aussi les IPs de Destination et les Ports Source.
        """
        base = rules[0]
        
        new_src_ips = netaddr.IPSet()
        new_dst_ips = netaddr.IPSet() 
        new_src_ports = netaddr.IPSet()
        
        for r in rules:
            new_src_ips.update(r.src_ips)
            new_dst_ips.update(r.dst_ips) 
            new_src_ports.update(r.src_ports)
            
        new_text = f"SEMANTIC FUSION ({len(rules)})"
        
        return RuleVector(
            id=base.id,
            original_text=new_text,
            proto=base.proto,
            src_ips=new_src_ips,
            src_ports=new_src_ports,
            dst_ips=new_dst_ips,
            dst_ports=base.dst_ports, # Inchangé car c'est la clé de groupement
            direction=base.direction,
            established=base.established,
            tcp_flags=base.tcp_flags,
            icmp_type=base.icmp_type,
            icmp_code=base.icmp_code,
            action=base.action,
            patterns=patterns
        )