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
        
        # SÉGRÉGATION CRITIQUE
        # On ne peut appliquer l'optimisation Trie (Factorisation) QUE sur les règles à pattern unique.
        # Pour les règles multi-patterns, on doit utiliser une correspondance exacte pour ne pas casser la logique.
        single_pattern_rules = []
        multi_pattern_rules = []
        
        for r in rules:
            if not r.patterns: continue
            
            # Condition stricte pour le mode Trie :
            # 1 seul pattern, pas de regex, pas de négation
            if len(r.patterns) == 1 and not r.patterns[0].is_regex and not r.patterns[0].negated:
                single_pattern_rules.append(r)
            else:
                multi_pattern_rules.append(r)

        print(f"    - Règles Simples (Trie Opt.) : {len(single_pattern_rules)}")
        print(f"    - Règles Complexes (Hash Opt.) : {len(multi_pattern_rules)}")

        optimized_rules = []
        
        # 1. Optimisation Lexicale (Trie) pour les patterns simples
        optimized_rules.extend(self._optimize_via_trie(single_pattern_rules))
        
        # 2. Optimisation Exacte pour les patterns complexes
        optimized_rules.extend(self._optimize_via_hash(multi_pattern_rules))
        
        return optimized_rules

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