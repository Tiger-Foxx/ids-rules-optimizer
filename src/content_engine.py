import re
from collections import defaultdict
from typing import Dict, Set, Tuple, List
import netaddr
from .models import RuleVector, Pattern


# =============================================================================
# TRIE DATA STRUCTURES FOR PREFIX FACTORIZATION
# =============================================================================

class TrieNode:
    """
    Trie node for common prefix factorization.
    Optimized with __slots__ to reduce memory footprint.
    """
    __slots__ = ['children', 'is_end', 'pattern_keys']
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end: bool = False
        self.pattern_keys: Set[Tuple] = set()


# =============================================================================
# ADVANCED SEMANTIC OPTIMIZATION ENGINE
# =============================================================================

class ContentEngine:
    """
    Optimization engine for content patterns using TRIE FACTORIZATION.
    
    SEMANTIC OPTIMIZATION STRATEGY
    ==============================
    
    Contextual aggregation alone does NOT reduce the complexity of the Hyperscan 
    automaton. Giant OR expressions keep N atomic automata active, resulting in
    zero real performance gain.
    
    SOLUTION: Global Lexical Factorization via Trie
    ----------------------------------------------
    
    Transformation: "GET /admin" + "GET /config" -> "GET /(admin|config)"
    
    BEFORE (2 atomic patterns):
        Pattern 1: /GET \/admin/
        Pattern 2: /GET \/config/
        -> Hyperscan compiles 2 distinct automata
    
    AFTER (1 factorized pattern):
        Pattern X: /GET \/(?:admin|config)/
        -> Hyperscan compiles 1 automaton with internal alternation
        -> Real reduction in scan workload
    
    PIPELINE:
    1. Global Extraction: All unique patterns -> normalization
    2. Segregation: Literals (Trie candidates) vs complex PCRE
    3. Trie Factorization: Common prefix >= 4 chars, branching >= 2
    4. Reinjection: Update rules with factorized patterns
    5. Final Aggregation: Exact deduplication + contextual aggregation
    """
    
    def __init__(self):
        # Performance heuristics
        self.MIN_PREFIX_LEN = 4    # Min length of common prefix
        self.MIN_BRANCHING_FACTOR = 2  # Min number of patterns to merge

    def _validate_regex_parentheses(self, regex: str) -> bool:
        """
        Verify that parentheses are balanced in the regex.
        Handles escaped cases: \\( and \\) are ignored.
        """
        depth = 0
        i = 0
        while i < len(regex):
            char = regex[i]
            
            # Check for escaped characters
            if char == '\\' and i + 1 < len(regex):
                i += 2
                continue
            
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth < 0:
                    return False  # Too many closing parentheses
            
            i += 1
        
        return depth == 0

    def optimize(self, rules: List[RuleVector]) -> List[RuleVector]:
        """
        Optimization pipeline WITHOUT Trie merge (safety mode).
        
        Preserves:
        - Exact deduplication of identical patterns
        - Network context aggregation (IP/Port)
        
        Disabled:
        - Trie merging (caused false positives due to semantic mixing)
        """
        print(f"[*] Starting Semantic Optimization (Conservative Mode)...")
        
        # Filter rules with patterns
        rules_with_patterns = [r for r in rules if r.patterns]
        print(f"    - Rules with patterns: {len(rules_with_patterns)}")
        
        # Initial stats
        multi_content_rules = [r for r in rules_with_patterns if len(r.patterns) > 1]
        print(f"    - Multi-content rules (logical AND): {len(multi_content_rules)}")

        # Count initial patterns
        initial_patterns = set()
        for r in rules_with_patterns:
            for p in r.patterns:
                initial_patterns.add((p.string_val, str(p.modifiers)))
        print(f"    - Unique patterns before deduplication: {len(initial_patterns)}")

        # =================================================================
        # TRIE MERGE DISABLED - Avoids false positives
        # =================================================================
        print(f"    [INFO] Trie Factorization DISABLED (safety)")
        print(f"    [INFO] Exact deduplication applied")

        # =================================================================
        # PHASE 1: EXACT DEDUPLICATION
        # =================================================================
        deduplicated_rules = self._deduplicate_exact(rules_with_patterns)
        print(f"    - After exact deduplication: {len(deduplicated_rules)}")

        # =================================================================
        # PHASE 2: NETWORK CONTEXT AGGREGATION
        # =================================================================
        final_rules = self._aggregate_by_network_context(deduplicated_rules)
        print(f"    - Final rules (after contextual aggregation): {len(final_rules)}")

        # Final stats
        final_patterns = set()
        for r in final_rules:
            for p in r.patterns:
                final_patterns.add((p.string_val, str(p.modifiers)))
        
        reduction = len(initial_patterns) - len(final_patterns)
        percent = (reduction / len(initial_patterns) * 100) if initial_patterns else 0
        print(f"    >>> GAIN: {len(initial_patterns)} -> {len(final_patterns)} unique patterns (-{percent:.1f}%)")

        return final_rules

    # =========================================================================
    # PHASE 1 & 2: EXTRACTION AND SEGREGATION
    # =========================================================================

    def _extract_and_normalize_patterns(self, rules: List[RuleVector]) -> Dict[Tuple, dict]:
        """
        Extract and normalize all atomic patterns from all rules.
        
        Returns a dict {(string, is_regex, flags): pattern_info}
        """
        patterns = {}
        
        for r in rules:
            if not hasattr(r, 'patterns') or not r.patterns:
                continue
                
            for p in r.patterns:
                if not p.string_val:
                    continue
                
                # Flag normalization
                flags = ''
                modifiers_str = str(p.modifiers).lower() if p.modifiers else ''
                if 'nocase' in modifiers_str:
                    flags += 'i'
                
                # Stable unique key (string, is_regex, flags)
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
        Separate literal patterns (Trie candidates) from complex PCRE.
        
        Only literals (is_regex=False) are candidates for factorization.
        PCRE are preserved as-is.
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
    # PHASE 3: TRIE FACTORIZATION ALGORITHM
    # =========================================================================

    def _factorize_patterns(self, simple_patterns: Dict[Tuple, dict]) -> Dict[Tuple, Pattern]:
        """
        Groups patterns by flags and starts Trie factorization.
        
        Returns a mapping {original_key -> fused_Pattern}
        """
        # Group by flags (nocase vs case-sensitive)
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
        Trie construction and factorization search.
        """
        root = TrieNode()

        # 1. Build Trie
        for p_obj in patterns_list:
            s = p_obj['string']
            node = root
            
            for char in s:
                if char not in node.children:
                    node.children[char] = TrieNode()
                node = node.children[char]
                # Track pattern keys along the path
                node.pattern_keys.add(p_obj['key'])
            
            node.is_end = True

        # 2. Traverse and Factorize
        self._traverse_and_factorize(root, "", flags, factorized_map)

    def _traverse_and_factorize(self, node: TrieNode, current_prefix: str, 
                                  flags: str, factorized_map: Dict[Tuple, Pattern]):
        """
        Recursive Trie traversal to identify factorization points.
        
        Factorization condition:
        - Prefix >= MIN_PREFIX_LEN characters
        - >= MIN_BRANCHING_FACTOR patterns pass through this node
        """
        # Check condition
        if (len(current_prefix) >= self.MIN_PREFIX_LEN and 
            len(node.pattern_keys) >= self.MIN_BRANCHING_FACTOR):
            
            # FACTORIZATION DETECTED!
            keys_to_factorize = node.pattern_keys.copy()
            
            # 1. Collect remaining suffixes
            suffixes = []
            self._collect_suffixes(node, "", suffixes)

            # 2. Build Factorized Regex
            prefix_escaped = re.escape(current_prefix)
            
            # Handle empty suffix (prefix itself is a pattern)
            prefix_is_pattern = "" in suffixes
            if prefix_is_pattern:
                suffixes.remove("")

            # Filter and sort suffixes
            MIN_SUFFIX_LEN = 15
            escaped_suffixes = sorted(
                list(set(re.escape(s) for s in suffixes if s and len(s) >= MIN_SUFFIX_LEN)), 
                key=len, 
                reverse=True
            )
            
            # If not enough long suffixes, abandon this branch
            if len(escaped_suffixes) < self.MIN_BRANCHING_FACTOR:
                for char, child in node.children.items():
                    self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)
                return
            
            # =================================================================
            # ANTI-FALSE-POSITIVE CORRECTION: NEVER generate (?:|...)
            # =================================================================
            if prefix_is_pattern:
                # Prefix alone is a pattern -> Dangerous to factorize
                for char, child in node.children.items():
                    self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)
                return
            
            # Build alternation
            if escaped_suffixes:
                alternation = "|".join(escaped_suffixes)
                fused_regex = f"{prefix_escaped}(?:{alternation})"
            else:
                return

            # =================================================================
            # VALIDATION: Check balanced parentheses
            # =================================================================
            if not self._validate_regex_parentheses(fused_regex):
                for char, child in node.children.items():
                    self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)
                return

            # Create factorized Pattern
            fused_pattern = Pattern(
                string_val=fused_regex,
                is_regex=True,
                modifiers={'nocase': 'true'} if 'i' in flags else {}
            )
            
            # Update mapping
            for key in keys_to_factorize:
                if key not in factorized_map:
                    factorized_map[key] = fused_pattern
            
            return

        # Recursive descent
        for char, child in node.children.items():
            self._traverse_and_factorize(child, current_prefix + char, flags, factorized_map)

    def _collect_suffixes(self, node: TrieNode, current_suffix: str, suffixes: List[str]):
        """
        Recursive collection of all suffixes from a node.
        Includes internal terminals.
        """
        if node.is_end:
            suffixes.append(current_suffix)

        for char, child in node.children.items():
            self._collect_suffixes(child, current_suffix + char, suffixes)

    # =========================================================================
    # PHASE 4: REINJECTION
    # =========================================================================

    def _reinject_patterns(self, rules: List[RuleVector], 
                            factorized_map: Dict[Tuple, Pattern]) -> List[RuleVector]:
        """
        Replaces atomic patterns with their factorized versions.
        """
        updated_rules = []
        
        for r in rules:
            if not hasattr(r, 'patterns') or not r.patterns:
                updated_rules.append(r)
                continue

            new_patterns = []
            patterns_changed = False
            seen_fused = set()  # Avoid duplicates for factorized patterns
            
            for p in r.patterns:
                if not p.string_val:
                    continue

                # Reconstruct key
                flags = ''
                modifiers_str = str(p.modifiers).lower() if p.modifiers else ''
                if 'nocase' in modifiers_str:
                    flags += 'i'
                key = (p.string_val, p.is_regex, flags)

                # Replace if factorized
                if key in factorized_map:
                    fused = factorized_map[key]
                    fused_id = id(fused)
                    
                    if fused_id not in seen_fused:
                        new_patterns.append(fused)
                        seen_fused.add(fused_id)
                    
                    patterns_changed = True
                else:
                    new_patterns.append(p)
            
            if patterns_changed:
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
    # PHASE 5: DEDUPLICATION AND AGGREGATION
    # =========================================================================

    def _deduplicate_exact(self, rules: List[RuleVector]) -> List[RuleVector]:
        """
        Exact rule deduplication after factorization.
        Uses Pattern object hashes for comparison.
        """
        groups = defaultdict(list)
        
        for r in rules:
            if not r.patterns:
                continue

            k_dst_pt = tuple(sorted(str(c) for c in r.dst_ports.iter_cidrs()))
            
            # Use frozenset on Pattern objects (hashable)
            try:
                k_patterns = frozenset(r.patterns)
            except TypeError:
                # Fallback if Pattern not hashable
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
        Merges N identical rules (same patterns) into a single one.
        Unions source and destination IPs.
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
        LEVEL 1 AGGREGATION: DISABLED for different patterns.
        
        PROBLEM ANALYSIS
        ================
        Merging rules with DIFFERENT patterns into an OR logic destroys
        the original Snort rule semantics.
        
        Example:
        - Rule A: Detects "Netscape overflow" (specific binary pattern)
        - Rule B: Detects "SQL injection" ("SELECT" pattern)
        - Rule C: Detects "XSS" ("<script>" pattern)
        
        OR aggregation -> (A | B | C) = "if ANY pattern matches, DROP"
        
        Issues:
        1. Loss of traceability
        2. False positives if a pattern is too generic
        3. Impossible to tune one rule without affecting others
        
        RETAINED SOLUTION
        =================
        - Exact deduplication: same patterns -> merge IPs 
        - IP fusion in Phase 3 (Hypercube Convergence): OK 
        - Aggregating different patterns: DISABLED 
        
        Runtime performance is maintained by CompositeRuleIndex (O(1) pre-filtering).
        """
        # Return rules without aggregating different patterns
        # Exact deduplication is already done in _deduplicate_exact()
        print(f"    [INFO] Aggregation of different patterns DISABLED (semantic preservation)")
        print(f"    [INFO] Exact deduplication + IP Fusion remain active")
        return rules

    def _merge_rules_with_different_patterns(self, rules: List[RuleVector]) -> RuleVector:
        """
        DISABLED FUNCTION - Semantic preservation.
        
        This function merged rules with DIFFERENT patterns into OR logic.
        Issue: this destroys the original Snort rule semantics.
        
        Kept for historical reference.
        """
        raise NotImplementedError(
            "Merging of different patterns disabled. "
            "Use _deduplicate_exact() to merge rules with identical patterns."
        )