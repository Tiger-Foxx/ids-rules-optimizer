from collections import defaultdict
import netaddr
from .models import RuleVector

class IPEngine:
    def __init__(self):
        self.firewall_rules = []
        self.inspection_rules = []

    def optimize(self, rules: list[RuleVector]):
        print(f"[*] Démarrage de l'optimisation 'Hypercube Convergence' sur {len(rules)} règles...")
        
        pure_candidates = [r for r in rules if r.is_pure_firewall()]
        deep_candidates = [r for r in rules if not r.is_pure_firewall()]
        
        # --- AUDIT DE SÉCURITÉ ---
        print(f"\n[AUDIT] Vérification des {len(pure_candidates)} règles classées 'Firewall Pur'...")
        count_flags = sum(1 for r in pure_candidates if r.tcp_flags or r.icmp_type)
        if count_flags > 0:
            print(f"    - {count_flags} règles ont des contraintes protocolaires (flags/itype).")
            print(f"    - Sécurité : ACTIVE (Prise en compte dans la signature de fusion).")
        # -------------------------

        # On traite séparément car les règles d'inspection ont des contraintes de pattern strictes
        self.firewall_rules = self._run_optimization_loop(pure_candidates, is_pure=True)
        self.inspection_rules = self._run_optimization_loop(deep_candidates, is_pure=False)
        
        return self.firewall_rules, self.inspection_rules

    def _run_optimization_loop(self, rules: list[RuleVector], is_pure: bool) -> list[RuleVector]:
        """
        Exécute la pipeline en boucle jusqu'à stabilité (Point Fixe).
        Garantit la compression maximale possible.
        """
        if not rules: return []

        current_rules = rules
        iteration = 0
        
        while True:
            start_count = len(current_rules)
            iteration += 1
            
            # Pipeline de réduction dimensionnelle
            # L'ordre Src -> Dst -> Ports est heuristiquement le meilleur
            
            # 1. Fusion des Sources
            current_rules = self._merge_generic(current_rules, target='src_ip', is_pure=is_pure)
            
            # 2. Fusion des Destinations
            current_rules = self._merge_generic(current_rules, target='dst_ip', is_pure=is_pure)
            
            # 3. Fusion des Ports Destination (Services)
            current_rules = self._merge_generic(current_rules, target='dst_port', is_pure=is_pure)

            # 4. Fusion des Ports Sources
            current_rules = self._merge_generic(current_rules, target='src_port', is_pure=is_pure)
            
            end_count = len(current_rules)
            
            # Condition d'arrêt : Si le nombre de règles ne bouge plus, on a atteint l'optimum.
            if end_count == start_count:
                break
                
        prefix = "FW" if is_pure else "IPS"
        print(f"    [{prefix}] Convergence atteinte en {iteration} itérations : {len(rules)} -> {len(current_rules)} règles.")
        return current_rules

    def _merge_generic(self, rules: list[RuleVector], target: str, is_pure: bool):
        """
        Algorithme de fusion générique par dimension cible.
        """
        groups = defaultdict(list)
        
        for r in rules:
            # Création des clés de hachage stables
            k_src_ip = tuple(sorted(r.src_ips.iter_cidrs()))
            k_dst_ip = tuple(sorted(r.dst_ips.iter_cidrs()))
            k_src_pt = tuple(sorted(r.src_ports.iter_cidrs()))
            k_dst_pt = tuple(sorted(r.dst_ports.iter_cidrs()))
            k_patterns = tuple(r.patterns) if not is_pure else None
            
            # --- SECURITE CRITIQUE : INTEGRATION DES FLAGS ---
            # Si on oublie ça, on fusionne SYN avec tout le reste !
            proto_sig = (r.tcp_flags, r.icmp_type, r.icmp_code)

            # Construction de la signature (Invariant)
            # On exclut de la signature UNIQUEMENT ce qu'on veut fusionner
            if target == 'src_ip':
                # Invariant = Tout sauf Src IP
                sig = (r.proto, proto_sig, k_dst_ip, k_src_pt, k_dst_pt, r.direction, r.action, r.established, k_patterns)
            elif target == 'dst_ip':
                # Invariant = Tout sauf Dst IP
                sig = (r.proto, proto_sig, k_src_ip, k_src_pt, k_dst_pt, r.direction, r.action, r.established, k_patterns)
            elif target == 'dst_port':
                # Invariant = Tout sauf Dst Port
                sig = (r.proto, proto_sig, k_src_ip, k_dst_ip, k_src_pt, r.direction, r.action, r.established, k_patterns)
            elif target == 'src_port':
                # Invariant = Tout sauf Src Port
                sig = (r.proto, proto_sig, k_src_ip, k_dst_ip, k_dst_pt, r.direction, r.action, r.established, k_patterns)
            else:
                raise ValueError(f"Unknown target {target}")

            groups[sig].append(r)

        optimized = []
        for sig, group in groups.items():
            if len(group) == 1:
                optimized.append(group[0])
                continue

            base = group[0]
            
            # Copies pour éviter les effets de bord
            new_src_ips = netaddr.IPSet(base.src_ips)
            new_dst_ips = netaddr.IPSet(base.dst_ips)
            new_src_ports = netaddr.IPSet(base.src_ports)
            new_dst_ports = netaddr.IPSet(base.dst_ports)

            # Fusion mathématique ciblée
            for r in group[1:]:
                if target == 'src_ip': new_src_ips.update(r.src_ips)
                elif target == 'dst_ip': new_dst_ips.update(r.dst_ips)
                elif target == 'src_port': new_src_ports.update(r.src_ports)
                elif target == 'dst_port': new_dst_ports.update(r.dst_ports)

            # Métadonnées
            new_text = f"FUSED {target.upper()} ({len(group)})"
            if is_pure: new_text += " FW"

            super_rule = RuleVector(
                id=base.id,
                original_text=new_text,
                proto=base.proto,
                src_ips=new_src_ips,
                dst_ips=new_dst_ips,
                src_ports=new_src_ports,
                dst_ports=new_dst_ports,
                direction=base.direction,
                established=base.established,
                tcp_flags=base.tcp_flags, # Important de garder les flags
                icmp_type=base.icmp_type,
                icmp_code=base.icmp_code,
                action=base.action,
                patterns=base.patterns
            )
            optimized.append(super_rule)

        return optimized