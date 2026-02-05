from collections import defaultdict
import netaddr
from .models import RuleVector

class IPEngine:
    def __init__(self):
        self.firewall_rules = []
        self.inspection_rules = []

    def optimize(self, rules: list[RuleVector]):
        print(f"[*] Starting 'Hypercube Convergence' optimization on {len(rules)} rules...")
        
        pure_candidates = [r for r in rules if r.is_pure_firewall()]
        deep_candidates = [r for r in rules if not r.is_pure_firewall()]
        
        # --- SECURITY AUDIT ---
        print(f"\n[AUDIT] Checking {len(pure_candidates)} 'Pure Firewall' rules...")
        count_flags = sum(1 for r in pure_candidates if r.tcp_flags or r.icmp_type)
        if count_flags > 0:
            print(f"    - {count_flags} rules have protocol constraints (flags/itype).")
            print(f"    - Security : ACTIVE (Captured in fusion signature).")
        # -------------------------

        self.firewall_rules = self._run_optimization_loop(pure_candidates, is_pure=True)
        self.inspection_rules = self._run_optimization_loop(deep_candidates, is_pure=False)
        
        return self.firewall_rules, self.inspection_rules

    def _run_optimization_loop(self, rules: list[RuleVector], is_pure: bool) -> list[RuleVector]:
        """
        Loop until fix point.
        """
        if not rules: return []

        current_rules = rules
        iteration = 0
        
        while True:
            start_count = len(current_rules)
            iteration += 1
            
            # Dimensional Reduction Pipeline
            # Order Src -> Dst -> Ports is heuristically optimal/
            
            # 1. Merge Sources
            current_rules = self._merge_generic(current_rules, target='src_ip', is_pure=is_pure)
            
            # 2. Merge Destinations
            current_rules = self._merge_generic(current_rules, target='dst_ip', is_pure=is_pure)
            
            # 3. Merge Destination Ports (Services)
            current_rules = self._merge_generic(current_rules, target='dst_port', is_pure=is_pure)

            # 4. Merge Source Ports
            current_rules = self._merge_generic(current_rules, target='src_port', is_pure=is_pure)
            
            end_count = len(current_rules)
            
            if end_count == start_count:
                break
                
        prefix = "FW" if is_pure else "IPS"
        print(f"    [{prefix}] Convergence reached in {iteration} iterations : {len(rules)} -> {len(current_rules)} rules.")
        return current_rules

    def _merge_generic(self, rules: list[RuleVector], target: str, is_pure: bool):
        """
        Generic merging algorithm by target dimension.
        """
        groups = defaultdict(list)
        
        for r in rules:
            k_src_ip = tuple(sorted(r.src_ips.iter_cidrs()))
            k_dst_ip = tuple(sorted(r.dst_ips.iter_cidrs()))
            k_src_pt = tuple(sorted(r.src_ports.iter_cidrs()))
            k_dst_pt = tuple(sorted(r.dst_ports.iter_cidrs()))
            k_patterns = tuple(r.patterns) if not is_pure else None
            
            # --- CRITICAL SECURITY : FLAGS INTEGRATION ---
            proto_sig = (r.tcp_flags, r.icmp_type, r.icmp_code)

            # Signature Construction (Invariant)
            if target == 'src_ip':
                sig = (r.proto, proto_sig, k_dst_ip, k_src_pt, k_dst_pt, r.direction, r.action, r.established, k_patterns)
            elif target == 'dst_ip':
                sig = (r.proto, proto_sig, k_src_ip, k_src_pt, k_dst_pt, r.direction, r.action, r.established, k_patterns)
            elif target == 'dst_port':
                sig = (r.proto, proto_sig, k_src_ip, k_dst_ip, k_src_pt, r.direction, r.action, r.established, k_patterns)
            elif target == 'src_port':
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
            
            # Use copies to avoid side effects
            new_src_ips = netaddr.IPSet(base.src_ips)
            new_dst_ips = netaddr.IPSet(base.dst_ips)
            new_src_ports = netaddr.IPSet(base.src_ports)
            new_dst_ports = netaddr.IPSet(base.dst_ports)

            # Mathematical targeted fusion
            for r in group[1:]:
                if target == 'src_ip': new_src_ips.update(r.src_ips)
                elif target == 'dst_ip': new_dst_ips.update(r.dst_ips)
                elif target == 'src_port': new_src_ports.update(r.src_ports)
                elif target == 'dst_port': new_dst_ports.update(r.dst_ports)

            # Metadata
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
                tcp_flags=base.tcp_flags, # Important to preserve flags
                icmp_type=base.icmp_type,
                icmp_code=base.icmp_code,
                action=base.action,
                patterns=base.patterns
            )
            optimized.append(super_rule)

        return optimized