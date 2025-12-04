from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import netaddr

@dataclass
class Pattern:
    string_val: Optional[str] = None
    hex_val: Optional[bytes] = None
    is_regex: bool = False
    negated: bool = False
    modifiers: Dict[str, str] = field(default_factory=dict)

    def __hash__(self):
        # Hachage stable pour le regroupement
        mods = tuple(sorted((k, v) for k, v in self.modifiers.items() if not k.startswith('_')))
        return hash((self.string_val, self.hex_val, self.is_regex, self.negated, mods))
    
    def __eq__(self, other):
        if not isinstance(other, Pattern):
            return False
        # Exclure les clés internes (_aggregated_or, etc.) pour la comparaison
        self_mods = {k: v for k, v in self.modifiers.items() if not k.startswith('_')}
        other_mods = {k: v for k, v in other.modifiers.items() if not k.startswith('_')}
        return (
            self.string_val == other.string_val and
            self.hex_val == other.hex_val and
            self.is_regex == other.is_regex and
            self.negated == other.negated and
            self_mods == other_mods
        )

@dataclass
class RuleVector:
    id: int
    original_text: str
    
    # 1. Filtres L3/L4
    proto: str
    src_ips: netaddr.IPSet
    src_ports: netaddr.IPSet
    dst_ips: netaddr.IPSet
    dst_ports: netaddr.IPSet
    
    # 2. Métadonnées de Flux
    direction: str = "any"
    established: bool = False
    
    # 3. Contraintes Protocolaires Fines (NOUVEAU)
    # Indispensable pour ne pas fusionner un SYN scan avec un trafic normal
    tcp_flags: Optional[str] = None  # Ex: "S", "A,12"
    icmp_type: Optional[str] = None  # Ex: "8" (Echo Request)
    icmp_code: Optional[str] = None  # Ex: "0"
    
    # 4. Payload
    patterns: List[Pattern] = field(default_factory=list)
    action: str = "alert"

    def is_pure_firewall(self):
        """
        Une règle est 'Pure Firewall' si elle n'a PAS de patterns (payload).
        Elle peut avoir des flags TCP ou ICMP codes, car iptables gère ça.
        """
        return len(self.patterns) == 0