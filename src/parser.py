import re
import netaddr
from .models import RuleVector, Pattern

class SnortParser:
    def __init__(self):
        self.UNIVERSE = netaddr.IPSet(['0.0.0.0/0'])
        
        # Variables standard
        home_net = netaddr.IPSet(['192.168.0.0/16', '10.0.0.0/8'])
        external_net = self.UNIVERSE - home_net

        self.variables = {
            "$HOME_NET": home_net,
            "$EXTERNAL_NET": external_net,
            "$HTTP_SERVERS": home_net,
            "$SMTP_SERVERS": home_net,
            "$SQL_SERVERS": home_net,
            "$DNS_SERVERS": home_net,
            "$TELNET_SERVERS": home_net,
            "any": self.UNIVERSE
        }
        
        self.port_vars = {
            "$HTTP_PORTS": "80",
            "$SHELLCODE_PORTS": "180",
            "$ORACLE_PORTS": "1521",
            "$SSH_PORTS": "22",
            "$FILE_DATA_PORTS": "80,21,25,143,110",
            "$FTP_PORTS": "21",
            "$TELNET_PORTS": "23",
            "any": "0:65535"
        }

    def parse_file(self, filepath):
        parsed_rules = []
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if not line.strip() or line.strip().startswith('#'):
                    continue
                try:
                    rule = self.parse_line(line)
                    if rule:
                        parsed_rules.append(rule)
                except Exception:
                    pass
        return parsed_rules

    def parse_line(self, line):
        header_regex = r"^([a-zA-Z]+)\s+([a-zA-Z]+)\s+([^\s]+)\s+([^\s]+)\s+(->|<>)\s+([^\s]+)\s+([^\s]+)\s+\((.*)\)"
        match = re.match(header_regex, line.strip())
        if not match:
            return None

        action, proto, src, src_p, direction_sign, dst, dst_p, opts_str = match.groups()

        src_ips = self._resolve_ip(src)
        dst_ips = self._resolve_ip(dst)
        src_ports = self._resolve_port(src_p)
        dst_ports = self._resolve_port(dst_p)

        rule = RuleVector(
            id=0, 
            original_text=line.strip(),
            proto=proto.lower(),
            src_ips=src_ips,
            src_ports=src_ports,
            dst_ips=dst_ips,
            dst_ports=dst_ports,
            action=action
        )

        self._parse_options(rule, opts_str)
        return rule

    def _resolve_ip(self, val_str):
        val_str = val_str.strip()
        if val_str.startswith('['):
            val_str = val_str.strip('[]')
            parts = [p.strip() for p in val_str.split(',')]
            final_set = netaddr.IPSet()
            for part in parts:
                if part.startswith('!'):
                    final_set.update(self._resolve_single_ip_token(part[1:]))
                else:
                    final_set.update(self._resolve_single_ip_token(part))
            return final_set
        return self._resolve_single_ip_token(val_str)

    def _resolve_single_ip_token(self, token):
        is_negated = token.startswith('!')
        clean_token = token[1:] if is_negated else token
        result_set = None

        if clean_token.startswith('$'):
            result_set = self.variables.get(clean_token, self.UNIVERSE)
        elif clean_token.lower() == 'any':
            result_set = self.UNIVERSE
        else:
            try:
                result_set = netaddr.IPSet([clean_token])
            except:
                result_set = netaddr.IPSet()

        if is_negated:
            return self.UNIVERSE - result_set
        return result_set

    def _resolve_port(self, val_str):
        val_str = val_str.strip()
        PORT_UNIVERSE = netaddr.IPSet([netaddr.IPRange(0, 65535)])
        is_negated = val_str.startswith('!')
        clean_val = val_str[1:] if is_negated else val_str

        if clean_val in self.port_vars:
            clean_val = self.port_vars[clean_val]

        final_set = netaddr.IPSet()
        if clean_val.startswith('['):
            parts = clean_val.strip('[]').split(',')
        else:
            parts = [clean_val]

        for part in parts:
            part = part.strip()
            if not part: continue
            if part.lower() == 'any':
                final_set.update(PORT_UNIVERSE)
                continue
            if ':' in part:
                try:
                    s, e = part.split(':')
                    start = int(s) if s else 0
                    end = int(e) if e else 65535
                    final_set.add(netaddr.IPRange(max(0,start), min(65535,end)))
                except: pass
            else:
                try:
                    final_set.add(int(part))
                except: pass

        if is_negated:
            return PORT_UNIVERSE - final_set
        return final_set

    def _parse_options(self, rule, opts_str):
        parts = opts_str.split(';')
        for part in parts:
            part = part.strip()
            if not part: continue
            
            if ':' in part:
                key, val = part.split(':', 1)
                key = key.strip().lower()
                val = val.strip()
            else:
                key = part.strip().lower()
                val = ""

            if key == "content":
                # Extraire UNIQUEMENT ce qui est entre guillemets
                clean_val = self._extract_quoted_value(val)
                if clean_val is not None:
                    rule.patterns.append(Pattern(string_val=clean_val))
            elif key == "pcre":
                clean_val = self._extract_quoted_value(val)
                if clean_val is not None:
                    rule.patterns.append(Pattern(string_val=clean_val, is_regex=True))
            # --- MODIFIERS DE CONTENT (s'appliquent au dernier pattern) ---
            elif key == "nocase":
                if rule.patterns:
                    rule.patterns[-1].modifiers['nocase'] = True
            elif key == "depth":
                if rule.patterns:
                    rule.patterns[-1].modifiers['depth'] = val
            elif key == "offset":
                if rule.patterns:
                    rule.patterns[-1].modifiers['offset'] = val
            elif key == "distance":
                if rule.patterns:
                    rule.patterns[-1].modifiers['distance'] = val
            elif key == "within":
                if rule.patterns:
                    rule.patterns[-1].modifiers['within'] = val
            elif key == "fast_pattern":
                if rule.patterns:
                    rule.patterns[-1].modifiers['fast_pattern'] = True
            elif key == "flow":
                if "to_server" in val: rule.direction = "to_server"
                if "to_client" in val: rule.direction = "to_client"
                if "established" in val: rule.established = True
            elif key == "sid":
                try: rule.id = int(val)
                except: pass
            
            # --- NOUVEAU : EXTRACTION FINE DU PROTOCOLE ---
            elif key == "flags":
                # ex: flags:S; ou flags:A,12;
                rule.tcp_flags = val
            elif key == "itype":
                rule.icmp_type = val
            elif key == "icode":
                rule.icmp_code = val
            elif key == "icmp_id":
                # On le stocke dans icmp_type pour la signature, ou un champ dédié
                # Pour l'instant, on ne le met pas en signature principale car iptables gère mal l'ID
                # Mais on peut le garder pour éviter la fusion abusive
                pass

    def _extract_quoted_value(self, val):
        """
        Extrait uniquement la valeur entre guillemets.
        Ex: '"hello",depth 16' -> 'hello'
        Ex: '"test|00|data"' -> 'test|00|data'
        """
        if not val:
            return None
        
        val = val.strip()
        if not val.startswith('"'):
            return val  # Pas de guillemet, retourner tel quel
        
        # Trouver le guillemet fermant (en gérant les échappements)
        i = 1
        result = []
        while i < len(val):
            if val[i] == '\\' and i + 1 < len(val):
                # Caractère échappé
                result.append(val[i:i+2])
                i += 2
            elif val[i] == '"':
                # Guillemet fermant trouvé
                break
            else:
                result.append(val[i])
                i += 1
        
        return ''.join(result) if result else None