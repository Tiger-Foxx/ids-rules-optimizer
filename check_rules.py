#!/usr/bin/env python3
"""Script de diagnostic pour vérifier les règles générées"""
import msgpack

data = msgpack.unpackb(open('outputs/rules_config.msgpack', 'rb').read())
print(f"Total rules: {len(data)}")

# Chercher règles qui matchent port 80
print("\n=== Règles qui matchent port 80 ===")
rules_80 = []
for r in data:
    ports = r['dst_ports']
    if not ports:  # vide = any
        rules_80.append(r)
    else:
        for p in ports:
            if p[0] <= 80 <= p[1]:
                rules_80.append(r)
                break

print(f"Trouvées: {len(rules_80)}")
for r in rules_80[:10]:
    print(f"  id={r['id']} src={r['src_ips'][:2]} dst_ports={r['dst_ports'][:3]}")

# Chercher règles XSS / javascript
print("\n=== Règles avec patterns XSS (vérifier dans patterns.txt) ===")
# On ne peut pas voir les patterns ici, mais on peut voir les hs_id
