#!/usr/bin/env python3
"""Script de diagnostic pour vérifier les règles générées"""
import msgpack

data = msgpack.unpackb(open('outputs/rules_config.msgpack', 'rb').read())
print(f"Total rules: {len(data)}")

# Compter par type de src_ips
any_count = 0
home_count = 0
other_count = 0

for r in data:
    src = r['src_ips']
    if '0.0.0.0/0' in src:
        any_count += 1
    elif '10.0.0.0/8' in src or '192.168.0.0/16' in src:
        home_count += 1
    else:
        other_count += 1

print(f"\nRègles par type de source:")
print(f"  - src = any (0.0.0.0/0): {any_count}")
print(f"  - src = HOME_NET: {home_count}")
print(f"  - src = autre: {other_count}")

# Montrer quelques exemples avec any
print("\n5 premières règles avec src=any:")
for r in data[:20]:
    if '0.0.0.0/0' in r['src_ips']:
        print(f"  ID={r['id']} dst={r['dst_ips'][:2]}... dir={r['direction']} action={r['action']}")
        break
else:
    print("  Aucune trouvée!")

# Montrer les règles to_server (attaques entrantes)
print("\n5 premières règles to_server:")
count = 0
for r in data:
    if r['direction'] == 'to_server' and count < 5:
        print(f"  ID={r['id']} src={r['src_ips'][:2]}... dst={r['dst_ips'][:2]}...")
        count += 1
