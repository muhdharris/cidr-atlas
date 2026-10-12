"""Reference data from Python's ipaddress module, which CIDR Atlas is checked against.
usage: python3 tools/gen_reference.py > /tmp/ref.json   (seeded, so runs are repeatable)"""
import ipaddress as ip, json, random, sys
random.seed(20261012)
out = {"info": [], "split": [], "aggregate": [], "exclude": [], "range": []}

def rnd_net(v):
    bits = 32 if v == 4 else 128
    p = random.choice([random.randint(0, bits), random.randint(8, 30) if v == 4 else random.randint(32, 64)])
    x = random.getrandbits(bits)
    return ip.ip_network((x, p), strict=False)

for _ in range(300):
    n = rnd_net(random.choice([4, 6]))
    e = {"in": str(n.network_address) + "/" + str(n.prefixlen), "v": n.version, "net": str(n.network_address),
         "last": str(n.broadcast_address if n.version == 4 else n[-1]), "total": str(n.num_addresses),
         "compressed": n.network_address.compressed, "exploded": n.network_address.exploded}
    if n.version == 4:
        e["mask"] = str(n.netmask); e["wild"] = str(n.hostmask)
    out["info"].append(e)

for _ in range(150):
    v = random.choice([4, 6]); bits = 32 if v == 4 else 128
    n = ip.ip_network((random.getrandbits(bits), random.randint(0, min(bits - 6, 24 if v == 4 else 120))), strict=False)
    d = random.randint(1, 6)
    out["split"].append({"in": str(n), "new": n.prefixlen + d, "subnets": [str(x) for x in n.subnets(prefixlen_diff=d)]})

for _ in range(200):
    v = random.choice([4, 6]); bits = 32 if v == 4 else 128
    base = random.getrandbits(bits)
    nets = []
    for _ in range(random.randint(2, 14)):
        p = random.randint(max(0, bits - 10), bits)             # clustered so merges and containment actually happen
        x = (base & ~((1 << 10) - 1)) | random.getrandbits(10)
        nets.append(ip.ip_network((x, p), strict=False))
    out["aggregate"].append({"in": [str(n) for n in nets], "out": [str(n) for n in ip.collapse_addresses(nets)]})

for _ in range(200):
    v = random.choice([4, 6]); bits = 32 if v == 4 else 128
    n = ip.ip_network((random.getrandbits(bits), random.randint(0, min(bits - 2, 20 if v == 4 else 100))), strict=False)
    if random.random() < 0.8:
        p = random.randint(n.prefixlen, min(bits, n.prefixlen + 12))
        off = random.getrandbits(p - n.prefixlen) if p > n.prefixlen else 0
        x = ip.ip_network(((int(n.network_address) | (off << (bits - p))), p), strict=False)
    else:
        x = ip.ip_network((random.getrandbits(bits), random.randint(0, bits)), strict=False)
    try: res = sorted(n.address_exclude(x), key=lambda q: (int(q.network_address), q.prefixlen)) if x.subnet_of(n) else ([n] if not x.overlaps(n) else [])
    except Exception: continue
    out["exclude"].append({"n": str(n), "x": str(x), "out": [str(q) for q in res]})

for _ in range(200):
    v = random.choice([4, 6]); bits = 32 if v == 4 else 128
    a = random.getrandbits(bits); b = min((1 << bits) - 1, a + random.choice([0, 1, 5, 100, 1 << 12, random.getrandbits(bits - 4)]))
    A = ip.ip_address(a) if v == 4 else ip.IPv6Address(a); B = ip.ip_address(b) if v == 4 else ip.IPv6Address(b)
    out["range"].append({"a": str(A), "b": str(B), "out": [str(x) for x in ip.summarize_address_range(A, B)]})
json.dump(out, sys.stdout)
