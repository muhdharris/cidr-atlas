// CIDR Atlas engine: IPv4 and IPv6 address maths on BigInt. No dependencies, no DOM.
// The web app and the command line both run on this file.
//
// A network is a plain object { v, a, p }:
//   v  4 or 6          a  network address (BigInt, host bits already zero)      p  prefix length

export class CidrError extends Error {}
const fail = (m) => { throw new CidrError(m); };

export const BITS = { 4: 32, 6: 128 };
const ALL = (v) => (1n << BigInt(BITS[v])) - 1n;
const maskOf = (v, p) => ALL(v) ^ (ALL(v) >> BigInt(p));          // top p bits set
const bitLen = (x) => (x === 0n ? 0 : x.toString(2).length);

/* ---------- addresses ---------- */

export function parseV4(s) {
    const parts = s.trim().split(".");
    if (parts.length !== 4) fail(`"${s}" is not an IPv4 address: it needs four numbers separated by dots`);
    let n = 0n;
    for (const part of parts) {
        if (!/^\d{1,3}$/.test(part)) fail(`"${part}" is not a valid IPv4 number`);
        if (part.length > 1 && part[0] === "0") fail(`"${part}" has a leading zero, which some systems read as octal; write it without`);
        const x = Number(part);
        if (x > 255) fail(`${x} is above 255`);
        n = (n << 8n) | BigInt(x);
    }
    return n;
}

export function parseV6(input) {
    let s = input.trim().toLowerCase();
    if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
    s = s.replace(/%.*$/, "");                                  // zone id such as %eth0 has no bearing on the maths
    if (!/^[0-9a-f:.]+$/.test(s) || !s.includes(":")) fail(`"${input}" is not an IPv6 address`);
    let tail = [];
    if (s.includes(".")) {                                      // embedded IPv4 in the last 32 bits
        const i = s.lastIndexOf(":");
        const v4 = parseV4(s.slice(i + 1));
        tail = [Number(v4 >> 16n), Number(v4 & 0xffffn)];
        s = s.slice(0, i + 1) + "0:0";
    }
    const halves = s.split("::");
    if (halves.length > 2) fail(`"${input}" has more than one "::"`);
    const grp = (t) => (t === "" ? [] : t.split(":"));
    const head = grp(halves[0]), back = halves.length === 2 ? grp(halves[1]) : [];
    const have = head.length + back.length;
    if (halves.length === 1 && have !== 8) fail(`"${input}" needs eight groups (or a "::" to stand for zeros)`);
    if (halves.length === 2 && have > 7) fail(`"${input}" has too many groups for a "::"`);
    const all = [...head, ...Array(8 - have).fill("0"), ...back];
    let n = 0n;
    for (const g of all) {
        if (!/^[0-9a-f]{1,4}$/.test(g)) fail(`"${g}" is not a valid IPv6 group (1 to 4 hex digits)`);
        n = (n << 16n) | BigInt(parseInt(g, 16));
    }
    if (tail.length) n = (n & ~0xffffffffn) | (BigInt(tail[0]) << 16n) | BigInt(tail[1]);
    return n;
}

export function parseAddress(s) {
    const t = s.trim();
    if (!t) fail("empty address");
    return t.includes(":") ? { v: 6, x: parseV6(t) } : { v: 4, x: parseV4(t) };
}

export const fmtV4 = (n) => [24n, 16n, 8n, 0n].map((sh) => Number((n >> sh) & 255n)).join(".");

export function fmtV6(n, { expand = false } = {}) {
    const g = [];
    for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
    if (expand) return g.map((x) => x.toString(16).padStart(4, "0")).join(":");
    let best = -1, bestLen = 0;                                  // RFC 5952: longest run of zeros, leftmost on a tie, at least two
    for (let i = 0; i < 8;) {
        if (g[i] !== 0) { i++; continue; }
        let j = i; while (j < 8 && g[j] === 0) j++;
        if (j - i > bestLen) { best = i; bestLen = j - i; }
        i = j;
    }
    const h = (x) => x.toString(16);
    if (bestLen < 2) return g.map(h).join(":");
    return g.slice(0, best).map(h).join(":") + "::" + g.slice(best + bestLen).map(h).join(":");
}

export const fmt = (v, x, o) => (v === 4 ? fmtV4(x) : fmtV6(x, o));

/* ---------- networks ---------- */

export function mk(v, x, p) {
    if (!Number.isInteger(p) || p < 0 || p > BITS[v]) fail(`prefix /${p} is outside 0 to ${BITS[v]} for IPv${v}`);
    return { v, a: x & maskOf(v, p), p };
}
export const size = (n) => 1n << BigInt(BITS[n.v] - n.p);
export const last = (n) => n.a + size(n) - 1n;
export const str = (n) => `${fmt(n.v, n.a)}/${n.p}`;
export const maskBig = (n) => maskOf(n.v, n.p);

// "10.1.2.3/22", "10.1.2.3 255.255.255.0", "10.1.2.3 0.0.0.255" (wildcard), "10.1.2.3" (a single host),
// "2001:db8::1/48". Returns the network and the address that was typed (which may have host bits).
export function parse(input) {
    const s = String(input).trim();
    if (!s) fail("type an address, for example 10.20.30.40/22");
    const m = s.match(/^(\S+?)(?:\s*\/\s*(\S+)|\s+(\d+\.\d+\.\d+\.\d+))?$/);
    if (!m) fail(`could not read "${s}": expected address/prefix, for example 10.0.0.0/24`);
    const { v, x } = parseAddress(m[1]);
    const rest = m[2] ?? m[3];
    let p;
    if (rest === undefined) p = BITS[v];
    else if (/^\d+$/.test(rest)) p = Number(rest);
    else if (v === 4 && /^\d+\.\d+\.\d+\.\d+$/.test(rest)) p = prefixFromMask(parseV4(rest));
    else fail(`"${rest}" is not a prefix length or a netmask`);
    return { net: mk(v, x, p), ip: x, v, p };
}

export function prefixFromMask(m) {
    // A netmask is ones then zeros (255.255.255.0). A wildcard, as Cisco ACLs write it, is the
    // reverse: zeros then ones (0.0.0.255). 0.0.0.0 reads as a netmask, so it means /0.
    let p = 0;
    for (let b = 31; b >= 0 && ((m >> BigInt(b)) & 1n); b--) p++;
    if (m === maskOf(4, p)) return p;
    if ((m & (m + 1n)) === 0n) return 32 - bitLen(m);
    fail(`${fmtV4(m)} is neither a valid netmask nor a valid wildcard (the ones must be unbroken)`);
}

export const maskString = (p) => fmtV4(maskOf(4, p));
export const wildcardString = (p) => fmtV4(~maskOf(4, p) & ALL(4));

export function relation(a, b) {
    if (a.v !== b.v) return "different";
    if (a.a === b.a && a.p === b.p) return "equal";
    if (a.p <= b.p && (b.a & maskOf(a.v, a.p)) === a.a) return "contains";
    if (b.p <= a.p && (a.a & maskOf(b.v, b.p)) === b.a) return "within";
    return "disjoint";
}
export const containsAddr = (n, v, x) => n.v === v && (x & maskOf(n.v, n.p)) === n.a;

/* ---------- what an address block is ---------- */

const R4 = [
    ["0.0.0.0/8", "This network (only valid as a source)", "reserved", "RFC 791"],
    ["10.0.0.0/8", "Private use", "private", "RFC 1918"],
    ["100.64.0.0/10", "Shared address space (carrier-grade NAT)", "shared", "RFC 6598"],
    ["127.0.0.0/8", "Loopback", "loopback", "RFC 1122"],
    ["169.254.0.0/16", "Link-local (APIPA)", "link-local", "RFC 3927"],
    ["172.16.0.0/12", "Private use", "private", "RFC 1918"],
    ["192.0.0.0/24", "IETF protocol assignments", "reserved", "RFC 6890"],
    ["192.0.2.0/24", "Documentation (TEST-NET-1)", "documentation", "RFC 5737"],
    ["192.88.99.0/24", "6to4 relay anycast (deprecated)", "reserved", "RFC 7526"],
    ["192.168.0.0/16", "Private use", "private", "RFC 1918"],
    ["198.18.0.0/15", "Network benchmarking", "benchmark", "RFC 2544"],
    ["198.51.100.0/24", "Documentation (TEST-NET-2)", "documentation", "RFC 5737"],
    ["203.0.113.0/24", "Documentation (TEST-NET-3)", "documentation", "RFC 5737"],
    ["224.0.0.0/4", "Multicast", "multicast", "RFC 5771"],
    ["240.0.0.0/4", "Reserved for future use", "reserved", "RFC 1112"],
    ["255.255.255.255/32", "Limited broadcast", "broadcast", "RFC 919"],
];
const R6 = [
    ["::/128", "Unspecified address", "reserved", "RFC 4291"],
    ["::1/128", "Loopback", "loopback", "RFC 4291"],
    ["::ffff:0:0/96", "IPv4-mapped address", "reserved", "RFC 4291"],
    ["64:ff9b::/96", "NAT64 translation prefix", "reserved", "RFC 6052"],
    ["100::/64", "Discard-only", "reserved", "RFC 6666"],
    ["2000::/3", "Global unicast", "public", "RFC 4291"],
    ["2001::/32", "Teredo tunnelling", "reserved", "RFC 4380"],
    ["2001:db8::/32", "Documentation", "documentation", "RFC 3849"],
    ["2002::/16", "6to4", "reserved", "RFC 3056"],
    ["fc00::/7", "Unique local address (private)", "private", "RFC 4193"],
    ["fe80::/10", "Link-local", "link-local", "RFC 4291"],
    ["ff00::/8", "Multicast", "multicast", "RFC 4291"],
];
const table = (rows) => rows.map(([c, label, scope, rfc]) => ({ net: parse(c).net, label, scope, rfc }));
const SPECIAL = { 4: table(R4), 6: table(R6) };

// The most specific registered range that holds the whole block; otherwise any special ranges it runs across.
export function classify(n) {
    let best = null;
    for (const r of SPECIAL[n.v]) if (relation(r.net, n) === "contains" || relation(r.net, n) === "equal") if (!best || r.net.p > best.net.p) best = r;
    if (best) return { label: best.label, scope: best.scope, rfc: best.rfc, whole: true, spans: [] };
    const spans = SPECIAL[n.v].filter((r) => relation(r.net, n) === "within");
    if (spans.length) return { label: "Spans several ranges", scope: "mixed", rfc: "", whole: false, spans: spans.map((r) => ({ net: str(r.net), label: r.label })) };
    return n.v === 4
        ? { label: "Public (globally routable unicast)", scope: "public", rfc: "", whole: true, spans: [] }
        : { label: "Reserved, not yet allocated by IANA", scope: "reserved", rfc: "", whole: true, spans: [] };
}

/* ---------- inspect ---------- */

export function hostRange(n) {
    const sz = size(n);
    if (n.v === 4) {
        if (n.p === 32) return { first: n.a, last: n.a, usable: 1n, note: "single host" };
        if (n.p === 31) return { first: n.a, last: last(n), usable: 2n, note: "point-to-point link, both addresses usable (RFC 3021)" };
        return { first: n.a + 1n, last: last(n) - 1n, usable: sz - 2n, note: "" };
    }
    if (n.p === 128) return { first: n.a, last: n.a, usable: 1n, note: "single host" };
    return { first: n.a, last: last(n), usable: sz, note: n.p === 127 ? "point-to-point link (RFC 6164)" : "every address is usable; the first is the subnet-router anycast" };
}

const sep = (x) => x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
export function count(x) {
    const k = bitLen(x) - 1;
    return { n: x, text: sep(x), pow: x === 1n ? "1" : `2^${k}`, short: x < 10n ** 12n ? sep(x) : `2^${k}` };
}

export function reverseZones(n) {
    if (n.v === 4) {
        const o = fmtV4(n.a).split(".").map(Number);
        if (n.p >= 24) {
            const base = `${o[2]}.${o[1]}.${o[0]}.in-addr.arpa`;
            return n.p === 24 ? [base] : [`${o[3]}/${n.p}.${base}`];                    // RFC 2317 classless delegation
        }
        const zb = Math.max(8, Math.ceil(n.p / 8) * 8), cnt = 1 << (zb - n.p), step = 1 << (32 - zb);
        const keep = zb / 8, out = [];
        for (let i = 0; i < Math.min(cnt, 8); i++) {
            const a = fmtV4(n.a + BigInt(i * step)).split(".").map(Number).slice(0, keep).reverse();
            out.push(`${a.join(".")}.in-addr.arpa`);
        }
        if (cnt > 8) out.push(`... ${cnt} zones in all`);
        return out;
    }
    const zb = Math.max(4, Math.ceil(n.p / 4) * 4), cnt = 1 << (zb - n.p), out = [];
    for (let i = 0; i < Math.min(cnt, 8); i++) {
        const nib = (n.a + (BigInt(i) << BigInt(128 - zb))).toString(16).padStart(32, "0").slice(0, zb / 4);
        out.push(`${[...nib].reverse().join(".")}.ip6.arpa`);
    }
    if (cnt > 8) out.push(`... ${cnt} zones in all`);
    return out;
}

export function info(n, typedIp) {
    const hr = hostRange(n), sz = size(n), ip = typedIp ?? n.a;
    const out = {
        net: n, cidr: str(n), version: n.v, prefix: n.p,
        network: fmt(n.v, n.a), lastAddr: fmt(n.v, last(n)),
        first: fmt(n.v, hr.first), lastHost: fmt(n.v, hr.last),
        usable: count(hr.usable), total: count(sz), hostNote: hr.note,
        kind: classify(n), reverse: reverseZones(n),
        hostIndex: ip - n.a, typed: fmt(n.v, ip), typedInside: ip >= n.a && ip <= last(n),
    };
    if (n.v === 4) {
        out.netmask = maskString(n.p); out.wildcard = wildcardString(n.p);
        out.broadcast = n.p >= 31 ? (n.p === 31 ? fmtV4(last(n)) + " (not used)" : "none (single host)") : fmtV4(last(n));
        const f = Number(n.a >> 24n);
        out.class = f < 128 ? "A" : f < 192 ? "B" : f < 224 ? "C" : f < 240 ? "D (multicast)" : "E (reserved)";
        out.binary = fmtV4(n.a).split(".").map((o) => Number(o).toString(2).padStart(8, "0")).join(".");
    } else {
        out.expanded = fmtV6(n.a, { expand: true });
        out.lastExpanded = fmtV6(last(n), { expand: true });
        out.subnets64 = n.p <= 64 ? count(1n << BigInt(64 - n.p)) : null;
        if ((n.a >> 32n) === 0xffffn && n.p >= 96) out.mapped = fmtV4(n.a & 0xffffffffn);
    }
    return out;
}

/* ---------- walking the address space ---------- */

export const parent = (n) => (n.p === 0 ? null : mk(n.v, n.a, n.p - 1));
export function neighbour(n, dir) {
    const next = n.a + (dir > 0 ? size(n) : -size(n));
    if (next < 0n || next > ALL(n.v)) return null;
    return mk(n.v, next, n.p);
}

/* ---------- split ---------- */

export function splitCount(n, newP) {
    if (!Number.isInteger(newP) || newP < n.p || newP > BITS[n.v]) fail(`the new prefix must be between /${n.p} and /${BITS[n.v]}`);
    return 1n << BigInt(newP - n.p);
}
export function split(n, newP, limit = 1 << 20) {
    const total = splitCount(n, newP);
    const step = 1n << BigInt(BITS[n.v] - newP), out = [];
    const take = total < BigInt(limit) ? Number(total) : limit;
    for (let i = 0; i < take; i++) out.push({ v: n.v, a: n.a + BigInt(i) * step, p: newP });
    return { subnets: out, total, truncated: total > BigInt(take) };
}
// "into N": the next power of two at or above N, because CIDR blocks halve
export function prefixForCount(n, want) {
    if (!Number.isInteger(want) || want < 1) fail("the number of subnets must be 1 or more");
    const k = want <= 1 ? 0 : bitLen(BigInt(want) - 1n);
    return { newP: n.p + k, exact: 1 << k === want, got: 2 ** k };
}

/* ---------- ranges, aggregation, subtraction ---------- */

export function rangeToCidrs(v, start, end) {
    if (start > end) fail("the range starts after it ends");
    const out = [];
    while (start <= end) {
        let sz = start === 0n ? 1n << BigInt(BITS[v]) : start & -start;
        while (sz > end - start + 1n) sz >>= 1n;
        out.push({ v, a: start, p: BITS[v] - (bitLen(sz) - 1) });
        start += sz;
        if (start > ALL(v)) break;
    }
    return out;
}

const byAddr = (x, y) => (x.a < y.a ? -1 : x.a > y.a ? 1 : x.p - y.p);

export function aggregate(list) {
    const out = [];
    for (const v of [4, 6]) {
        const nets = list.filter((n) => n.v === v).sort(byAddr);
        const kept = [];
        for (const n of nets) {                                    // drop duplicates and anything inside an earlier block
            const lastKept = kept[kept.length - 1];
            if (lastKept && relation(lastKept, n) !== "disjoint") continue;
            kept.push(n);
        }
        const stack = [];
        for (const n of kept) {
            let cur = n;
            while (stack.length) {
                const top = stack[stack.length - 1];
                if (top.p === cur.p && cur.p > 0 && top.a + size(top) === cur.a && (top.a & maskOf(v, cur.p - 1)) === top.a) {
                    stack.pop(); cur = mk(v, top.a, cur.p - 1);
                } else break;
            }
            stack.push(cur);
        }
        out.push(...stack);
    }
    return out;
}

// the single smallest block that covers every network in the list, and what it covers beyond them
export function enclosing(list, v) {
    const nets = list.filter((n) => n.v === v);
    if (!nets.length) return null;
    let lo = nets[0].a, hi = last(nets[0]);
    for (const n of nets) { if (n.a < lo) lo = n.a; if (last(n) > hi) hi = last(n); }
    const p = BITS[v] - bitLen(lo ^ hi);
    const net = mk(v, lo, p);
    const listed = aggregate(nets).reduce((s, n) => s + size(n), 0n);
    return { net, listed, extra: size(net) - listed };
}

export function overlaps(list) {
    const found = [];
    for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) {
        const r = relation(list[i], list[j]);
        if (r !== "disjoint" && r !== "different") found.push({ a: list[i], b: list[j], kind: r });
    }
    return found;
}

export function exclude(n, x) {
    const r = relation(n, x);
    if (r === "different") fail("cannot subtract an IPv6 block from an IPv4 block");
    if (r === "disjoint") return [n];
    if (r === "equal" || r === "within") return [];
    const out = [];
    let cur = n;
    while (cur.p < x.p) {
        const lo = mk(n.v, cur.a, cur.p + 1), hi = mk(n.v, cur.a + size(lo), cur.p + 1);
        if (relation(lo, x) === "contains" || relation(lo, x) === "equal") { out.push(hi); cur = lo; } else { out.push(lo); cur = hi; }
    }
    return out.sort(byAddr);
}

/* ---------- VLSM ---------- */

export function hostsToPrefix(hosts, { ptp31 = false } = {}) {
    if (!Number.isInteger(hosts) || hosts < 1) fail("each subnet needs at least 1 host");
    if (ptp31 && hosts === 2) return 31;
    const need = BigInt(hosts) + 2n;
    return 32 - (bitLen(need - 1n));
}

export function vlsm(parentNet, reqs, opts = {}) {
    if (parentNet.v !== 4) fail("the VLSM planner is for IPv4. In IPv6 every LAN is a /64, so use Split instead");
    const items = reqs.map((r, i) => {
        const p = hostsToPrefix(r.hosts, opts);
        return { i, name: r.name, hosts: r.hosts, p, sz: 1n << BigInt(32 - p) };
    });
    const order = [...items].sort((x, y) => (x.sz === y.sz ? x.i - y.i : x.sz > y.sz ? -1 : 1));
    const end = last(parentNet);
    let cursor = parentNet.a;
    const placed = [], unplaced = [];
    for (const it of order) {
        const start = ((cursor + it.sz - 1n) / it.sz) * it.sz;                  // next address aligned to the block size
        if (it.p < parentNet.p || start + it.sz - 1n > end) {
            unplaced.push({ ...it, reason: it.p < parentNet.p ? `needs a /${it.p}, larger than the parent /${parentNet.p}` : `no room left in ${str(parentNet)}` });
            continue;
        }
        const net = { v: 4, a: start, p: it.p };
        const hr = hostRange(net);
        placed.push({ ...it, net, usable: hr.usable, spare: hr.usable - BigInt(it.hosts) });
        cursor = start + it.sz;
    }
    placed.sort((x, y) => (x.net.a < y.net.a ? -1 : 1));
    const free = [];
    let at = parentNet.a;
    for (const pl of placed) { if (pl.net.a > at) free.push(...rangeToCidrs(4, at, pl.net.a - 1n)); at = pl.net.a + pl.sz; }
    if (at <= end) free.push(...rangeToCidrs(4, at, end));
    const used = placed.reduce((s, x) => s + x.sz, 0n);
    const wanted = placed.reduce((s, x) => s + BigInt(x.hosts), 0n);
    const usableSum = placed.reduce((s, x) => s + x.usable, 0n);
    return { placed, unplaced, free, parent: parentNet, used, total: size(parentNet), wanted, usableSum };
}

/* ---------- device configuration snippets ---------- */

export function snippets(n, typedIp, nextHop) {
    const ip = typedIp !== undefined && n.p < BITS[n.v] ? typedIp : (n.v === 4 ? n.a + (n.p < 31 ? 1n : 0n) : n.a + 1n);
    const host = fmt(n.v, ip), net = fmt(n.v, n.a), nh = nextHop || (n.v === 4 ? "192.0.2.1" : "2001:db8::1");
    if (n.v === 4) {
        const mask = maskString(n.p), wc = wildcardString(n.p);
        return [
            { name: "Cisco IOS", text: `interface GigabitEthernet0/0\n ip address ${host} ${mask}\n!\nip route ${net} ${mask} ${nh}\n!\nrouter ospf 1\n network ${net} ${wc} area 0\n!\nip access-list extended EXAMPLE\n permit ip ${net} ${wc} any` },
            { name: "Huawei VRP", text: `interface GigabitEthernet0/0/1\n ip address ${host} ${n.p}\n#\nip route-static ${net} ${n.p} ${nh}\n#\nospf 1\n area 0.0.0.0\n  network ${net} ${wc}\n#\nacl name EXAMPLE advance\n rule permit ip source ${net} ${wc}` },
            { name: "MikroTik", text: `/ip address add address=${host}/${n.p} interface=ether1\n/ip route add dst-address=${net}/${n.p} gateway=${nh}\n/routing ospf network add network=${net}/${n.p} area=backbone\n/ip firewall address-list add list=EXAMPLE address=${net}/${n.p}` },
            { name: "Linux", text: `ip addr add ${host}/${n.p} dev eth0\nip route add ${net}/${n.p} via ${nh}\nnft add rule inet filter input ip saddr ${net}/${n.p} accept` },
        ];
    }
    return [
        { name: "Cisco IOS", text: `interface GigabitEthernet0/0\n ipv6 address ${host}/${n.p}\n!\nipv6 route ${net}/${n.p} ${nh}\n!\nipv6 access-list EXAMPLE\n permit ipv6 ${net}/${n.p} any` },
        { name: "Huawei VRP", text: `interface GigabitEthernet0/0/1\n ipv6 enable\n ipv6 address ${host} ${n.p}\n#\nipv6 route-static ${net} ${n.p} ${nh}\n#\nacl ipv6 name EXAMPLE advance\n rule permit ipv6 source ${net}/${n.p}` },
        { name: "MikroTik", text: `/ipv6 address add address=${host}/${n.p} interface=ether1\n/ipv6 route add dst-address=${net}/${n.p} gateway=${nh}\n/ipv6 firewall address-list add list=EXAMPLE address=${net}/${n.p}` },
        { name: "Linux", text: `ip -6 addr add ${host}/${n.p} dev eth0\nip -6 route add ${net}/${n.p} via ${nh}\nnft add rule inet filter input ip6 saddr ${net}/${n.p} accept` },
    ];
}

/* ---------- reading lists from text ---------- */

// One entry per line (or comma/semicolon). Accepts CIDR, a single address, a netmask form, or "a - b" ranges.
export function parseList(text) {
    const nets = [], errors = [];
    const lines = text.split(/\r?\n|[;,]/).map((l) => l.replace(/#.*$/, "").trim()).filter(Boolean);
    lines.forEach((line, i) => {
        try {
            const r = line.match(/^(\S+)\s*(?:-|\u2013|\bto\b)\s*(\S+)$/i);
            if (r && !line.includes("/")) {
                const a = parseAddress(r[1]), b = parseAddress(r[2]);
                if (a.v !== b.v) fail("a range cannot mix IPv4 and IPv6");
                nets.push(...rangeToCidrs(a.v, a.x, b.x));
            } else nets.push(parse(line).net);
        } catch (e) {
            if (!(e instanceof CidrError)) throw e;
            errors.push({ line: i + 1, text: line, message: e.message });
        }
    });
    return { nets, errors };
}
