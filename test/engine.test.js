import test from "node:test";
import assert from "node:assert/strict";
import * as E from "../src/engine.js";

const P = (s) => E.parse(s).net;
const S = (list) => list.map(E.str);

test("IPv4 basics: /24, /22, /30, /31, /32", () => {
    let i = E.info(P("192.168.1.77/24"));
    assert.equal(i.network, "192.168.1.0"); assert.equal(i.broadcast, "192.168.1.255");
    assert.equal(i.first, "192.168.1.1"); assert.equal(i.lastHost, "192.168.1.254");
    assert.equal(i.usable.n, 254n); assert.equal(i.netmask, "255.255.255.0"); assert.equal(i.wildcard, "0.0.0.255");
    i = E.info(P("10.20.30.40/22"));
    assert.equal(i.network, "10.20.28.0"); assert.equal(i.lastAddr, "10.20.31.255"); assert.equal(i.usable.n, 1022n);
    i = E.info(P("10.0.0.0/30")); assert.equal(i.usable.n, 2n); assert.equal(i.first, "10.0.0.1"); assert.equal(i.lastHost, "10.0.0.2");
    i = E.info(P("10.0.0.0/31")); assert.equal(i.usable.n, 2n); assert.equal(i.first, "10.0.0.0"); assert.match(i.hostNote, /3021/);
    i = E.info(P("10.0.0.5/32")); assert.equal(i.usable.n, 1n); assert.equal(i.first, "10.0.0.5");
    i = E.info(P("0.0.0.0/0")); assert.equal(i.total.n, 1n << 32n); assert.equal(i.netmask, "0.0.0.0");
});

test("input forms: mask, wildcard, bare host, brackets, spaces", () => {
    assert.equal(E.str(P("10.1.2.3 255.255.255.0")), "10.1.2.0/24");
    assert.equal(E.str(P("10.1.2.3 0.0.0.255")), "10.1.2.0/24");
    assert.equal(E.str(P("10.1.2.3 0.0.0.0")), "0.0.0.0/0");                // all zeros reads as a netmask, so /0
    assert.equal(E.str(P("10.1.2.3")), "10.1.2.3/32");
    assert.equal(E.str(P("  10.1.2.3 / 24 ")), "10.1.2.0/24");
    assert.equal(E.str(P("[2001:db8::1]/64")), "2001:db8::/64");
    assert.equal(E.str(P("2001:DB8:0:0:0:0:0:1/32")), "2001:db8::/32");
});

test("rejects bad input with a reason", () => {
    for (const bad of ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4/33", "1.2.3.4/-1", "01.2.3.4", "a.b.c.d", "1.2.3.4 255.0.255.0", "::1::2", "2001:db8::/129", "1:2:3:4:5:6:7:8:9", "12345::1", "1.2.3.4/x"]) {
        assert.throws(() => E.parse(bad), E.CidrError, bad);
    }
});

test("IPv6 formatting follows RFC 5952", () => {
    const f = (s) => E.fmtV6(E.parseV6(s));
    assert.equal(f("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1");
    assert.equal(f("2001:db8:0:0:1:0:0:1"), "2001:db8::1:0:0:1");           // longest run wins, leftmost on a tie
    assert.equal(f("2001:db8:0:1:1:1:1:1"), "2001:db8:0:1:1:1:1:1");          // a single zero group is not compressed
    assert.equal(f("0:0:0:0:0:0:0:0"), "::");
    assert.equal(f("0:0:0:0:0:0:0:1"), "::1");
    assert.equal(f("::ffff:192.0.2.1"), "::ffff:c000:201");
    assert.equal(E.fmtV6(E.parseV6("fe80::1"), { expand: true }), "fe80:0000:0000:0000:0000:0000:0000:0001");
    assert.equal(E.fmtV6(E.parseV6("fe80::1%eth0")), "fe80::1");
});

test("IPv6 info", () => {
    const i = E.info(P("2001:db8:abcd:12::5/48"));
    assert.equal(i.cidr, "2001:db8:abcd::/48"); assert.equal(i.lastAddr, "2001:db8:abcd:ffff:ffff:ffff:ffff:ffff");
    assert.equal(i.total.n, 1n << 80n); assert.equal(i.subnets64.n, 65536n); assert.equal(i.kind.scope, "documentation");
    assert.equal(E.info(P("::ffff:192.0.2.1/128")).mapped, "192.0.2.1");
});

test("classification", () => {
    const k = (s) => E.classify(P(s));
    assert.equal(k("10.1.1.0/24").scope, "private"); assert.equal(k("172.16.0.0/12").scope, "private");
    assert.equal(k("172.32.0.0/16").scope, "public"); assert.equal(k("100.64.1.0/24").scope, "shared");
    assert.equal(k("169.254.1.1/32").scope, "link-local"); assert.equal(k("127.0.0.1/32").scope, "loopback");
    assert.equal(k("8.8.8.8/32").scope, "public"); assert.equal(k("224.0.0.1/32").scope, "multicast");
    assert.equal(k("192.0.2.0/24").scope, "documentation"); assert.equal(k("fd00::/8").scope, "private");
    assert.equal(k("fe80::/64").scope, "link-local"); assert.equal(k("2606:4700::/32").scope, "public");
    const wide = k("0.0.0.0/0"); assert.equal(wide.scope, "mixed"); assert.ok(wide.spans.length > 5);
});

test("reverse DNS zones", () => {
    assert.deepEqual(E.reverseZones(P("192.168.1.0/24")), ["1.168.192.in-addr.arpa"]);
    assert.deepEqual(E.reverseZones(P("10.0.0.0/8")), ["10.in-addr.arpa"]);
    assert.deepEqual(E.reverseZones(P("172.16.0.0/14")), ["16.172.in-addr.arpa", "17.172.in-addr.arpa", "18.172.in-addr.arpa", "19.172.in-addr.arpa"]);
    assert.deepEqual(E.reverseZones(P("192.0.2.64/26")), ["64/26.2.0.192.in-addr.arpa"]);
    assert.deepEqual(E.reverseZones(P("2001:db8::/32")), ["8.b.d.0.1.0.0.2.ip6.arpa"]);
    const z33 = E.reverseZones(P("2001:db8::/33"));                       // /33 is not on a nibble boundary: 8 zones of /36
    assert.equal(z33.length, 8); assert.equal(z33[0], "0.8.b.d.0.1.0.0.2.ip6.arpa"); assert.equal(z33[7], "7.8.b.d.0.1.0.0.2.ip6.arpa");
    assert.equal(E.reverseZones(P("2001:db8::/34")).length, 4);
});

test("split", () => {
    const r = E.split(P("10.0.0.0/24"), 26);
    assert.deepEqual(S(r.subnets), ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"]);
    assert.equal(r.total, 4n); assert.equal(r.truncated, false);
    assert.equal(E.split(P("2001:db8::/32"), 64, 10).truncated, true);
    assert.equal(E.splitCount(P("2001:db8::/32"), 64), 1n << 32n);
    assert.throws(() => E.split(P("10.0.0.0/24"), 23), E.CidrError);
    assert.deepEqual(E.prefixForCount(P("10.0.0.0/24"), 5), { newP: 27, exact: false, got: 8 });
    assert.deepEqual(E.prefixForCount(P("10.0.0.0/24"), 4), { newP: 26, exact: true, got: 4 });
});

test("range to CIDR", () => {
    assert.deepEqual(S(E.rangeToCidrs(4, E.parseV4("10.0.0.1"), E.parseV4("10.0.0.6"))), ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]);
    assert.deepEqual(S(E.rangeToCidrs(4, 0n, 0xffffffffn)), ["0.0.0.0/0"]);
    assert.deepEqual(S(E.rangeToCidrs(4, E.parseV4("192.168.0.0"), E.parseV4("192.168.3.255"))), ["192.168.0.0/22"]);
    assert.deepEqual(S(E.rangeToCidrs(4, E.parseV4("255.255.255.255"), E.parseV4("255.255.255.255"))), ["255.255.255.255/32"]);
    assert.deepEqual(S(E.rangeToCidrs(6, E.parseV6("::"), E.parseV6("::3"))), ["::/126"]);
});

test("aggregate", () => {
    const ag = (...x) => S(E.aggregate(x.map(P)));
    assert.deepEqual(ag("10.0.0.0/25", "10.0.0.128/25"), ["10.0.0.0/24"]);
    assert.deepEqual(ag("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"), ["10.0.0.0/22"]);
    assert.deepEqual(ag("10.0.1.0/24", "10.0.2.0/24"), ["10.0.1.0/24", "10.0.2.0/24"]);       // not aligned, cannot merge
    assert.deepEqual(ag("10.0.0.0/16", "10.0.5.0/24", "10.0.0.0/16"), ["10.0.0.0/16"]);
    assert.deepEqual(ag("0.0.0.0/1", "128.0.0.0/1"), ["0.0.0.0/0"]);
    assert.deepEqual(ag("2001:db8::/33", "2001:db8:8000::/33"), ["2001:db8::/32"]);
    assert.deepEqual(ag("10.0.0.0/24", "2001:db8::/32"), ["10.0.0.0/24", "2001:db8::/32"]);
});

test("enclosing block and what it adds", () => {
    const e = E.enclosing([P("10.0.0.0/24"), P("10.0.3.0/24")], 4);
    assert.equal(E.str(e.net), "10.0.0.0/22"); assert.equal(e.listed, 512n); assert.equal(e.extra, 512n);
    assert.equal(E.enclosing([P("10.0.0.0/24")], 6), null);
});

test("overlaps", () => {
    const o = E.overlaps([P("10.0.0.0/16"), P("10.0.5.0/24"), P("192.168.0.0/24"), P("10.0.5.0/24")]);
    assert.equal(o.length, 3);
    assert.deepEqual(o.map((x) => x.kind).sort(), ["contains", "contains", "equal"]);
});

test("exclude (subtract)", () => {
    assert.deepEqual(S(E.exclude(P("10.0.0.0/24"), P("10.0.0.64/26"))), ["10.0.0.0/26", "10.0.0.128/25"]);
    assert.deepEqual(S(E.exclude(P("10.0.0.0/24"), P("10.0.0.0/24"))), []);
    assert.deepEqual(S(E.exclude(P("10.0.0.0/24"), P("192.168.0.0/24"))), ["10.0.0.0/24"]);
    const pieces = E.exclude(P("10.0.0.0/16"), P("10.0.77.5/32"));
    assert.equal(pieces.length, 16);
    assert.equal(pieces.reduce((s, x) => s + E.size(x), 0n), 65535n);
    assert.ok(pieces.every((x) => E.relation(x, P("10.0.77.5/32")) === "disjoint"));
});

test("VLSM: largest first, aligned, nothing overlaps", () => {
    const r = E.vlsm(P("192.168.10.0/24"), [{ name: "Servers", hosts: 25 }, { name: "Staff", hosts: 100 }, { name: "Guests", hosts: 50 }, { name: "Link", hosts: 2 }]);
    assert.equal(r.unplaced.length, 0);
    const by = Object.fromEntries(r.placed.map((x) => [x.name, E.str(x.net)]));
    assert.deepEqual(by, { Staff: "192.168.10.0/25", Guests: "192.168.10.128/26", Servers: "192.168.10.192/27", Link: "192.168.10.224/30" });
    assert.deepEqual(S(r.free), ["192.168.10.228/30", "192.168.10.232/29", "192.168.10.240/28"]);
    assert.equal(E.overlaps(r.placed.map((x) => x.net)).length, 0);
    const tight = E.vlsm(P("10.0.0.0/24"), [{ name: "A", hosts: 200 }, { name: "B", hosts: 100 }]);
    assert.equal(tight.unplaced.length, 1); assert.match(tight.unplaced[0].reason, /no room/);
    const ptp = E.vlsm(P("10.0.0.0/24"), [{ name: "L", hosts: 2 }], { ptp31: true });
    assert.equal(ptp.placed[0].net.p, 31);
    assert.equal(E.hostsToPrefix(254), 24); assert.equal(E.hostsToPrefix(255), 23); assert.equal(E.hostsToPrefix(1), 30);
});

test("lists: ranges, masks, comments, errors keep going", () => {
    const r = E.parseList("10.0.0.0/24\n# comment\n10.0.1.1 - 10.0.1.2\n172.16.0.0 255.255.0.0, bogus\n2001:db8::/32");
    assert.deepEqual(S(r.nets), ["10.0.0.0/24", "10.0.1.1/32", "10.0.1.2/32", "172.16.0.0/16", "2001:db8::/32"]);
    assert.equal(r.errors.length, 1); assert.equal(r.errors[0].text, "bogus");
});

test("neighbours and parent", () => {
    assert.equal(E.str(E.neighbour(P("10.0.0.0/24"), 1)), "10.0.1.0/24");
    assert.equal(E.neighbour(P("0.0.0.0/24"), -1), null);
    assert.equal(E.neighbour(P("255.255.255.0/24"), 1), null);
    assert.equal(E.str(E.parent(P("10.0.1.0/24"))), "10.0.0.0/23");
    assert.equal(E.parent(P("0.0.0.0/0")), null);
});

test("snippets carry the right values", () => {
    const s = E.snippets(P("10.20.30.0/24"));
    assert.equal(s.length, 4);
    assert.match(s[0].text, /ip address 10\.20\.30\.1 255\.255\.255\.0/);
    assert.match(s[0].text, /network 10\.20\.30\.0 0\.0\.0\.255 area 0/);
    assert.match(s[1].text, /ip address 10\.20\.30\.1 24/);
    assert.match(s[2].text, /address=10\.20\.30\.1\/24/);
    assert.match(E.snippets(P("2001:db8:1::/64"))[0].text, /ipv6 address 2001:db8:1::1\/64/);
});
