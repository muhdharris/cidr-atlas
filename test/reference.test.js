// Differential test: CIDR Atlas against Python's ipaddress module on thousands of random inputs.
// Regenerate the reference with: python3 tools/gen_reference.py > test/reference.json
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import * as E from "../src/engine.js";

const file = new URL("./reference.json", import.meta.url);
const R = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
const t = R ? test : test.skip;
const P = (s) => E.parse(s).net;
const S = (l) => l.map(E.str);

t("addresses, masks and counts match ipaddress", () => {
    for (const e of R.info) {
        const n = P(e.in), i = E.info(n);
        assert.equal(i.network, e.net, e.in);
        assert.equal(E.fmt(n.v, E.last(n)), e.last, e.in);
        assert.equal(E.size(n).toString(), e.total, e.in);
        assert.equal(E.fmt(n.v, n.a), e.compressed, e.in);
        if (n.v === 6) assert.equal(i.expanded, e.exploded, e.in);
        if (n.v === 4) { assert.equal(i.netmask, e.mask, e.in); assert.equal(i.wildcard, e.wild, e.in); }
    }
});
t("split matches subnets()", () => {
    for (const e of R.split) assert.deepEqual(S(E.split(P(e.in), e.new).subnets), e.subnets, e.in);
});
t("aggregate matches collapse_addresses()", () => {
    for (const e of R.aggregate) assert.deepEqual(S(E.aggregate(e.in.map(P))), e.out, e.in.join(" "));
});
t("exclude matches address_exclude()", () => {
    for (const e of R.exclude) assert.deepEqual(S(E.exclude(P(e.n), P(e.x))), e.out, `${e.n} - ${e.x}`);
});
t("range to CIDR matches summarize_address_range()", () => {
    for (const e of R.range) {
        const a = E.parseAddress(e.a), b = E.parseAddress(e.b);
        assert.deepEqual(S(E.rangeToCidrs(a.v, a.x, b.x)), e.out, `${e.a} - ${e.b}`);
    }
});
