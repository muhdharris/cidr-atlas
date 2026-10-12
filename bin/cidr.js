#!/usr/bin/env node
// cidr: the same engine as the web app, on the command line. No dependencies.
import * as E from "../src/engine.js";

const HELP = `cidr: IPv4 and IPv6 subnet calculator

  cidr info <addr/prefix>                 everything about a block
  cidr split <addr/prefix> <new-prefix>   cut a block into equal subnets   (or: --into N)
  cidr vlsm <addr/prefix> <name=hosts>... plan subnets by host count, largest first   (--ptp31)
  cidr agg <block>...                     merge blocks into the fewest CIDRs  (reads stdin if none)
  cidr range <first> <last>               turn an address range into CIDR blocks
  cidr exclude <block> <hole>             what is left of a block after cutting a hole out
  cidr contains <block> <addr/block>      exit 0 if it is inside, 1 if not
  cidr overlap <block>...                 list blocks that overlap (exit 1 if any do)

  --json   machine-readable output        --help   this text
Accepts 10.0.0.0/24, "10.0.0.0 255.255.255.0", "10.0.0.0 0.0.0.255", a bare address, or IPv6.`;

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith("--")));
const args = argv.filter((a) => !a.startsWith("--"));
const into = (() => { const i = argv.indexOf("--into"); return i >= 0 ? Number(argv[i + 1]) : null; })();
if (into !== null) args.splice(args.indexOf(String(into)), 1);
const json = flags.has("--json");
const J = (o) => JSON.stringify(o, (k, v) => (typeof v === "bigint" ? v.toString() : k === "net" && v && v.a !== undefined ? E.str(v) : v), 2);
const P = (s) => E.parse(s).net;
const out = (s) => process.stdout.write(s + "\n");
const pad = (k) => (k + ":").padEnd(15);

async function stdinText() {
    if (process.stdin.isTTY) return "";
    let t = ""; for await (const c of process.stdin) t += c; return t;
}
async function listFrom(rest) {
    const text = rest.length ? rest.join("\n") : await stdinText();
    const { nets, errors } = E.parseList(text);
    for (const e of errors) process.stderr.write(`line ${e.line}: ${e.text}: ${e.message}\n`);
    if (errors.length && !nets.length) process.exit(2);
    return nets;
}

try {
    const [cmd, ...rest] = args;
    if (!cmd || flags.has("--help") || cmd === "help") { out(HELP); process.exit(cmd || flags.has("--help") ? 0 : 2); }

    if (cmd === "info") {
        const p = E.parse(rest.join(" ")); const i = E.info(p.net, p.ip);
        if (json) { out(J(i)); process.exit(0); }
        const rows = [["CIDR", i.cidr], ["Network", i.network]];
        if (i.version === 4) rows.push(["Netmask", i.netmask], ["Wildcard", i.wildcard], ["Broadcast", i.broadcast]);
        rows.push(["First host", i.first], ["Last host", i.lastHost], ["Last address", i.lastAddr], ["Usable hosts", i.usable.text], ["Total", `${i.total.text} (${i.total.pow})`]);
        rows.push(["Type", i.kind.label + (i.kind.rfc ? ` (${i.kind.rfc})` : "")]);
        if (i.version === 4) rows.push(["Class", i.class], ["Binary", i.binary]);
        else rows.push(["Expanded", i.expanded], ["/64 subnets", i.subnets64 ? i.subnets64.text : "n/a"]);
        rows.push(["Reverse DNS", i.reverse.join(", ")]);
        if (i.hostNote) rows.push(["Note", i.hostNote]);
        for (const [k, v] of rows) out(pad(k) + v);
    } else if (cmd === "split") {
        const n = P(rest[0]);
        const newP = into !== null ? E.prefixForCount(n, into).newP : Number(rest[1]);
        const r = E.split(n, newP, 65536);
        if (json) { out(J({ total: r.total, subnets: r.subnets.map(E.str) })); process.exit(0); }
        for (const s of r.subnets) out(E.str(s));
        if (r.truncated) process.stderr.write(`... ${r.total} subnets in all; showing the first ${r.subnets.length}\n`);
    } else if (cmd === "vlsm") {
        const reqs = rest.slice(1).map((a) => { const [name, h] = a.split("="); return { name, hosts: Number(h) }; });
        const r = E.vlsm(P(rest[0]), reqs, { ptp31: flags.has("--ptp31") });
        if (json) { out(J(r)); process.exit(r.unplaced.length ? 1 : 0); }
        out("NAME".padEnd(14) + "NEED".padStart(7) + "  BLOCK".padEnd(22) + "USABLE".padStart(8) + "  RANGE");
        for (const x of r.placed) { const hr = E.hostRange(x.net); out(x.name.padEnd(14) + String(x.hosts).padStart(7) + ("  " + E.str(x.net)).padEnd(22) + String(x.usable).padStart(8) + `  ${E.fmt(4, hr.first)} - ${E.fmt(4, hr.last)}`); }
        for (const x of r.unplaced) out(`${x.name.padEnd(14)}${String(x.hosts).padStart(7)}  NOT PLACED: ${x.reason}`);
        out(`\nfree: ${r.free.length ? r.free.map(E.str).join(", ") : "none"}`);
        process.exit(r.unplaced.length ? 1 : 0);
    } else if (cmd === "agg") {
        const nets = E.aggregate(await listFrom(rest));
        if (json) out(J(nets.map(E.str))); else for (const n of nets) out(E.str(n));
    } else if (cmd === "range") {
        const a = E.parseAddress(rest[0]), b = E.parseAddress(rest[1]);
        if (a.v !== b.v) throw new E.CidrError("a range cannot mix IPv4 and IPv6");
        const l = E.rangeToCidrs(a.v, a.x, b.x);
        if (json) out(J(l.map(E.str))); else for (const n of l) out(E.str(n));
    } else if (cmd === "exclude") {
        const l = E.exclude(P(rest[0]), P(rest[1]));
        if (json) out(J(l.map(E.str))); else if (l.length) for (const n of l) out(E.str(n)); else out("(nothing left)");
    } else if (cmd === "contains") {
        const a = P(rest[0]), b = P(rest[1]); const r = E.relation(a, b);
        const yes = r === "contains" || r === "equal";
        if (json) out(J({ contains: yes, relation: r })); else out(yes ? "yes" : `no (${r})`);
        process.exit(yes ? 0 : 1);
    } else if (cmd === "overlap") {
        const o = E.overlaps(await listFrom(rest));
        if (json) out(J(o.map((x) => ({ a: E.str(x.a), b: E.str(x.b), kind: x.kind }))));
        else if (!o.length) out("no overlaps");
        else for (const x of o) out(`${E.str(x.a)}  ${x.kind}  ${E.str(x.b)}`);
        process.exit(o.length ? 1 : 0);
    } else { process.stderr.write(`unknown command "${cmd}"\n\n${HELP}\n`); process.exit(2); }
} catch (e) {
    if (e instanceof E.CidrError) { process.stderr.write("error: " + e.message + "\n"); process.exit(2); }
    throw e;
}
