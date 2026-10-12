// CIDR Atlas interface. Everything is computed in the browser by engine.js; nothing is sent anywhere.
import * as E from "./engine.js";

const $ = (s, r = document) => r.querySelector(s);
const h = (tag, props = {}, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
        if (v === false || v == null) continue;
        if (k === "class") el.className = v;
        else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
        else if (k === "text") el.textContent = v;
        else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(kid));
    return el;
};
const clear = (el) => { el.replaceChildren(); return el; };

/* ---------- small shared pieces ---------- */

function copyText(text, btn) {
    const done = () => { const t = btn.textContent; btn.textContent = "copied"; btn.classList.add("ok"); setTimeout(() => { btn.textContent = t; btn.classList.remove("ok"); }, 1100); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
    else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
    const ta = h("textarea", { class: "offscreen", "aria-hidden": "true" }); ta.value = text; document.body.append(ta); ta.select();
    try { document.execCommand("copy"); done(); } finally { ta.remove(); }
}
const copyBtn = (get, label = "copy") => { const b = h("button", { type: "button", class: "copy", "aria-label": "Copy to clipboard" }, label); b.addEventListener("click", () => copyText(typeof get === "function" ? get() : get, b)); return b; };

function download(name, text, type = "text/plain") {
    const a = h("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

const errBox = () => h("p", { class: "err", role: "alert", hidden: true });
function showErr(box, e) {
    if (!e) { box.hidden = true; box.textContent = ""; return; }
    box.hidden = false; box.textContent = e instanceof E.CidrError ? e.message : "Something went wrong with that input.";
    if (!(e instanceof E.CidrError)) console.error(e);
}

function fact(label, value, { copy = true, mono = true, note } = {}) {
    return h("div", { class: "fact" },
        h("dt", {}, label),
        h("dd", {}, h("span", { class: mono ? "mono" : "" }, value), note ? h("small", {}, note) : null, copy ? copyBtn(String(value)) : null));
}

const SCOPE_CLASS = { private: "s-priv", public: "s-pub", loopback: "s-lo", "link-local": "s-lo", multicast: "s-mc", documentation: "s-doc", shared: "s-priv", reserved: "s-res", mixed: "s-res", benchmark: "s-res", broadcast: "s-res" };

/* ---------- state kept in the address bar so any result can be shared ---------- */

const state = { tab: "inspect", q: "10.20.30.40/22", s_q: "10.0.0.0/24", s_n: "26", v_q: "192.168.10.0/24", v_rows: "Staff=100\nGuests=50\nServers=25\nLink=2", l: "10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24\n10.0.3.0/24\n10.0.2.128/25\n192.168.1.1 - 192.168.1.9" };
(function readHash() {
    const p = new URLSearchParams(location.hash.slice(1));
    for (const k of Object.keys(state)) if (p.has(k)) state[k] = p.get(k);
})();
let hashTimer;
function saveHash() {
    clearTimeout(hashTimer);
    hashTimer = setTimeout(() => history.replaceState(null, "", "#" + new URLSearchParams(state).toString()), 250);
}

/* ---------- the bit strip: network bits filled, host bits open; click or drag to set the prefix ---------- */

function bitStrip(net, onPrefix) {
    const bits = E.BITS[net.v], per = net.v === 4 ? 8 : 16;
    const wrap = h("div", { class: "strip", "data-v": net.v });
    const row = h("div", { class: "bits", role: "presentation" });
    const bin = net.a.toString(2).padStart(bits, "0");
    for (let g = 0; g < bits / per; g++) {
        const grp = h("span", { class: "grp" });
        for (let i = 0; i < per; i++) {
            const idx = g * per + i;
            grp.append(h("i", { class: idx < net.p ? "n" : "hst", "data-i": idx, text: bin[idx] }));
        }
        grp.append(h("b", { class: "lbl", text: net.v === 4 ? String(Number(BigInt("0b" + bin.slice(g * 8, g * 8 + 8)))) : BigInt("0b" + bin.slice(g * 16, g * 16 + 16)).toString(16) }));
        row.append(grp);
    }
    const slider = h("input", { type: "range", min: 0, max: bits, value: net.p, "aria-label": "Prefix length", class: "pslider" });
    slider.addEventListener("input", () => onPrefix(Number(slider.value)));
    let drag = false;
    const at = (e) => { const t = document.elementFromPoint(e.clientX, e.clientY); const i = t && t.dataset && t.dataset.i; if (i !== undefined) onPrefix(Number(i) + 1); };
    row.addEventListener("pointerdown", (e) => { drag = true; row.setPointerCapture(e.pointerId); at(e); });
    row.addEventListener("pointermove", (e) => { if (drag) at(e); });
    row.addEventListener("pointerup", () => { drag = false; });
    wrap.append(
        h("div", { class: "strip-head" }, h("span", {}, h("i", { class: "key n" }), " network ", h("b", { class: "mono", text: net.p }), " bits"), h("span", {}, h("i", { class: "key hst" }), " host ", h("b", { class: "mono", text: bits - net.p }), " bits")),
        row, slider);
    return wrap;
}

/* ---------- Inspect ---------- */

function inspectPanel() {
    const root = h("section", { class: "panel", id: "p-inspect", role: "tabpanel" });
    const input = h("input", { id: "q", type: "text", inputmode: "text", spellcheck: "false", autocomplete: "off", autocapitalize: "off", "aria-label": "IP address and prefix", placeholder: "10.20.30.40/22   or   192.168.1.0 255.255.255.0   or   2001:db8::/48", value: state.q });
    const err = errBox();
    const out = h("div", { class: "out" });
    const chips = ["10.20.30.40/22", "192.168.1.0 255.255.255.0", "172.16.0.0 0.0.15.255", "100.64.0.0/10", "2001:db8:abcd::/48", "fe80::1/64"].map((c) => h("button", { type: "button", class: "chip", onclick: () => { input.value = c; run(); input.focus(); } }, c));
    root.append(h("label", { for: "q", class: "ask" }, "Address and prefix, mask or wildcard"), h("div", { class: "box" }, input), err, h("div", { class: "chips" }, h("span", {}, "try"), chips), out);

    let snipIdx = 0, hop = "";
    function setNet(n) { input.value = E.str(n); run(); }
    function run() {
        state.q = input.value; saveHash();
        clear(out);
        let p;
        try { p = E.parse(input.value); showErr(err, null); } catch (e) { showErr(err, input.value.trim() ? e : null); return; }
        const net = p.net, i = E.info(net, p.ip), par = E.parent(net), prev = E.neighbour(net, -1), next = E.neighbour(net, 1);

        out.append(h("div", { class: "hero" },
            h("div", { class: "cidr mono" }, i.cidr, copyBtn(i.cidr)),
            h("span", { class: "badge " + (SCOPE_CLASS[i.kind.scope] || "") }, i.kind.label, i.kind.rfc ? h("small", {}, " " + i.kind.rfc) : null),
            h("p", { class: "sub" }, `${i.total.text} addresses`, i.total.pow !== "1" ? ` (${i.total.pow})` : "", i.hostNote ? " · " + i.hostNote : "")));
        if (i.kind.spans && i.kind.spans.length) out.append(h("p", { class: "note" }, "This block runs across: ", i.kind.spans.map((s) => `${s.net} ${s.label}`).join("; "), "."));

        out.append(bitStrip(net, (pp) => setNet(E.mk(net.v, p.ip, pp))));

        const nav = h("div", { class: "nav" },
            h("button", { type: "button", disabled: !prev, onclick: () => prev && setNet(prev), title: "Previous block of the same size ( [ )" }, "◀ previous"),
            h("button", { type: "button", disabled: !par, onclick: () => par && setNet(par), title: "The block one bit wider" }, "▲ supernet /" + (net.p - 1)),
            h("button", { type: "button", disabled: net.p >= E.BITS[net.v], onclick: () => setNet(E.mk(net.v, net.a, net.p + 1)), title: "The lower half" }, "▼ lower half"),
            h("button", { type: "button", disabled: net.p >= E.BITS[net.v], onclick: () => setNet(E.mk(net.v, net.a + E.size(net) / 2n, net.p + 1)), title: "The upper half" }, "▼ upper half"),
            h("button", { type: "button", disabled: !next, onclick: () => next && setNet(next), title: "Next block of the same size ( ] )" }, "next ▶"));
        out.append(nav);

        if (p.ip !== net.a && net.p < E.BITS[net.v]) out.append(h("p", { class: "note" }, h("span", { class: "mono" }, i.typed), ` is host number ${i.hostIndex.toString()} in this block; the network address is `, h("span", { class: "mono" }, i.network), "."));

        const dl = h("dl", { class: "facts" });
        dl.append(fact("Network address", i.network));
        if (i.version === 4) dl.append(fact("Netmask", i.netmask), fact("Wildcard", i.wildcard), fact("Broadcast", i.broadcast, { copy: net.p < 31 }));
        dl.append(fact("First usable", i.first), fact("Last usable", i.lastHost), fact("Last address", i.lastAddr));
        dl.append(fact("Usable hosts", i.usable.text, { note: i.usable.n >= 10n ** 12n ? i.usable.pow : "" }), fact("Total addresses", i.total.text, { note: i.total.pow }));
        if (i.version === 4) dl.append(fact("Binary", i.binary, { mono: true }), fact("Class", i.class, { copy: false, mono: false }));
        else { dl.append(fact("Expanded", i.expanded), fact("Last, expanded", i.lastExpanded)); if (i.subnets64) dl.append(fact("/64 subnets inside", i.subnets64.text, { note: i.subnets64.pow })); if (i.mapped) dl.append(fact("Mapped IPv4", i.mapped)); }
        dl.append(fact("Reverse DNS", i.reverse.join("\n"), { note: i.reverse.length > 1 ? `${i.reverse.length} zones` : "" }));
        out.append(dl);

        const snips = E.snippets(net, p.ip !== net.a ? p.ip : undefined);
        const pre = h("pre", { class: "mono", tabindex: "0" });
        const tabs = h("div", { class: "stabs", role: "group", "aria-label": "Device" });
        const draw = () => { pre.textContent = snips[snipIdx].text; [...tabs.children].forEach((b, k) => b.setAttribute("aria-pressed", String(k === snipIdx))); };
        snips.forEach((s, k) => tabs.append(h("button", { type: "button", onclick: () => { snipIdx = k; draw(); } }, s.name)));
        draw();
        out.append(h("div", { class: "snip" }, h("div", { class: "snip-head" }, h("h3", {}, "Config for this block"), tabs, copyBtn(() => snips[snipIdx].text)), pre, h("p", { class: "note" }, "Starting points with the block's own values filled in. The interface name, area and next hop are examples; check them before you paste.")));
    }
    input.addEventListener("input", run);
    input.addEventListener("keydown", (e) => {                         // arrow keys nudge the prefix
        if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
        try { const p = E.parse(input.value); const np = p.p + (e.key === "ArrowUp" ? 1 : -1); if (np >= 0 && np <= E.BITS[p.v]) { e.preventDefault(); input.value = `${E.fmt(p.v, p.ip)}/${np}`; run(); } } catch { /* leave the text alone */ }
    });
    root.addEventListener("keydown", (e) => { if (e.target === input) return; if (e.key === "[" ) $(".nav button:first-child", root)?.click(); if (e.key === "]") $(".nav button:last-child", root)?.click(); });
    root.run = run; root.focus = () => input.focus();
    return root;
}

/* ---------- Split ---------- */

function splitPanel() {
    const root = h("section", { class: "panel", id: "p-split", role: "tabpanel", hidden: true });
    const q = h("input", { type: "text", spellcheck: "false", autocomplete: "off", "aria-label": "Block to split", value: state.s_q });
    const mode = h("select", { "aria-label": "How to split" }, h("option", { value: "prefix" }, "into /prefix"), h("option", { value: "count" }, "into N subnets"));
    const n = h("input", { type: "number", min: 0, max: 128, "aria-label": "New prefix or number of subnets", value: state.s_n, class: "num" });
    const err = errBox(), out = h("div", { class: "out" });
    root.append(h("label", { class: "ask" }, "Block to cut up"), h("div", { class: "row" }, h("div", { class: "box grow" }, q), mode, n), err, out);
    function run() {
        state.s_q = q.value; state.s_n = n.value; saveHash(); clear(out);
        try {
            const net = E.parse(q.value).net;
            let newP = Number(n.value);
            let note = "";
            if (mode.value === "count") { const r = E.prefixForCount(net, Number(n.value)); newP = r.newP; if (!r.exact) note = `CIDR blocks halve, so ${n.value} rounds up to ${r.got} subnets of /${newP}.`; }
            const r = E.split(net, newP, 4096);
            showErr(err, null);
            const per = E.hostRange({ v: net.v, a: 0n, p: newP });
            out.append(h("p", { class: "sub" }, `${E.count(r.total).text} subnets of /${newP}, each with ${E.count(per.usable).text} usable address${per.usable === 1n ? "" : "es"}.`, note ? " " + note : ""));
            const all = () => r.subnets.map(E.str).join("\n");
            out.append(h("div", { class: "row tools" }, copyBtn(all, "copy list"), h("button", { type: "button", onclick: () => download("subnets.csv", "subnet,first,last,usable\n" + E.split(net, newP, 65536).subnets.map((s) => { const x = E.hostRange(s); return [E.str(s), E.fmt(s.v, x.first), E.fmt(s.v, x.last), x.usable].join(","); }).join("\n"), "text/csv") }, "download CSV"), r.truncated ? h("span", { class: "note" }, `showing the first ${r.subnets.length}; the CSV holds up to 65,536`) : null));
            const tb = h("tbody");
            r.subnets.forEach((s, i) => { const x = E.hostRange(s); tb.append(h("tr", {}, h("td", { class: "mono dim" }, i + 1), h("td", { class: "mono" }, h("a", { href: "#", onclick: (e) => { e.preventDefault(); state.q = E.str(s); go("inspect"); } }, E.str(s))), h("td", { class: "mono" }, E.fmt(s.v, x.first), " – ", E.fmt(s.v, x.last)), h("td", { class: "mono r" }, E.count(x.usable).text))); });
            out.append(h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "Subnet"), h("th", {}, "Usable range"), h("th", { class: "r" }, "Usable"))), tb)));
        } catch (e) { showErr(err, e); }
    }
    [q, mode, n].forEach((el) => el.addEventListener("input", run));
    root.run = run; root.focus = () => q.focus();
    return root;
}

/* ---------- VLSM plan ---------- */

function vlsmPanel() {
    const root = h("section", { class: "panel", id: "p-vlsm", role: "tabpanel", hidden: true });
    const q = h("input", { type: "text", spellcheck: "false", autocomplete: "off", "aria-label": "Parent block", value: state.v_q });
    const rows = h("textarea", { rows: 6, spellcheck: "false", "aria-label": "Subnets, one per line as name=hosts", class: "mono" }); rows.value = state.v_rows;
    const ptp = h("input", { type: "checkbox", id: "ptp" });
    const err = errBox(), out = h("div", { class: "out" });
    root.append(h("label", { class: "ask" }, "Parent block"), h("div", { class: "box" }, q),
        h("label", { class: "ask", for: "vrows" }, "What each subnet needs, one per line:  name=hosts"), rows,
        h("label", { class: "check", for: "ptp" }, ptp, " use /31 for two-host links (RFC 3021)"), err, out);
    rows.id = "vrows";
    function run() {
        state.v_q = q.value; state.v_rows = rows.value; saveHash(); clear(out);
        try {
            const reqs = rows.value.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l, i) => {
                const m = l.match(/^(.*?)\s*[=:]\s*(\d+)$/) || l.match(/^(.*\S)\s+(\d+)$/);
                if (!m) throw new E.CidrError(`line ${i + 1} ("${l}") should look like  Staff=100`);
                return { name: m[1] || `net${i + 1}`, hosts: Number(m[2]) };
            });
            if (!reqs.length) throw new E.CidrError("add at least one subnet, for example  Staff=100");
            const r = E.vlsm(E.parse(q.value).net, reqs, { ptp31: ptp.checked });
            showErr(err, null);
            const colors = ["#b02f14", "#3d5a80", "#5b7a3a", "#8a5a14", "#6b4a8a", "#2f6f73", "#8a3a5a", "#555"];
            const bar = h("div", { class: "alloc", role: "img", "aria-label": "How the parent block is divided" });
            const total = Number(r.total > 2n ** 52n ? 2n ** 52n : r.total);
            const seg = (cls, sz, label, color, title) => bar.append(h("span", { class: cls, style: `flex:${Math.max(Number(sz) / total, 0.0006)};${color ? "background:" + color : ""}`, title }, Number(sz) / total > 0.07 ? label : ""));
            const placed = [...r.placed];
            const parts = [...placed.map((x, k) => ({ a: x.net.a, sz: x.sz, label: x.name, c: colors[k % colors.length], t: `${x.name}: ${E.str(x.net)}` })), ...r.free.map((f) => ({ a: f.a, sz: E.size(f), label: "free", c: null, t: `free: ${E.str(f)}` }))].sort((x, y) => (x.a < y.a ? -1 : 1));
            parts.forEach((x) => seg(x.c ? "seg" : "seg free", x.sz, x.label, x.c, x.t));
            out.append(h("p", { class: "sub" }, `${E.str(r.parent)}: ${E.count(r.used).text} of ${E.count(r.total).text} addresses allocated (${Number((r.used * 1000n) / r.total) / 10}%). Asked for ${E.count(r.wanted).text} hosts and got ${E.count(r.usableSum).text} usable.`), bar);
            const tb = h("tbody");
            placed.forEach((x, k) => { const hr = E.hostRange(x.net); tb.append(h("tr", {}, h("td", {}, h("i", { class: "sw", style: "background:" + colors[k % colors.length] }), x.name), h("td", { class: "mono r" }, x.hosts), h("td", { class: "mono" }, E.str(x.net)), h("td", { class: "mono" }, E.fmtV4(hr.first), " – ", E.fmtV4(hr.last)), h("td", { class: "mono r" }, x.usable.toString()), h("td", { class: "mono r dim" }, "+" + x.spare.toString()))); });
            out.append(h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", { class: "r" }, "Needs"), h("th", {}, "Block"), h("th", {}, "Usable range"), h("th", { class: "r" }, "Usable"), h("th", { class: "r" }, "Spare"))), tb)));
            r.unplaced.forEach((x) => out.append(h("p", { class: "err" }, `${x.name} (${x.hosts} hosts) could not be placed: ${x.reason}.`)));
            if (r.free.length) out.append(h("p", { class: "note" }, "Still free: ", r.free.map(E.str).join(", "), "."));
            const text = () => placed.map((x) => `${x.name}\t${E.str(x.net)}\t${x.hosts}\t${x.usable}`).join("\n");
            out.append(h("div", { class: "row tools" }, copyBtn(text, "copy plan"), h("button", { type: "button", onclick: () => download("vlsm-plan.csv", "name,block,needs,usable\n" + placed.map((x) => `${x.name},${E.str(x.net)},${x.hosts},${x.usable}`).join("\n"), "text/csv") }, "download CSV")));
        } catch (e) { showErr(err, e); }
    }
    [q, rows, ptp].forEach((el) => el.addEventListener("input", run));
    root.run = run; root.focus = () => q.focus();
    return root;
}

/* ---------- Lists: aggregate, overlaps, enclosing block, subtract ---------- */

function listsPanel() {
    const root = h("section", { class: "panel", id: "p-lists", role: "tabpanel", hidden: true });
    const ta = h("textarea", { rows: 8, spellcheck: "false", class: "mono", id: "ltxt", "aria-label": "Networks, one per line" }); ta.value = state.l;
    const hole = h("input", { type: "text", spellcheck: "false", autocomplete: "off", "aria-label": "Block to remove", placeholder: "optional: a block to cut out of all of the above" });
    const err = errBox(), out = h("div", { class: "out" });
    root.append(h("label", { class: "ask", for: "ltxt" }, "Networks, ranges or addresses, one per line (comments with #)"), ta, h("label", { class: "ask" }, "Remove a block"), h("div", { class: "box" }, hole), err, out);
    function section(title, body, text) { return h("div", { class: "blk" }, h("div", { class: "blk-head" }, h("h3", {}, title), text ? copyBtn(text) : null), body); }
    function run() {
        state.l = ta.value; saveHash(); clear(out);
        const { nets, errors } = E.parseList(ta.value);
        showErr(err, null);
        if (errors.length) out.append(h("div", { class: "err" }, errors.map((e) => h("div", {}, `line ${e.line}: "${e.text}": ${e.message}`))));
        if (!nets.length) return;
        let agg = E.aggregate(nets);
        const ovl = E.overlaps(nets);
        const lines = (l) => l.map(E.str).join("\n");
        out.append(section(`Aggregated: ${nets.length} in, ${agg.length} out`, h("pre", { class: "mono" }, lines(agg)), lines(agg)));
        out.append(section(ovl.length ? `Overlaps: ${ovl.length}` : "Overlaps: none", ovl.length ? h("ul", { class: "ovl" }, ovl.slice(0, 50).map((o) => h("li", { class: "mono" }, `${E.str(o.a)}  ${o.kind === "contains" ? "contains" : o.kind === "within" ? "is inside" : "is the same as"}  ${E.str(o.b)}`))) : h("p", { class: "note" }, "No block in the list overlaps another.")));
        for (const v of [4, 6]) {
            const e = E.enclosing(nets, v); if (!e) continue;
            out.append(section(`One block to cover every IPv${v} entry`, h("p", {}, h("span", { class: "mono big" }, E.str(e.net)), ` covers ${E.count(e.listed).text} listed address${e.listed === 1n ? "" : "es"} and ${E.count(e.extra).text} you did not list.`), E.str(e.net)));
        }
        if (hole.value.trim()) {
            try {
                const x = E.parse(hole.value).net;
                const left = E.aggregate(agg.flatMap((n) => (n.v === x.v ? E.exclude(n, x) : [n])));
                out.append(section(`After removing ${E.str(x)}: ${left.length} block${left.length === 1 ? "" : "s"}`, h("pre", { class: "mono" }, left.length ? lines(left) : "(nothing left)"), lines(left)));
            } catch (e) { out.append(h("p", { class: "err" }, e.message)); }
        }
    }
    [ta, hole].forEach((el) => el.addEventListener("input", run));
    root.run = run; root.focus = () => ta.focus();
    return root;
}

/* ---------- shell ---------- */

const panels = { inspect: inspectPanel(), split: splitPanel(), vlsm: vlsmPanel(), lists: listsPanel() };
const app = $("#app");
Object.values(panels).forEach((p) => app.append(p));
const tabBtns = [...document.querySelectorAll("#tabs button")];
function go(tab, focus = true) {
    if (!panels[tab]) tab = "inspect";
    state.tab = tab;
    tabBtns.forEach((b) => { const on = b.dataset.tab === tab; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; });
    for (const [k, p] of Object.entries(panels)) p.hidden = k !== tab;
    const p = panels[tab];
    if (tab === "inspect") p.querySelector("#q").value = state.q;
    if (tab === "split") { p.querySelector("input[type=text]").value = state.s_q; }
    p.run(); saveHash();
    if (focus) p.focus();
}
tabBtns.forEach((b, i) => {
    b.addEventListener("click", () => go(b.dataset.tab));
    b.addEventListener("keydown", (e) => {
        const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (d) { const n = tabBtns[(i + d + tabBtns.length) % tabBtns.length]; n.focus(); go(n.dataset.tab, false); }
    });
});
document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) { e.preventDefault(); panels[state.tab].focus(); }
});
go(state.tab, false);
