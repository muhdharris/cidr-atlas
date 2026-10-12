# CIDR Atlas

An IPv4 and IPv6 subnet calculator that shows the bits. It runs in the browser
with nothing sent anywhere, and as a command line tool on the same engine.

**Live:** https://muhdharris.github.io/cidr-atlas/

## What it does

**Inspect.** Type an address with a prefix, a netmask, a Cisco wildcard, or just
an address. You get the network, broadcast, first and last host, usable count,
reverse DNS zones, and what the block is (private, shared, documentation,
multicast and so on, with the RFC). A strip of bit boxes shows which bits are
network and which are host; click or drag it, use the slider, or press the
up and down arrows in the box to change the prefix. Buttons step to the
previous or next block, the supernet, or either half.

**Split.** Cut a block into equal subnets by prefix or by count, with CSV export.

**VLSM plan.** List what each subnet needs ("Staff=100"). It places the largest
first, aligned, shows the allocation as a bar, lists what is still free, and
exports CSV. Optional /31 for two-host links.

**Lists.** Paste networks, ranges ("10.0.0.1 - 10.0.0.9") or addresses. It merges
them into the fewest blocks, reports overlaps, gives the one block that covers
everything and how much extra that covers, and can cut a block out of the lot.

**Config snippets.** For any block: Cisco IOS, Huawei VRP, MikroTik and Linux,
with the block's own address, mask or wildcard filled in.

Every result is in the address bar, so a link shares it. IPv6 is exact to 128
bits (BigInt), formatted to RFC 5952.

## Command line

```
node bin/cidr.js info 10.20.30.40/22
node bin/cidr.js split 10.0.0.0/24 26          # or: --into 5
node bin/cidr.js vlsm 192.168.10.0/24 Staff=100 Guests=50 Link=2
node bin/cidr.js agg 10.0.0.0/25 10.0.0.128/25 # reads stdin with no arguments
node bin/cidr.js range 10.0.0.1 10.0.0.6
node bin/cidr.js exclude 10.0.0.0/24 10.0.0.64/26
node bin/cidr.js contains 10.0.0.0/8 10.5.5.5   # exit 0 if inside
node bin/cidr.js overlap < blocks.txt           # exit 1 if any overlap
```

Add `--json` for machine-readable output. Exit codes are 0 for success, 1 for a
negative answer (not inside, overlaps found, could not place a subnet) and 2 for bad input.

## Layout

```
src/engine.js   the maths: parsing, formatting, split, VLSM, aggregation, subtraction
src/app.js      the interface
bin/cidr.js     the command line
test/           unit tests, and a differential test against Python's ipaddress
tools/          generates the reference data for that test
```

No build step and no dependencies. Serve the folder as it is, or open
`index.html` through any static server (ES modules do not load from `file://`).

## Tests

```
npm test
```

Besides the unit tests, the engine is checked against Python's `ipaddress`
module on 1,050 seeded random cases: network and mask maths, splitting,
aggregation, subtraction and range conversion. `python3 tools/gen_reference.py >
test/reference.json` regenerates the reference.

## Limitations

- The VLSM planner is IPv4 only. In IPv6 every LAN is a /64, so Split covers it.
- The config snippets are starting points. The interface name, OSPF area and next hop are examples.
- The "what is this block" table is a fixed list of the IANA special-purpose ranges, not a live lookup. There is no whois or geolocation.
- Classful A, B and C are shown for IPv4 because people still ask for them; routing has not used them since CIDR.
- Tested in Chromium. Safari and Firefox have not been tried.

MIT licence.
