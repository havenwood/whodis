# whodis

mDNS / Bonjour recon and spoof, in Rust. macOS first.

```
whodis browse --fingerprint
whodis sweep 10.0.5.0/24
whodis capture --pcap snap.pcap -t 60
whodis probe
whodis enum OfficePrinter.local.
whodis spoof --template airplay --name ConferenceSpeaker --ip 10.0.5.42 --relay 10.0.5.20:7000
whodis flood conflict ConferenceSpeaker._airplay._tcp.local. --forever
whodis report --out engagement.md
```

## Install

```sh
cargo install --path .
```

## Subcommands

| Command | What |
|---|---|
| `browse`  | Stream every mDNS event from the LAN |
| `probe`   | Directed query, or service-type list with no args |
| `enum`    | Per-host service deep dive, or host list with no args |
| `arp`     | Read ARP/NDP caches with OUI vendor lookup |
| `sweep`   | Active ICMP host discovery, no root required |
| `capture` | Dump mDNS to a pcap file |
| `spoof`   | Authoritative responder, optionally with a TCP relay |
| `clone`   | Capture a real instance to a TOML answer table |
| `flood`   | Goodbye and conflict-rename floods |
| `report`  | Markdown engagement report |

## Browse

```
whodis browse
whodis browse --pretty --fingerprint
whodis browse --once
whodis browse -t 30
whodis browse --type _airplay._tcp.local.
```

`--once` is a 5-second snapshot. `--type FQDN` is case- and trailing-dot-insensitive.

## Probe

```
whodis probe                                          # service types + counts
whodis probe _airplay._tcp.local.                     # all AirPlay receivers
whodis probe _ipp._tcp.local. -t 5                    # printers, 5s window
whodis probe _airplay._tcp.local. --instance "Living" # one specific instance
whodis probe --host OfficePrinter.local               # resolve a hostname
```

## Enum

Pick one host, list every service it advertises. With no host, lists hosts on the LAN with the count of distinct service types each one advertises.

```
whodis enum
whodis enum OfficePrinter.local.
whodis enum 192-168-50-179.local. -t 8
```

## Arp

Read the kernel's ARP and NDP neighbor caches. No packets sent. Cache only contains hosts your Mac has recently talked to, so a fresh cache after reboot may be sparse.

```
whodis arp
whodis arp --v4
whodis arp --v6
whodis arp --vendor "Apple"
whodis arp --no-oui
```

`--vendor` is a case-insensitive substring match. `-i NAME` filters to a specific interface. `--scope FILE` applies `allow_subnet` to limit entries to the engagement subnet.

## Sweep

Active IPv4 host discovery via ICMP echo. Uses `SOCK_DGRAM + IPPROTO_ICMP`, which macOS allows unprivileged - no sudo required. After probing, the kernel's ARP cache is freshly populated; whodis reads it once to enrich live hosts with MAC and OUI vendor.

```
whodis sweep 192.168.1.0/24
whodis sweep 192.168.1.0/24 -t 500          # per-probe timeout in ms (default 500)
whodis sweep 192.168.1.0/24 --max 64        # cap concurrent probes (default 256)
whodis sweep 192.168.1.0/24 --max 0         # unbounded concurrency (watch fd limits)
whodis sweep 192.168.1.0/24 --no-arp        # skip MAC/vendor enrichment
whodis sweep 192.168.1.0/24 --no-oui        # keep MAC, skip OUI vendor lookup
whodis sweep 192.168.1.0/24 --show-dead     # also emit unreachable hosts
```

Default `--max 256` guards against file descriptor exhaustion (macOS default `ulimit -n` is 256). IPv4 only in v1. Output is one record per host (`ip`, `alive`, `rtt_ms`, `mac`, `vendor`, `interface`); dead hosts omitted unless `--show-dead`. `--scope FILE` applies `allow_subnet` to skip IPs outside the engagement range.

## Capture

LINKTYPE_RAW pcap with synthesized IPv4 / UDP wrappers. Wireshark and tshark read it directly. Default runs until Ctrl-C; `-t SECS` bounds the window.

```
whodis capture --pcap engagement.pcap
whodis capture --pcap engagement.pcap -t 60
tshark -r engagement.pcap
```

## Spoof

Pick a template or hand-write a TOML answer table.

```
whodis spoof --template airplay --name ConferenceSpeaker --ip 10.0.5.42
whodis spoof answers.toml --burst 3 --allow 10.0.5.0/24
```

Templates: `airplay`, `raop`, `ipp`, `smb`, `ssh`, `googlecast`. Each generates the matching `PTR` / `SRV` / `TXT` / `A` records for the instance.

`--relay HOST:PORT` adds a TCP bridge: whodis listens on every port the spoof advertises and forwards connections to the real device. Combine with `flood conflict` for discovery plus traffic MITM.

`--reannounce-interval SECS` periodically multicasts our records to evict cached entries from the legit device. `0` is reply-only (default). Try 30 for steady churn, 5 for aggressive cache-poisoning.

```sh
whodis spoof --template airplay --name ConferenceSpeaker --ip 10.0.5.42 \
    --allow 10.0.5.0/24 \
    --relay 10.0.5.20:7000
```

Manual answer table (`answers.toml`):

```toml
ttl = 120

[[answer]]
name = "_airplay._tcp.local."
qtype = "PTR"
data = "Spoofed-Speaker._airplay._tcp.local."

[[answer]]
name = "Spoofed-Speaker._airplay._tcp.local."
qtype = "SRV"
port = 7000
target = "Spoofed-Speaker.local."

[[answer]]
name = "Spoofed-Speaker._airplay._tcp.local."
qtype = "TXT"
txt = ["model=AppleTV11,1", "deviceid=AA:BB:CC:DD:EE:FF"]

[[answer]]
name = "Spoofed-Speaker.local."
qtype = "A"
data = "10.0.5.42"
```

Supported qtypes: `A`, `AAAA`, `PTR`, `SRV`, `TXT`. `PTR` responses bundle related `SRV` / `TXT` / `A` / `AAAA` as additionals so one query fully hydrates the instance.

The responder logs `spoof conflict` at warn level when something else on the LAN claims a name we own.

## Clone

Capture an instance on the LAN and emit a TOML answer table mimicking its `PTR` / `SRV` / `TXT` / `A` / `AAAA` records. Replays through `whodis spoof`; pair with `--relay` to MITM the real device.

```sh
whodis clone "Conference Speaker._airplay._tcp.local." > clone.toml
whodis spoof clone.toml --relay 10.0.5.20:7000 --allow 10.0.5.0/24
```

`-t SECS` (default 5) bounds the listen window. Exits non-zero if no records arrive in time.

## Flood

Disruptive.

- `goodbye` sends TTL=0 records, forces neighbors to re-announce. Useful for harvesting fresh `TXT`.
- `conflict` sends authoritative records claiming the target's name with different content. Per RFC 6762 §9 the legit device renames itself.

```
whodis flood goodbye Foo._airplay._tcp.local.
whodis flood goodbye Foo._airplay._tcp.local. --count 50
whodis flood goodbye Foo._airplay._tcp.local. --forever
whodis flood conflict Foo._airplay._tcp.local. --allow-instance Foo
whodis flood goodbye Foo._airplay._tcp.local. --dry-run
```

`--rate N` caps packets per second (default 50, minimum 1). `--count N` is per-target (default 1, minimum 1). `--forever` runs until Ctrl-C and conflicts with `--count`. `--dry-run` logs what would be sent. A mismatched allow-list logs the blocked target and exits non-zero.

## Report

Brief inventory pass plus a Markdown summary (service types, instance inventory with fingerprints, TXT highlights, timestamps).

```
whodis report --out engagement.md
whodis report -t 30 --out lan-snapshot.md
WHODIS_SCOPE=engagement.toml whodis report
```

Setting `WHODIS_SCOPE` writes the report into the scope's `log_dir` if one is configured. Pair with `whodis capture --pcap` for raw packet evidence.

## Modes

| Mode | When | Binds 5353 |
|---|---|---|
| QueryOnly     | `probe`, `enum`                 | no |
| Listen        | `browse`, `capture`, `report`   | yes (REUSEPORT) |
| Authoritative | `spoof`, `flood`                | yes (REUSEPORT) |

`SO_REUSEPORT` lets us coexist with macOS `mDNSResponder`. If 5353 won't bind, the error points at firewall or sudo. No silent fallback.

## Interface selection

`-i NAME` (`--interface`) restricts operations to a specific interface, e.g. `en0`. Repeatable. Default: all non-loopback interfaces. Useful on laptops with VPN tunnels you don't want to leak mDNS into.

## Shell completions

```sh
whodis completions zsh > "${fpath[1]}/_whodis"
whodis completions bash > /usr/local/etc/bash_completion.d/whodis
whodis completions fish > ~/.config/fish/completions/whodis.fish
```

Supported shells: `bash`, `elvish`, `fish`, `powershell`, `zsh`.

## Output

JSONL on stdout by default. `--pretty` switches to human view (auto on a TTY). `--color auto|always|never` respects `NO_COLOR`. Logs go to stderr.

## Authorization

`spoof` accepts `--allow CIDR` and `--allow-instance NAME`. `flood` accepts `--allow-instance NAME` only (it multicasts, no per-target IP). Both are repeatable. An empty allow-list emits one warning and proceeds. A mismatched allow-list logs the blocked target and exits non-zero.

`sweep` and `arp` honor a scope file's `allow_subnet`: `sweep` intersects the requested CIDR with the allow-list (probing only inside it), `arp` filters cache entries to addresses inside it. Without a scope, `sweep` warns once before probing.

Declare engagement scope once and reuse:

```toml
# whodis-scope.toml
allow_subnet   = ["10.0.5.0/24"]
allow_instance = ["ConferenceSpeaker"]
log_dir        = "./engagement-logs"
```

```sh
whodis --scope whodis-scope.toml spoof airplay.toml
WHODIS_SCOPE=whodis-scope.toml whodis flood conflict ConferenceSpeaker._airplay._tcp.local. --forever
```

CLI `--allow` flags stack on top of the scope file's lists.

## Engagement workflow

Set scope, capture in the background, spoof + flood the target, watch the LAN, then write up:

```sh
mkdir -p engagement-logs
export WHODIS_SCOPE=whodis-scope.toml

whodis sweep 10.0.5.0/24 > engagement-logs/hosts.jsonl

whodis capture --pcap engagement-logs/mdns.pcap &
whodis spoof --template airplay --name ConferenceSpeaker --ip 10.0.5.50 \
    --relay 10.0.5.20:7000 &
whodis flood conflict ConferenceSpeaker._airplay._tcp.local. --forever --rate 20 &

whodis browse --pretty --fingerprint
```

When done:

```sh
kill %1 %2 %3
whodis report --out engagement-logs/report.md
```

`engagement-logs/` ends up with the pcap, the report, and any redirected stderr.
