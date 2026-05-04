# whodis

mDNS / Bonjour recon and spoof, in Rust. macOS first.

```
whodis browse --fingerprint
whodis probe                                                  # service types on the LAN
whodis enum BedroomTV.local.                                  # one host, all services
whodis capture --pcap snap.pcap -t 60
whodis spoof --template airplay --name FakeATV --ip 10.0.5.42 --relay 10.0.5.20:7000
whodis flood goodbye Foo._airplay._tcp.local. --forever
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
| `probe`   | Directed query or service-type list with no args |
| `enum`    | Per-host service deep dive |
| `capture` | Dump mDNS to a pcap file |
| `spoof`   | Authoritative responder, optionally with a TCP relay |
| `clone`   | Capture a real instance to a TOML answer table |
| `flood`   | Goodbye and conflict-rename floods |
| `report`  | Markdown engagement report |

## Browse

```
whodis browse                       # JSONL until Ctrl-C
whodis browse --pretty              # human view, color on TTY
whodis browse --fingerprint         # tag instances with vendor / product
whodis browse --once                # 5-second snapshot
whodis browse -t 30                 # auto-exit after 30s
```

## Probe

```
whodis probe                                          # service types + counts
whodis probe _airplay._tcp.local.                     # all AirPlay receivers
whodis probe _ipp._tcp.local. -t 5                    # printers, 5s window
whodis probe _airplay._tcp.local. --instance "Living" # one specific instance
whodis probe --host BedroomTV.local                   # resolve a hostname
```

## Enum

Pick one host, list every service it advertises.

```
whodis enum BedroomTV.local.
whodis enum 192-168-50-179.local. -t 8
```

## Capture

LINKTYPE_RAW pcap with synthesized IPv4 / UDP wrappers. Wireshark and tshark read it directly.

```
whodis capture --pcap engagement.pcap -t 60
whodis capture --pcap engagement.pcap                # until Ctrl-C
tshark -r engagement.pcap
```

## Spoof

Pick a template or hand-write a TOML answer table.

```
whodis spoof --template airplay --name FakeATV --ip 10.0.5.42
whodis spoof answers.toml --burst 3 --allow 10.0.5.0/24
```

Templates: `airplay`, `raop`, `ipp`, `smb`, `ssh`, `googlecast`. Each generates the right `PTR` / `SRV` / `TXT` / `A` records for the named instance.

`--relay HOST:PORT` adds a TCP bridge. whodis listens on every port the spoof advertises and forwards new connections to the real device. Combine with `flood conflict` for full discovery + traffic MITM. Connection events and byte counts log to stderr.

```sh
whodis spoof --template airplay --name FakeATV --ip 10.0.5.42 \
    --allow 10.0.5.0/24 \
    --relay 10.0.5.20:7000
```

Manual answer table (`answers.toml`):

```toml
ttl = 120

[[answer]]
name = "_airplay._tcp.local."
qtype = "PTR"
data = "Spoofed-AppleTV._airplay._tcp.local."

[[answer]]
name = "Spoofed-AppleTV._airplay._tcp.local."
qtype = "SRV"
port = 7000
target = "Spoofed-AppleTV.local."

[[answer]]
name = "Spoofed-AppleTV._airplay._tcp.local."
qtype = "TXT"
txt = ["model=AppleTV11,1", "deviceid=AA:BB:CC:DD:EE:FF"]

[[answer]]
name = "Spoofed-AppleTV.local."
qtype = "A"
data = "10.0.5.42"
```

Supported qtypes: `A`, `AAAA`, `PTR`, `SRV`, `TXT`. `PTR` responses bundle related `SRV` / `TXT` / `A` / `AAAA` as additionals so one client query fully hydrates the instance.

## Clone

Capture an instance that is actually on the LAN and emit a TOML answer table that mimics its PTR / SRV / TXT / A / AAAA records. The output replays through `whodis spoof` for engagement-grade impersonation. Pair with `--relay` to MITM the real device.

```sh
whodis clone "Living Room AppleTV._airplay._tcp.local." > clone.toml
whodis spoof clone.toml --relay 10.0.5.20:7000 --allow 10.0.5.0/24
```

`-t SECS` (default 5) bounds the listen window. Exits non-zero if no records arrive in the window.

## Flood

Disruptive.

- `goodbye` sends TTL=0 records, forces neighbors to re-announce. Good for harvesting fresh `TXT`.
- `conflict` sends authoritative records claiming the target's name with different content. Per RFC 6762 §9 the legit device renames itself.

```
whodis flood goodbye Foo._airplay._tcp.local.
whodis flood goodbye Foo._airplay._tcp.local. --count 50
whodis flood goodbye Foo._airplay._tcp.local. --forever
whodis flood conflict Foo._airplay._tcp.local. --allow-instance Foo
whodis flood goodbye Foo._airplay._tcp.local. --dry-run    # show what would be sent
```

`--rate N` caps packets per second (default 50, minimum 1). `--count N` is per-target (default 1, minimum 1). `--forever` runs until Ctrl-C and conflicts with `--count`. `--dry-run` logs what would be sent without actually sending any packets. A mismatched allow-list logs a warn and exits non-zero.

## Capture

Listen on 5353 and write every received mDNS packet to a pcap file. Output is LINKTYPE_RAW (synthesized IPv4/IPv6 + UDP wrappers) so Wireshark and tshark open it directly.

```sh
whodis capture --pcap engagement.pcap -t 60     # 60s window
whodis capture --pcap engagement.pcap           # until Ctrl-C
tshark -r engagement.pcap                        # inspect
```

## Report

Brief inventory pass, Markdown summary (service types, instance inventory with fingerprints, TXT highlights, timestamps).

```
whodis report --out engagement.md
whodis report -t 30 --out lan-snapshot.md
WHODIS_SCOPE=engagement.toml whodis report          # writes into scope log_dir if set
```

Pair with `whodis capture --pcap` for raw packet evidence alongside the narrative.

## Modes

| Mode | When | Binds 5353 |
|---|---|---|
| QueryOnly     | `probe`, `enum`                 | no |
| Listen        | `browse`, `capture`, `report`   | yes (REUSEPORT) |
| Authoritative | `spoof`, `flood`                | yes (REUSEPORT) |

`SO_REUSEPORT` lets us coexist with macOS `mDNSResponder`. If 5353 will not bind, the error points at firewall or sudo. No silent fallback.

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

For an engagement, declare scope once and reuse:

```toml
# whodis-scope.toml
allow_subnet   = ["10.0.5.0/24"]
allow_instance = ["LivingRoomTV"]
log_dir        = "./engagement-logs"
```

```sh
whodis --scope whodis-scope.toml spoof airplay.toml
WHODIS_SCOPE=whodis-scope.toml whodis flood conflict LivingRoomTV._airplay._tcp.local. --forever
```

CLI `--allow` flags stack on top of the scope file's lists.

## Engagement workflow

A real run. Define scope once. Capture continuously. Spoof and bridge a target. Push the real device off its name. Write the report.

`whodis-scope.toml`:

```toml
allow_subnet   = ["10.0.5.0/24"]
allow_instance = ["LivingRoomTV"]
log_dir        = "./engagement-logs"
```

```sh
mkdir -p engagement-logs
export WHODIS_SCOPE=whodis-scope.toml

# Capture every mDNS packet
whodis capture --pcap engagement-logs/mdns.pcap &

# Spoof the real Apple TV, bridge AirPlay traffic through us
whodis spoof --template airplay --name LivingRoomTV --ip 10.0.5.50 \
    --relay 10.0.5.20:7000 &

# Persistently force the real device off its name
whodis flood conflict LivingRoomTV._airplay._tcp.local. --forever --rate 20 &

# Watch the LAN while you work
whodis browse --pretty --fingerprint
```

When done:

```sh
kill %1 %2 %3
whodis report --out engagement-logs/report.md
```

`engagement-logs/` ends up with `mdns.pcap`, `report.md`, plus whatever stderr you redirected from the background processes.
