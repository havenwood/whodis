# whodis

mDNS / Bonjour recon and spoof, in Rust. macOS first.

```
whodis browse --fingerprint
whodis probe _airplay._tcp.local.
whodis spoof answers.toml --burst 3 --allow 192.168.1.0/24
whodis flood goodbye Foo._airplay._tcp.local.
```

## Install

```sh
cargo install --path .
```

## Subcommands

| Command | What |
|---|---|
| `browse` | Watch the LAN for mDNS announcements |
| `probe`  | One-shot directed mDNS query |
| `enum`   | Per-host service deep dive |
| `spoof`  | Authoritative responder reading a TOML answer table |
| `flood`  | Goodbye / conflict-rename floods |

## Browse

Listens on UDP/5353 (REUSEPORT, coexists with `mDNSResponder`) and emits one record per event. Goodbyes and TXT updates come through too.

```
whodis browse                       # JSONL until Ctrl-C
whodis browse --pretty              # human view, ANSI color on TTY
whodis browse --fingerprint         # tag each instance with vendor / product
whodis browse --once                # 5-second snapshot, exits clean
whodis browse -t 30                 # auto-exit after 30s
whodis browse | jq -c 'select(.kind == "instance_found")'
```

## Probe

Sends a directed query, collects answers for `--timeout` (default 3s), exits. Without a service type, lists what is on the LAN.

```
whodis probe                                                     # discover service types and counts
whodis probe _airplay._tcp.local.                                # all AirPlay receivers
whodis probe _ipp._tcp.local. -t 5                               # printers, 5s window
whodis probe _airplay._tcp.local. --instance "Living Room ATV"   # single instance
whodis probe --host BedroomTV.local                              # resolve a hostname
```

## Enum

Per-host deep dive. Lists every service that one host advertises by walking the DNS-SD meta-query then filtering SRV records by target.

```sh
whodis enum BedroomTV.local.
whodis enum 192-168-50-179.local. -t 8     # longer window for sluggish LANs
```

## Spoof

Runs an authoritative responder. Reads a TOML answer table, listens on 5353, replies with `aa` set, optionally bursts the response to win the race against `mDNSResponder`.

```
whodis spoof answers.toml --burst 3 --allow 192.168.1.0/24
whodis spoof answers.toml --allow-instance "Living Room ATV"
```

Built-in templates let you skip writing a TOML file for common service types. Pass `--template`, `--name`, and `--ip`:

```
whodis spoof --template airplay --name "Conf Room" --ip 10.0.5.42
whodis spoof --template ipp --name "Lobby Printer" --ip 10.0.5.50
whodis spoof --template ssh --name "honeypot" --ip 10.0.5.99
```

Available templates: `airplay`, `raop`, `ipp`, `smb`, `ssh`, `googlecast`.

`answers.toml` for a fake AirPlay receiver:

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
data = "192.168.1.42"
```

Supported `qtype` values: `A`, `AAAA`, `PTR`, `SRV`, `TXT`. The responder bundles related records as DNS additionals automatically (PTR responses include matching SRV / TXT / A / AAAA), so a single client query is enough to fully discover the spoofed instance.

With `--relay HOST:PORT`, whodis additionally listens on every port advertised in the answer table's SRV records and bridges incoming TCP connections to HOST:PORT. Combined with `flood conflict` against the real target, this is a full discovery + traffic MITM.

```sh
# Spoof Apple TV in the AirPlay picker, bridge AirPlay traffic to the real one
whodis spoof --template airplay --name FakeATV --ip 192.168.50.108 \
    --allow 192.168.50.0/24 \
    --relay 192.168.50.20:7000
```

## Flood

Disruptive. `goodbye` sends TTL=0 records to make neighbors re-announce (good for harvesting fresh TXT). `conflict` sends authoritative records that conflict with the target's claimed name, forcing a rename per RFC 6762 sec 9.

```
whodis flood goodbye Foo._airplay._tcp.local.
whodis flood goodbye --rate 10 Foo._airplay._tcp.local. Bar._ipp._tcp.local.
whodis flood conflict Foo._airplay._tcp.local. --allow-instance Foo
whodis flood goodbye Foo._airplay._tcp.local. --count 50
whodis flood goodbye Foo._airplay._tcp.local. --forever
```

`--rate` caps packets per second (default 50, minimum 1). `--count N` sends N packets per target (default 1, minimum 1). `--forever` repeats until Ctrl-C; mutually exclusive with `--count`.

## Capture

Listen on 5353 and write every received mDNS packet to a pcap file. Output is LINKTYPE_RAW (synthesized IPv4/IPv6 + UDP wrappers) so Wireshark and tshark open it directly.

```sh
whodis capture --pcap engagement.pcap -t 60     # 60s window
whodis capture --pcap engagement.pcap           # until Ctrl-C
tshark -r engagement.pcap                        # inspect
```

## Demo: spoof, browse, flood together

Three terminals using the `answers.toml` from the Spoof section.

**Terminal 1** — start the spoof:

```sh
whodis spoof answers.toml --burst 3 --allow 192.168.50.0/24
```

**Terminal 2** — watch the LAN. Your fake AppleTV shows up next to anything real:

```
$ whodis browse --pretty --fingerprint
   +  19:11:52  spoofed-appletv  _airplay._tcp...  spoofed-appletv.local.:7000  Apple AppleTV (tvOS)
```

**Terminal 3** — flood the spoof. The spoof defends its own name immediately, so Terminal 2 sees the goodbye and the re-announce:

```sh
whodis flood goodbye Spoofed-AppleTV._airplay._tcp.local.
```

Back on Terminal 2:

```
   +  19:11:52  spoofed-appletv  _airplay._tcp...  spoofed-appletv.local.:7000  Apple AppleTV (tvOS)
   -  19:11:53  spoofed-appletv._airplay....                                    goodbye
   +  19:11:54  spoofed-appletv  _airplay._tcp...  spoofed-appletv.local.:7000  Apple AppleTV (tvOS)
```

Same recipe works against real LAN devices. Pick a target name from `whodis browse` and substitute it for the fqdn above.

## Modes

| Mode | When | Binds 5353 |
|---|---|---|
| QueryOnly     | `probe`          | no |
| Listen        | `browse`         | yes (REUSEPORT) |
| Authoritative | `spoof`, `flood` | yes (REUSEPORT) |
| Custom        | tests            | configurable |

If 5353 won't bind, the error points at firewall or sudo. No silent fallback.

## Output

JSONL on stdout by default. `--pretty` switches to human view (auto on a TTY). `--color auto|always|never` respects `NO_COLOR`. Logs go to stderr.

## Authorization

`spoof` and `flood` accept `--allow CIDR` and `--allow-instance NAME` (both repeatable). Empty allow-list warns once and proceeds.

## Scope file

For an engagement, declare allow-lists once in a TOML scope file and pass it everywhere:

```toml
# whodis-scope.toml
allow_subnet   = ["10.0.5.0/24"]
allow_instance = ["LivingRoomTV"]
log_dir        = "./engagement-logs"   # used by `report` (planned)
```

```sh
whodis --scope whodis-scope.toml spoof airplay-takeover.toml
WHODIS_SCOPE=whodis-scope.toml whodis flood conflict "LivingRoomTV._airplay._tcp.local." --forever
```

`--allow` and `--allow-instance` on the command line stack on top of the file's lists.
