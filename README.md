# whodis

mDNS / Bonjour recon and spoof, in Rust. macOS first.

```
cargo run -- browse
cargo run -- probe _airplay._tcp.local.
cargo run -- spoof --table answers.toml --burst 3 --allow 192.168.1.0/24
```

## Install

```sh
cargo install --path .
```

## Modes

| Mode | When | Binds 5353 |
|---|---|---|
| QueryOnly | `probe`, `fingerprint` | no |
| Listen | `browse` | yes (REUSEPORT) |
| Authoritative | `spoof`, `flood` | yes (REUSEPORT) |
| Custom | tests | configurable |

Bind modes coexist with `mDNSResponder` via SO_REUSEPORT. If 5353 won't bind, the error points at firewall or sudo. No silent fallback.

## Output

JSONL on stdout by default; `--pretty` for human view (auto on a TTY). `--color auto|always|never` respects `NO_COLOR`. Logs go to stderr.

## Authorization

`spoof` and `flood` accept `--allow CIDR` and `--allow-instance NAME` (both repeatable). Empty allow-list warns once and proceeds.

## Spoof table

TOML. Example `answers.toml`:

```toml
ttl = 120

[[answer]]
name = "_airplay._tcp.local."
qtype = "PTR"
data = "Spoofed-AppleTV._airplay._tcp.local."

[[answer]]
name = "Spoofed-AppleTV.local."
qtype = "A"
data = "192.168.1.42"
```

Supports `A`, `AAAA`, `PTR`.
