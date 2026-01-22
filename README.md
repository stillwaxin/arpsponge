# arpsponge (Go rewrite)

`arpsponge` is a daemon that mitigates ARP storms on large L2 networks. It listens on an Ethernet interface and, when ARP requests for a given IP exceed a threshold, it starts replying on behalf of that IP to absorb the storm.

This repository contains a Linux-focused Go rewrite of the original Perl implementation. The archived Perl code and documentation live under `archive/`.

## Requirements

- Linux
- Go 1.21+
- libpcap development headers (`libpcap-dev` on Debian/Ubuntu)
- Privileges for raw capture/injection (root or capabilities)

## Build

```
go build -o arpsponge ./cmd/arpsponge
go build -o arpspongectl ./cmd/arpspongectl
```

With version injection:

```
go build -ldflags "-X main.version=1.2.3 -X arpsponge/internal/engine.Version=1.2.3" -o arpsponge ./cmd/arpsponge
go build -ldflags "-X main.version=1.2.3 -X arpsponge/internal/engine.Version=1.2.3" -o arpspongectl ./cmd/arpspongectl
```

Taskfile shortcut:

```
task build VERSION=1.2.3
```

## Run

Basic usage (legacy-style positional arguments):

```
sudo ./arpsponge 192.0.2.0/24 dev eth0 \
  --rate=50 \
  --queuedepth=1000 \
  --pending=5 \
  --mac=02:de:ad:be:ef:01 \
  --sweep=900/3600
```

Alternative flags:

```
sudo ./arpsponge --network 192.0.2.0/24 --interface eth0 --mac 02:de:ad:be:ef:01
```

Key options:
- `--rate`: threshold rate in queries/minute
- `--queuedepth`: per-IP queue size for ARP request sampling
- `--pending`: number of probe cycles before sponging
- `--sweep`: `period/age` in seconds (e.g., `900/3600`)
- `--passive`: do not send ARP queries
- `--dummy`: do not send any packets
- `--mac` (experimental): override source MAC address (may disrupt normal traffic on some systems)
- `--arp-update-method`: `reply,request,gratuitous` or `none`

Control socket default path:
- `/run/arpsponge/<interface>/control.sock`

## Control CLI

```
./arpspongectl --interface eth0 status
./arpspongectl --interface eth0 ip list --state=dead
./arpspongectl --interface eth0 ip set 192.0.2.10 dead
./arpspongectl --interface eth0 log follow
```

Version check:

```
./arpsponge --version
./arpspongectl --version
```

## Architecture

See `ARCHITECTURE.md` for a component-level view and data flow.

## Archived Perl Implementation

The original Perl code and documentation are preserved under `archive/`.
