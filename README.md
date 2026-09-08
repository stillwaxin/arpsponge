# arpsponge (Go rewrite)

`arpsponge` is a daemon that mitigates ARP storms on large L2 networks. It listens on an Ethernet interface and, when ARP requests for a given IP exceed a threshold, it starts replying on behalf of that IP to absorb the storm.

This repository contains a Linux-focused Go rewrite of the original Perl implementation. The original Perl project and documentation are available upstream at [github.com/AMS-IX/arpsponge](https://github.com/AMS-IX/arpsponge).

## Requirements

- Linux
- Go 1.21+
- libpcap development headers (`libpcap-dev` on Debian/Ubuntu)
- Privileges for raw capture/injection (capabilities recommended, see Security)

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
- `--age`: expire learned ARP entries after this many seconds (`0` disables expiry)
- `--rate`: threshold rate in queries/minute
- `--queuedepth`: per-IP queue size for ARP request sampling
- `--pending`: number of probe cycles before sponging
- `--proberate`: positive aggregate query rate (q/s) shared by pending probes
  and sweeps (`0` disables pacing); pending probes are prioritized, while an
  aging sweep can eventually receive a shared slot
- `--init`: virtual state for previously unseen addresses (`ALIVE`, `DEAD`, `PENDING`, or `NONE`)
- `--sweep`: `period/age` in seconds (e.g., `900/3600`)
- `--passive`: do not send ARP queries
- `--dummy`: do not send any packets
- `--mac` (experimental): override source MAC address (may disrupt normal traffic on some systems)
- `--arp-update-method`: `reply,request,gratuitous` or `none`
- `--pidfile`: atomically publish the daemon PID and prevent a second daemon using the same pidfile; the PID file is removed on exit
- `--daemon`: deprecated compatibility no-op; emits a warning and relies on the service manager for backgrounding

`arpspongectl ip clear` removes materialized per-address state but does not
rewrite the configured `--init` policy. Subsequent read-only lookups report that
virtual policy without creating state or scheduling probes; packet processing
materializes state when it needs to write it.

The pidfile lock uses a persistent `<pidfile>.lock` sidecar. The sidecar is
intentionally retained across restarts so replacing the visible pidfile cannot
create an inode-lock race.

Control socket default path:
- `/run/arpsponge/<interface>/control.sock`

At startup, the daemon takes an exclusive sidecar lock for its control socket
and holds it until shutdown. A second daemon using the same socket path fails
without replacing the active listener. An existing socket is replaced only
after a bounded connection probe shows it is stale; a live or uncertain socket
causes startup to fail. A directory, regular file, symlink, or other
non-socket node is preserved and also causes startup to fail instead of being
deleted.

## Security

For production use, avoid running as root. Instead, grant the binary the necessary capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./arpsponge
```

Ensure the control socket directory is writable only by the user running the daemon to prevent unauthorized control.

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

## Original Perl Implementation

The original Perl project and documentation are available upstream at
[github.com/AMS-IX/arpsponge](https://github.com/AMS-IX/arpsponge).
