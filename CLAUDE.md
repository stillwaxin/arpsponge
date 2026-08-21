# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`arpsponge` is a Linux daemon that mitigates ARP storms on large L2 networks: it watches ARP request rates per IP and, once a threshold is exceeded, starts answering on behalf of that IP to absorb the storm. This is a Go rewrite of an older Perl implementation; the archived Perl code/docs live under `archive/`.

## Commands

Build (via Taskfile, preferred — injects version):
```
task build VERSION=1.2.3
```

Equivalent manual build:
```
go build -ldflags "-X main.version=1.2.3 -X arpsponge/internal/engine.Version=1.2.3" -o arpsponge ./cmd/arpsponge
go build -ldflags "-X main.version=1.2.3 -X arpsponge/internal/engine.Version=1.2.3" -o arpspongectl ./cmd/arpspongectl
```

Other Taskfile targets: `task fmt` (gofmt), `task vet` (go vet), `task lint` (golangci-lint), `task test` (go test ./...).

Run a single test:
```
go test ./internal/control/... -run TestName -v
```

**Platform note**: `internal/platform/linux/*.go` is built with `//go:build linux` and requires libpcap headers (`libpcap-dev`). On a non-Linux dev machine (e.g. macOS), `cmd/arpsponge` and anything importing `internal/platform/linux` will fail to build/test — this is expected, not a bug to fix. `internal/control`, `internal/engine` (build only, see below), `internal/netutil`, and `internal/packet` build cross-platform.

**Known pre-existing issue**: `go test ./internal/engine/...` fails with an import cycle (`engine_test.go` imports `internal/control`, which imports `internal/engine` via `log.go`). This is not something to silently work around — it's a real test-package structuring bug in the existing code.

## Architecture

Four pieces, described in full in `ARCHITECTURE.md` — read it before making structural changes:

1. **Capture/Inject** (Linux-only, `internal/platform/linux/`) — libpcap-based packet capture and raw ARP injection, isolated behind `//go:build linux` and `// linux-only` breadcrumbs so the rest of the codebase stays OS-agnostic.
2. **Engine** (`internal/engine/engine.go`) — the state machine. Per-IP states: `ALIVE`, `DEAD`, `STATIC`, `PENDING(n)`, `NONE`. Tracks ARP request rate per IP via a circular queue (`internal/engine/queue.go`); once the queue is full and the rate exceeds `max_rate`, the IP moves to `PENDING` and is probed — if still quiet after `max_pending` probes, it's marked `DEAD` and sponged. A periodic sweep re-probes quiet IPs on `sweep_period`/`sweep_age`.
3. **Control API** (`internal/control/server.go`) — HTTP/JSON over a Unix socket, endpoints under `/v1/...` (`status`, `ip`, `arp`, `config`, `log` including SSE log streaming at `/v1/log/stream`). Config updates are validated and applied to the live engine.
4. **CLI** (`cmd/arpspongectl/main.go`) — talks to the control API over the Unix socket. Commands: `status`, `ip {list|show|set|clear}`, `arp {list|show|clear}`, `config {get|set}`, `log {tail|follow}`.

Concurrency model: one goroutine runs pcap capture and feeds packets to the engine; a 1-second ticker drives pending-probe and sweep timers; the control API serves concurrently via `net/http`.

The daemon entrypoint (`cmd/arpsponge/main.go`) wires flags → `engine.Config`, opens the pcap capture, starts the control server on a Unix socket, then loops on the ticker plus `SIGINT`/`SIGTERM` (exit), `SIGHUP`/`SIGUSR1` (dump status to `--statusfile` if set).

## Security-sensitive code

- `internal/platform/linux/socket.go` creates the control Unix socket with a restricted umask (`0o077`) before `net.Listen` to avoid a permission-race window, then applies explicit owner/group/mode from `--permissions user:group:mode`. Any change to control-socket creation needs to preserve the umask-then-listen ordering. Default socket path: `/run/arpsponge/<interface>/control.sock`.
- The daemon is meant to run with `cap_net_raw,cap_net_admin` capabilities rather than as root (see README "Security" section).
- `--mac` (source MAC override) is explicitly experimental — see `TODO_MAC_SPOOFING.md` for the known tradeoffs (can trigger port-security on some switches) and the design directions being considered (macvlan/ipvlan, VLAN sub-interface, netns/veth) before extending this feature.
