# Architecture

## Overview

The system is split into four main pieces:

1) Capture/Inject (Linux) — packet capture + ARP injection via libpcap.
2) Engine — state machine, rate tracking, pending probes, sweeping.
3) Control API — HTTP/JSON over a Unix socket (plus SSE log stream).
4) CLI — `arpspongectl` for status, state changes, and log tailing.

The control API and engine are OS-agnostic. Linux-specific functionality is isolated under `internal/platform/linux` with `//go:build linux` and `// linux-only` breadcrumbs.

## Components

### Packet Capture (Linux)

- `internal/platform/linux/pcap.go`
- Uses libpcap for capture and raw ARP injection.
- Applies a BPF filter for `arp or ip` to reduce packet processing overhead.

### Engine

- `internal/engine/engine.go`
- Maintains per-IP state and request queues.
- States: `ALIVE`, `DEAD`, `STATIC`, `PENDING(n)`, `NONE`.
- Threshold logic:
  - Track ARP request rate per IP via a circular queue.
  - If queue is full and rate exceeds `max_rate`, mark IP as PENDING.
  - Pending IPs are probed; if still quiet after `max_pending`, mark DEAD.
- Sweep logic:
  - Periodic probes of quiet IPs (`sweep_period`, `sweep_age`).

### Control API

- `internal/control/server.go`
- HTTP/JSON on a Unix socket with endpoints under `/v1/...`.
- Log streaming via Server-Sent Events (`/v1/log/stream`).
- Config updates are validated and applied at runtime.

### CLI

- `cmd/arpspongectl/main.go`
- Connects via Unix socket.
- Commands: `status`, `ip`, `arp`, `config`, `log`.

## Data Flow

1) Packet capture yields Ethernet frames (ARP or IPv4).
2) Decoder extracts src/dst MAC and IP information.
3) Engine updates state and may emit ARP replies or probes.
4) Log events are buffered and streamed to API clients.

## Concurrency Model

- One goroutine runs pcap capture and dispatches packets to the engine.
- A 1-second ticker drives periodic timers (pending probes, sweep).
- Control API serves concurrently via Go’s HTTP server.

## Configuration

- CLI flags configure runtime defaults.
- The control API can update a subset of config fields live via `/v1/config`.

## OS-Specific Boundaries

- `internal/platform/linux/iface.go`: interface MAC + IPv4 discovery.
- `internal/platform/linux/pcap.go`: capture + injection.
- `internal/platform/linux/socket.go`: Unix socket ownership/perms.

## Archived Perl Implementation

The original Perl architecture and docs are preserved under `archive/`.
