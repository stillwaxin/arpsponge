# Repository Guidelines

## Project Structure & Module Organization

This repository contains a Linux-focused Go implementation of `arpsponge`. Executables live in `cmd/arpsponge/` (daemon lifecycle, signals, and PID files) and `cmd/arpspongectl/` (control client). Shared packages are under `internal/`: `engine/` owns ARP state and pacing, `control/` provides the HTTP/JSON API over a Unix socket, `packet/` and `netutil/` contain protocol helpers, and `platform/` isolates OS-specific capture and socket code. Read `ARCHITECTURE.md` before changing component boundaries.

## Build, Test, and Development Commands

With Go Task installed, use the checked-in Taskfile for routine work:

- `task build VERSION=1.2.3` builds both binaries with version metadata.
- `task test` runs `go test ./...`.
- `task fmt` applies `gofmt` to `cmd/` and `internal/`.
- `task vet` runs Go's static analyzer.
- `task lint` runs the configured `golangci-lint` checks.

For focused work, run `go test ./internal/control/... -run TestServerConfigUpdate -v`. Linux builds require libpcap development headers. macOS is supported only for portable development and tests; the daemon is not runnable there, and Windows is unsupported.

## Coding Style & Naming Conventions

Follow standard Go formatting and use tabs as emitted by `gofmt`. Package names are short and lowercase; exported identifiers use `CamelCase`, unexported identifiers use `camelCase`, and filenames use lowercase words such as `pidfile_unix.go`. Keep Linux-only behavior behind `//go:build linux` files. Prefer small packages with explicit interfaces at the engine, control, and platform boundaries.

## Testing Guidelines

Place tests beside their implementation in `*_test.go` files and name cases `TestXxx`. Add regression tests for concurrency, state transitions, CLI parsing, and filesystem safety. Run the focused package while iterating, then `task test`, `task vet`, and `task lint` before submission.

## Commit & Pull Request Guidelines

Recent commits use concise, imperative subjects, for example `Fix correctness, concurrency, and CLI defects found in review`. Keep each commit scoped to one coherent change. Pull requests should explain user-visible behavior, list validation commands, link relevant issues, and call out Linux-only testing or security implications. Screenshots are unnecessary unless output presentation changes.

## Security & Configuration Tips

Avoid running the daemon as root; prefer `cap_net_raw,cap_net_admin` capabilities. Treat control-socket ownership, permissions, path replacement, packet injection, and experimental MAC overrides as security-sensitive changes requiring targeted regression tests.
