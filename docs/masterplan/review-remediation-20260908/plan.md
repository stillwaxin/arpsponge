# September 8 review remediation plan

Derived by native Astra planning subagent from the approved spec and goals. All eight review acceptance criteria remain required; REVIEW-2026-09-08.md and spec.md are the detailed behavior contract.

Wave 0 runs engine and socket tasks with disjoint scopes. Wave 1 runs CLI/control and daemon/platform after engine.ValidateConfig is available. R6 HTTP tests belong to task 3; startup tests belong to task 4. Implementers write only their declared scope, demonstrate failing regressions before fixes, return evidence, and never commit or mutate workflow state.

Task 1 implements R1 before R2: send gratuitous announcements outside state locking; preserve tracked shutdown; count successful active probes with pending-episode identity, simulate passive/dummy progression, retain a response cycle, and bound send-error logs. Failed sweeps neither count nor postpone. Add pure field-specific validation with atomic updates, zero semantics, finite rates, safe duration conversion and tiny-rate pacing arithmetic. Correct all-mask negation. Cover blocked sender/state/clear/re-pending races and all review acceptance cases.

Task 2 holds a persistent sidecar lock before probing/recovering socket paths. Refuse live or uncertain sockets, preserve filesystem protections, close the listener before releasing ownership, and test concurrent starts, stale recovery, failed construction and repeated close. Update README.

Task 3 gives log following a separate timeout-free streaming client with bounded context-aware dial/header waits, flushes headers, propagates failures and supports cancellation/JSON. Track supplied config flags explicitly and reject invalid values or extra arguments before HTTP. Test idle follow beyond ten seconds, failure exit status, zero/false preservation and HTTP validation atomicity.

Task 4 supervises synchronous packet reads and unexpected capture completion, preserves cancel/stop/join/close order, and validates startup before runtime resources. Test terminal errors, timeout/cancel, nil completion, shutdown handle safety and each invalid configuration field. Add Linux libpcap CI and run actual idle-capture cancellation in the prepared Docker environment, reporting any skipped privileged checks.

## Verification and review

Run each task's indexed tests and race tests, then task test, task vet, task lint, go test -race ./..., go build ./..., formatting and whitespace checks. Repeat tests/race/vet/build in the Linux libpcap container; confirm privileged idle-capture tests execute. An independent native reviewer examines all eight findings, concurrency guarantees and G1-G5. Resolve findings and rerun affected checks. Keep code/workflow-state commits separate and preserve the untracked review. Final branch disposition is handled by the orchestrator's final gate.

## Machine-indexed tasks

### Task 1 (wave 0)

Design and implement engine fixes for R1, R2, R6, and R8, preserving locking, pending-episode identity, pacing fairness, configuration atomicity, and shutdown guarantees.

- internal/engine/engine.go
- internal/engine/engine_test.go
- internal/engine/types.go
- internal/engine/types_test.go
- internal/engine/status.go
- internal/engine/queue.go
- internal/engine/queue_test.go
- internal/engine/config.go
- internal/engine/config_test.go

Verify: go test ./internal/engine/...; go test -race ./internal/engine/...; git diff --check

### Task 2 (wave 0)

Implement R4 exclusive control-socket ownership with a persistent sidecar lock, conservative stale recovery, safe listener cleanup, filesystem regressions, and updated README behavior.

- internal/platform/unixsocket/socket.go
- internal/platform/unixsocket/socket_test.go
- README.md

Verify: go test ./internal/platform/unixsocket/...; go test -race ./internal/platform/unixsocket/...; git diff --check

### Task 3 (wave 1)

Implement R5 streaming log-follow behavior and R7 explicit CLI argument validation; add R6 HTTP rejection and atomic-update coverage using the engine validator from task 1.

- cmd/arpspongectl/main.go
- cmd/arpspongectl/main_test.go
- internal/control/server.go
- internal/control/server_test.go
- internal/control/log.go

Verify: go test ./cmd/arpspongectl/... ./internal/control/...; go test -race ./cmd/arpspongectl/... ./internal/control/...; git diff --check

### Task 4 (wave 1)

Design and implement R3 tracked capture supervision and safe shutdown, integrate R6 startup validation from task 1, and add Linux libpcap CI with capture cancellation regression coverage.

- cmd/arpsponge/main.go
- cmd/arpsponge/main_test.go
- cmd/arpsponge/lifecycle.go
- cmd/arpsponge/lifecycle_test.go
- internal/cliargs/daemon.go
- internal/cliargs/daemon_test.go
- internal/platform/linux/pcap.go
- internal/platform/linux/pcap_test.go
- internal/platform/linux/stub.go
- internal/platform/linux/stub_test.go
- .github/workflows/ci.yml

Verify: go test ./cmd/arpsponge/... ./internal/cliargs/... ./internal/platform/linux/...; go test -race ./cmd/arpsponge/... ./internal/cliargs/... ./internal/platform/linux/...; git diff --check

