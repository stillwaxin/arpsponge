# arpsponge code review — findings and remediation plan

Scope: the full Go tree (~3,350 lines across `cmd/` and `internal/`).

This document is written to be picked up cold in a fresh session. Every finding marked
**VERIFIED** was reproduced empirically, with the evidence inline. Findings without that
marker are from code inspection only and should be confirmed before acting.

## Status — read this first

| Round | Date | Baseline | State |
|-------|------|----------|-------|
| 1 | 2026-08-20 | commit `d90a4de`, clean tree | **Implemented.** All 20 findings addressed. |
| 2 | 2026-08-20 | round-1 changes, uncommitted tree | **Implemented.** All 13 findings addressed, verified in round 3. |
| 3 | 2026-08-21 | round-2 changes, uncommitted tree | **Implemented.** All 4 findings addressed, verified in round 4. |
| 4 | 2026-08-21 | round-3 changes, uncommitted tree | **Implemented.** 1 finding addressed, verified in round 5. |
| 5 | 2026-08-21 | round-4 changes | **Closed. No findings.** |

**This review cycle is complete** — 39 findings across five rounds, all resolved. See
[Close-out](#close-out) at the bottom for what changed and what to know when reading the
history. Rounds 1–4 are retained as the record, including the reproductions for each
finding.

The per-round text refers throughout to an "uncommitted working tree". That described the
state at each review; the work has since been committed.

---

## Environment notes for whoever implements this

**Current (post round-3) — this is what you will find:**

- The whole tree builds and tests on macOS. `internal/platform/linux/stub.go` provides
  `//go:build !linux` fallbacks returning `ErrUnsupportedPlatform`, so `go build ./...`,
  `go vet ./...`, `go test ./...`, and `go test -race ./...` all work unmodified.
- `cmd/arpsponge` therefore links on macOS. It parses flags normally and fails at
  `linux.GetInterfaceInfo` with "unsupported platform: Linux is required", which makes
  CLI-level behavior testable without a Linux box — useful for R3-2 and R3-3.
- **`GOOS=windows go build ./...` fails, deliberately.** It passed after round 1 and broke
  when the Windows files were deleted in round 2; round 3 resolved this by declaring Windows
  unsupported in `ARCHITECTURE.md`. Do not "fix" the build — the vestigial `//go:build
  !windows` tags are the only loose end (R4-1 nit).
- `GOOS=linux go build` from macOS fails on gopacket's cgo pcap bindings. That is
  cross-compilation without cgo, not a code problem — don't chase it.
- Real capture and injection still require Linux plus libpcap headers.
- `gofmt -l ./cmd ./internal`, `go vet ./...`, and both test runs were clean at round-4
  review time. Keep them that way.
- Task targets exist for `fmt`, `vet`, `lint`, `test`, `build` (see `Taskfile.yml`).
  `golangci-lint` was not installed on the review machine, so `task lint` remains unverified.

**Historical (pre round-1):** `cmd/arpsponge` and `internal/platform/linux` failed to build
off Linux, so only `internal/control`, `internal/engine`, `internal/netutil`,
`internal/packet`, and `cmd/arpspongectl` could be checked on a Mac. Round-1 finding 18
fixed this.

---

## Suggested implementation order

> **Historical — this plan was carried out.** Retained to show what was asked for, so the
> round-2 findings can be read against the original intent.

Do these in order. The ordering matters: step 1 is a prerequisite for safely touching
the engine at all, and the concurrency work is deliberately last.

| Step | Findings | Why here |
|------|----------|----------|
| 1 | 7 | ~10 lines, and it turns the engine test suite on. Nothing else in the engine is safe to change until tests actually run. |
| 2 | 1, 2 | CLI parsing. Self-contained, zero engine risk, unblocks anyone trying to run the daemon as documented. |
| 3 | 4, 8 | Small, local, race-detector-verifiable. |
| 4 | 3 | Needs a semantics decision (see below) before coding. |
| 5 | 5, 6 | Concurrency restructure — largest blast radius. Do it with tests in place. |
| 6 | 9-20 | Hygiene, docs, hardening. Independent of each other. |

### Two decisions needed from the repo owner before starting

> **Both were decided by the implementing session without being escalated.** Finding 3 was
> treated as a bug and fixed; finding 9 was implemented rather than deleted. Both outcomes
> look right, but note that neither decision was actually put to the owner.

1. **Finding 3** — is `Queue.Reduce`'s aggressive collapse intentional Perl-compatible
   behavior, or a bug? The Perl original is no longer in the repo (see finding 13), so
   this cannot be settled from the source tree.
2. **Finding 9** — should `--age` / `arp_age` be implemented, or deleted? It is currently
   a knob that appears functional and does nothing.

---

# P0 — Silently broken in the documented configuration

## 1. The daemon ignores every flag in the README's primary invocation

**Location:** `cmd/arpsponge/main.go:60-82`
**Status:** VERIFIED

`flag.Parse()` stops at the first non-flag argument. The legacy-style form the README
advertises puts positional arguments first, so every flag after them lands in
`flag.Args()` unparsed and is silently discarded.

Reproduction (standalone, mirrors `main.go`'s flag set):

```go
rate := flag.Float64("rate", 50, "max rate")
mac := flag.String("mac", "", "mac")
flag.CommandLine.Parse(os.Args[1:])
fmt.Printf("rate=%v mac=%q args=%v\n", *rate, *mac, flag.Args())
```

```
$ go run flagtest.go 192.0.2.0/24 dev eth0 --rate=999 --mac=02:de:ad:be:ef:01
rate=50 mac="" args=[192.0.2.0/24 dev eth0 --rate=999 --mac=02:de:ad:be:ef:01]
```

A production deploy using the documented syntax runs entirely on defaults, with no
warning. Only the `--network`/`--interface` form currently honours flags.

**Fix:** parse in two passes. Scan `os.Args[1:]` for the `NET dev IFACE` triple, remove
those three tokens, then `flag.CommandLine.Parse()` the remainder. After parsing, error
out if `flag.Args()` is non-empty — that guard is what stops this class of bug recurring
silently.

**Verify:** the README invocation with `--rate=999` must produce a status showing
`max_rate: 999`, not 50.

---

## 2. `arpspongectl --interface eth0 status` fails

**Location:** `cmd/arpspongectl/main.go:30-51`
**Status:** VERIFIED

The hand-rolled subcommand scanner takes the first token not starting with `-` as the
subcommand. For `--interface eth0 status` that token is `eth0` — the *value* of the
preceding flag — so `global.Parse(args[:1])` is handed a lone `--interface`.

```
$ go build -o /tmp/arpspongectl ./cmd/arpspongectl
$ /tmp/arpspongectl --interface eth0 status
flag needs an argument: -interface
Usage of global:
  ...
(exit 2)
```

Only the glued `--interface=eth0` form works. Every README example uses the separated
form.

**Fix:** delete the manual scanner entirely. `global.Parse(os.Args[1:])`, then take the
subcommand and its arguments from `global.Args()` — the stdlib already implements the
"flags first, then positionals" split this code is hand-rolling. Note this also changes
`--version` handling, which currently has two separate code paths (lines 44-47 and
53-56) that collapse into one.

**Verify:** all four README `arpspongectl` examples must run and reach the socket-dial
stage (connection-refused is fine; a parse error is not).

---

## 3. Flood-protection reduction collapses queues and defeats sponging

**Location:** `internal/engine/queue.go:89-131`
**Status:** VERIFIED (behavior); intent NOT verified — see decision 1 above

`Reduce` compares each entry against its **immediate predecessor** in the sorted slice
rather than against the last *kept* entry. Any run of sub-`minDelta` gaps therefore
cascades, dropping everything but the final entry regardless of the run's total span.

```go
q := NewQueue(100)
base := time.Now()
for i := 0; i < 11; i++ {                      // 11 requests, one source,
    q.Add(1, 42, base.Add(time.Duration(i)*500*time.Millisecond))  // 500ms apart, 5s span
}
// before: depth=11 rate=120.0 q/min
q.Reduce(1, 1.0)                                // flood protection = 1 q/s
// after:  depth=1  rate=0.0 q/min
```

A correct per-second cap over a 5-second span keeps ~6 entries. This one keeps 1.

The consequence is the important part: the post-reduction re-check at
`internal/engine/engine.go:545` requires `IsFull() && Rate() > MaxRate`. A collapsed
queue satisfies neither, so **the address can never be sponged**. `FloodProtection`
defaults to `3.0`, so this code path is live in every default deployment.

**Caveat on intent:** flood protection legitimately exists to stop a single noisy source
from triggering sponging on its own, so collapsing a single-source burst is
*directionally* right. What is clearly wrong is the magnitude — the filter does not
implement "at most `maxRate` per second per source", it implements "keep the last entry
of any dense run". Settle decision 1 before changing this.

**Fix (if treated as a bug):** greedy filter anchored on the last kept entry:

```go
if lastKept == nil || entry.src != lastKept.src || entry.ts.Sub(lastKept.ts) >= minDelta {
    keep(entry)
    lastKept = entry
}
```

**Verify:** the 11-entry repro above should retain ~6 entries, and `Rate()` should stay
above zero. Add it as a table test in `internal/engine/queue_test.go`.

---

# P1 — Correctness and stability

## 4. Two data races

**Locations:** `internal/engine/engine.go:369` and `:491`
**Status:** VERIFIED with `go test -race`

| Unlocked read | Racing write | Field |
|---|---|---|
| `engine.go:369` (`handleIPv4`) | `engine.go:207` (`UpdateConfig`) | `e.cfg.ArpUpdateFlags` |
| `engine.go:491` (`handleARP`) | `engine.go:930` (`ForceLearning`), `:556` (`Tick`) | `e.learningLeft` |

Both are reads on the packet-handling goroutine racing writes from the control-API and
ticker goroutines. Race detector output (paths trimmed):

```
WARNING: DATA RACE
Write at 0x00c0000f82a0 by goroutine 10:
      internal/engine/engine.go:930          <- ForceLearning
Previous read at 0x00c0000f82a0 by goroutine 8:
      internal/engine/engine.go:491          <- handleARP
      internal/engine/engine.go:358

WARNING: DATA RACE
Write at 0x00c0000f81e8 by goroutine 9:
      internal/engine/engine.go:207          <- UpdateConfig
Previous read at 0x00c0000f81e9 by goroutine 8:
      internal/engine/engine.go:369          <- handleIPv4
      internal/engine/engine.go:353
```

**Fix:** take `e.mu`, copy into a local, release — the exact pattern already used in
`sendQuery` (`engine.go:697-702`) and `sendReply`. Do not hold the lock across the
send calls.

**Verify:** a concurrency test driving `HandlePacket`, `UpdateConfig`, and
`ForceLearning` from three goroutines under `-race`. The review used a ~30-line test of
this shape; it belongs in the repo permanently.

---

## 5. Probe and sweep sleep on the ticker goroutine

**Location:** `internal/engine/engine.go:570-695`, driven from `cmd/arpsponge/main.go:206-220`

`probePending` and `sweepIfNeeded` call `time.Sleep(1/proberate)` inline, once per
address. `Tick` is invoked from main's `select` loop — **the same loop that handles
signals**. A long pass therefore blocks packet-rate timers *and* leaves the daemon
unresponsive to SIGTERM for its full duration.

A `/16` sweep at the default `proberate=100` is 65,536 × 10 ms ≈ **655 seconds** of
sleeping inside a single `Tick`.

**Fix:** move probe and sweep onto their own goroutine, paced by a dedicated
`time.Ticker`, with an atomic in-progress guard so passes cannot overlap. `Tick` becomes
a non-blocking signal. Keep the 1-second ticker in main for anything genuinely cheap.

**Verify:** with a large network configured and a sweep in progress, SIGTERM must shut
the daemon down promptly.

---

## 6. `--init PENDING` hangs the daemon on any non-trivial network

**Location:** `internal/engine/engine.go:217-229` and `:231-240`
**Status:** VERIFIED

`Pending(0)` is `State(0)`, which satisfies `state >= 0` in `setStateLocked`, so
initialisation adds **every address in the range** to `e.pending`. Measured on
`10.0.0.0/16`:

```
/16 init PENDING: pending map entries=65535
```

`probePending` then walks all of them every tick at `1/proberate` seconds each — ~655 s
per pass at the default `proberate=100`. The first attempt to measure this blew a
2-minute test timeout from inside `probePending`; the figure above was obtained by
forcing `Proberate=0` and `Passive=true` to skip the sleeps. Combined with finding 5
this is a hard stall of the main loop, not merely slowness.

**Related, lower urgency:** `initAllStateLocked` eagerly materialises three map entries
per address regardless of init state:

```
/16 init ALIVE: 65536 state entries, 7.1 MB heap, 15ms
```

That scales linearly — a `/12` is ~110 MB, a `/8` ~1.8 GB — and the README advertises
this daemon for "large L2 networks".

**Fix:** populate state lazily on first sight rather than up front, and reject or warn on
prefixes shorter than a configurable bound. If eager init must stay for compatibility,
at minimum stop seeding `e.pending` for the whole range.

---

## 7. The engine package has zero working tests — DO THIS FIRST

**Location:** `internal/engine/engine_test.go:6`
**Status:** VERIFIED

`engine_test.go` declares `package engine` and imports `arpsponge/internal/control`,
which imports `arpsponge/internal/engine` via `log.go`. Import cycle, package does not
build:

```
$ go test ./...
# arpsponge/internal/engine
package arpsponge/internal/engine
	imports arpsponge/internal/control from engine_test.go
	imports arpsponge/internal/engine from log.go: import cycle not allowed in test
FAIL	arpsponge/internal/engine [setup failed]
```

**`go test ./...` has therefore never executed a single engine test.**

The cycle exists only because the test borrows `control.NewLogger` for a throwaway
logger. `engine.Logger` is already an interface — a local fake removes the dependency:

```go
type nopLogger struct{}
func (nopLogger) Logf(LogLevel, EventMask, string, ...any) {}
```

**Important — the cycle fix uncovers two red tests.** Applied in a scratch copy:

```
--- FAIL: TestHandleARPSetPending (0.00s)
    engine_test.go:55: expected state to be set
--- FAIL: TestHandleARPReplyForDead (0.00s)
    engine_test.go:84: expected a reply to be sent
```

Cause: `DefaultConfig().LearnSeconds = 5`, and `engine.go:491` drops all ARP requests
while `learningLeft > 0`. The tests were written against an engine that never ran them.

**Fix:** local fake logger, plus `cfg.LearnSeconds = 0` (or `eng.ForceLearning(0)`) in
`newTestEngine` at `engine_test.go:22-36`. Both tests then exercise what they claim to.

**Verify:** `go test ./internal/engine/...` passes, and `go test ./...` no longer reports
a setup failure for that package.

---

## 8. `incrPendingLocked` resurrects addresses that just went ALIVE

**Location:** `internal/engine/engine.go:268-272`, called from `:596-620`

`probePending` snapshots the pending set, then re-reads each address's state under the
lock per iteration. If an inbound packet marks an address ALIVE (`-1`) mid-loop:

- `pendingCount` is `-1`, which is not `> maxPending`, so no death
- `incrPendingLocked` computes `-1 + 1 = 0` and calls `setPendingLocked(ip, 0)`

The address is forced back to `PENDING(0)`, undoing a legitimate unsponge.

**Fix:** `if pendingCount < 0 { continue }` before the increment, inside the same locked
section that read the state.

**Verify:** test that flips an address to ALIVE between the snapshot and the increment
and asserts it stays ALIVE.

---

## 9. `--age` / `arp_age` is dead config; the ARP table never expires

**Location:** `internal/engine/engine.go:29`
**Status:** VERIFIED by exhaustive grep

`ArpAge` is plumbed through the CLI flag (`main.go:132`), `Config`, `DefaultConfig`,
`configView`, and `configUpdate` — and is **never read by any engine logic**. Full set of
references:

```
cmd/arpsponge/main.go:132          cfg.ArpAge = *flagAge
internal/engine/engine.go:29       ArpAge int
internal/engine/engine.go:52       ArpAge: 600
internal/control/server.go:336,358,380,405-406   (view + update plumbing only)
```

`e.arpTable` consequently only shrinks via an explicit `arp clear`. Two problems: an
operator-visible knob that silently does nothing, and unbounded retention of stale
entries.

**Fix:** implement expiry in `Tick` (evict entries older than `ArpAge`), or delete the
flag and field outright. See decision 2. Do not leave it half-wired.

---

# P2 — Security and robustness

## 10. Control-socket ownership failures are silent

**Location:** `internal/platform/linux/socket.go:29` and `:48`

```go
_ = os.Chmod(path, perm)
_ = os.Chown(path, uid, gid)
```

If the `--permissions` chown fails, the socket retains root ownership and the operator
gets no indication their access model did not apply. This undercuts the umask hardening
added in `d90a4de` — that commit closed the creation race, but the permissions that
follow it can fail silently.

**Fix:** propagate both errors. On failure, close the listener and remove the socket path
before returning, so a partially-configured socket is never left listening.

---

## 11. No HTTP server timeouts

**Location:** `cmd/arpsponge/main.go:184`

`http.Serve(listener, srv.Handler())` sets no `ReadHeaderTimeout`, `ReadTimeout`, or
`WriteTimeout`. A client that connects and stalls mid-header pins a goroutine
indefinitely. Exposure is low behind a `0700` directory, but the fix is a three-line
`&http.Server{...}` and it silences the standard gosec finding.

---

## 12. Minor lifecycle gaps

- `cmd/arpsponge/main.go:155-179` — `os.Exit(2)` on the rundir/socket error paths skips
  the `defer capture.Close()` registered at line 155. Cosmetic (the kernel reclaims the
  handle), but the pattern is worth correcting: return an error from a `run()` helper and
  let `main` exit.
- `--pidfile` is written (`main.go:187-191`) but never removed on exit, and there is no
  lock — two daemons can run against one interface and fight over the socket path.
- `--daemon` is accepted and ignored with a warning (`main.go:67-69`). Consider removing
  it rather than carrying a no-op flag.

---

# P3 — Documentation and hygiene

## 13. `archive/` is referenced but no longer exists

`README.md` and `ARCHITECTURE.md` both direct readers to `archive/` for the original Perl
implementation. It was deleted in `f8480ec` ("removed old perl code"). Three references
total.

This is more than a broken link: without the Perl reference, questions like findings 3
and 14 cannot be settled from the repo. **Recommend linking to the upstream Perl project
instead of just deleting the mentions.**

## 14. `--pending=N` probes N+1 times and sponges on cycle N+2

**Location:** `internal/engine/engine.go:602`

`pendingCount > maxPending`, starting from `PENDING(0)`. With the default `5`: ticks 1-6
each send a query and increment (0→6), tick 7 sees `6 > 5` and sponges. So six probes,
death on the seventh cycle, for a flag documented as "number of probe cycles before
sponging".

**Fix:** change to `>=`, or document the actual semantics. Confirm against the Perl
original if it can be recovered (finding 13).

## 15. Misleading per-packet debug log

**Location:** `internal/engine/engine.go:309-311`

```go
if !mac.IsZero() {
    e.logf(LevelDebug, EventState, "clearing: ip=%s mac=%s", ...)
}
```

Nothing is being cleared here — this fires for *every* alive host with a known MAC, i.e.
once per packet at `--loglevel=debug`. It appears to be a copy-paste of the genuine
clearing log at line 322. Both the wording and the unconditional firing look wrong.

## 16. Dead code

- `internal/engine/queue.go:82` — `Queue.GetQueue` is an exported method returning
  `[]queueEntry`, an unexported type. Unusable from outside the package, unused inside
  it.
- `internal/netutil/ipv4.go:75` — `netutil.Range` returns its two arguments unchanged and
  has no callers.

## 17. `learning` is settable via the control API but has no effect

`configUpdate.LearnSeconds` (`internal/control/server.go:384, 417-419`) updates
`cfg.LearnSeconds`, but `learningLeft` is only seeded from it in `New`
(`engine.go:146`). Either wire the update through to `ForceLearning`, or drop the field
from `configUpdate`.

## 18. No non-Linux build stub

`internal/platform/linux` has no `//go:build !linux` counterpart, so `go build ./...`,
`go vet ./...`, and `go test ./...` all fail on macOS dev machines — which is where this
review was conducted. A stub returning "unsupported platform" would make the standard
toolchain work everywhere and let CI run the full command set unmodified.

## 19. No tests for `netutil` or `packet`

Both are pure, dependency-free, and carry real parsing logic that is currently unexercised:

- `netutil` — CIDR parsing, broadcast computation, `InNet` boundary behavior at
  prefix 0/32, `ParseIPv4String` (which accepts IPv4-mapped IPv6 such as
  `::ffff:1.2.3.4` and returns a uint32 — confirm that is intended, since it reaches the
  control API via URL paths).
- `packet` — MAC parsing, `IsZero`, and the 12-hex-character `UnmarshalText` branch at
  `types.go:65-72`.

## 20. `--mac` override silently disables ARP-update-method

**Location:** `internal/engine/engine.go:372`

`handleIPv4` gates on `pkt.DstMAC != e.myMAC`. With `--mac` set, `myMAC` is the override
address, but the NIC still receives frames addressed to its *real* hardware MAC — so the
gate never passes and `--arp-update-method` never fires.

Related: `HandlePacket`'s self-filter at `engine.go:344` (`pkt.SrcMAC == e.myMAC`)
filters the daemon's own injected frames correctly under an override, but no longer
filters frames the host sends from its real MAC.

**Action:** document both in `TODO_MAC_SPOOFING.md` as known constraints of the
experimental flag. They are consequences of the single-MAC assumption that the TODO's
proposed macvlan/split-interface designs would resolve.

---

## Appendix: findings by file

| File | Findings |
|---|---|
| `cmd/arpsponge/main.go` | 1, 5, 11, 12 |
| `cmd/arpspongectl/main.go` | 2 |
| `internal/engine/engine.go` | 4, 5, 6, 8, 9, 14, 15, 20 |
| `internal/engine/queue.go` | 3, 16 |
| `internal/engine/engine_test.go` | 7 |
| `internal/control/server.go` | 9, 17 |
| `internal/platform/linux/socket.go` | 10 |
| `internal/platform/linux/*` | 18 |
| `internal/netutil/ipv4.go` | 16, 19 |
| `internal/packet/types.go` | 19 |
| `README.md`, `ARCHITECTURE.md` | 13 |
| `TODO_MAC_SPOOFING.md` | 20 |

---
---

# Round 2 — review of the round-1 implementation

Review date: 2026-08-20. Reviewed against the **uncommitted working tree** containing the
round-1 changes.

> **Status: implemented.** All 13 findings below were addressed by a follow-up session and
> independently verified in [Round 3](#round-3--review-of-the-round-2-implementation). Kept
> as the historical record. NEW-5's fix introduced R3-1 — read them together.

## Verdict

All 20 round-1 findings were addressed, and the mechanical fixes are good. The two fixes
that required judgement — lazy state init (finding 6) and async `Tick` (finding 5) — each
introduced a new defect. One will crash the daemon on shutdown.

**Do not commit the working tree until NEW-1 and NEW-2 are resolved.** NEW-2 additionally
has a test asserting the wrong behavior, so that test must be deleted, not made to pass.

## Baseline measured at review time

Everything below was run against the working tree, not inferred:

```
gofmt -l ./cmd ./internal      clean
go vet ./...                   clean
go build ./...                 clean
GOOS=windows go build ./...    clean
go test ./...                  all 9 packages ok
go test -race ./...            all 9 packages ok
```

47 test functions, up from 6. Coverage by package:

| Package | Coverage |
|---|---|
| `internal/platform/linux` | 100.0% |
| `internal/cliargs` | 93.3% |
| `internal/platform/unixsocket` | 88.0% |
| `internal/netutil` | 82.9% |
| `internal/packet` | 64.1% |
| `internal/engine` | 57.7% |
| `internal/control` | 41.2% |
| `cmd/arpsponge` | 18.7% |
| `cmd/arpspongectl` | 5.2% |

**The green race suite is not evidence of correctness.** It covers what the round-1 session
built. It does not cover what that session broke — there is no test for shutdown ordering,
none for read-path purity, and the one test touching lazy init asserts the defect as
intended behavior.

---

## Blockers

### NEW-1 — ARP packets are written through a freed pcap handle on shutdown

**Location:** `internal/engine/engine.go` (`Tick`), `cmd/arpsponge/main.go:175, 214-216, 241`
**Severity:** crash-class. **Status:** VERIFIED

`Tick` now detaches its work and nothing ever waits for it:

```go
go func() {
    defer e.passInProgress.Store(false)
    e.probePending(now)
    e.sweepIfNeeded(now)
}()
```

`Engine` has no `Stop`, no `Wait`, and takes no context. `main` still runs
`defer capture.Close()` (`main.go:175`) and the signal path simply returns (`main.go:241`).

Sequence on any SIGTERM landing during a probe or sweep pass:

1. `run` returns, deferred `capture.Close()` frees the cgo `pcap_t`
2. the orphaned goroutine continues calling `e.sender.SendARP`
3. `Capture.SendARP` calls `handle.WritePacketData` on freed memory

Reproduced with a sender that models the capture handle (flags any call arriving after
`Close`), `/16`, sweep in flight:

```
total SendARP calls=1479, calls made AFTER Close=1264
```

This is strictly worse than the bug it replaced. Finding 5 was "SIGTERM is slow to take
effect"; this is "SIGTERM corrupts memory". The old synchronous code could not do this.

The `capture.Run` goroutine at `main.go:214-216` is unwaited in the same way — pre-existing,
but it is the same fix.

**Fix:** give `Engine` a real lifecycle — context or `sync.WaitGroup`, plus a `Stop()` that
cancels and blocks until in-flight passes finish. Call it before `capture.Close()`, which
means ordering the shutdown deliberately rather than relying on defer-LIFO accident.

**Verify:** a test that starts a pass, closes the sender, and asserts zero sends afterwards.
The reproduction above is the shape of it and belongs in the repo.

---

### NEW-2 — Read-only control API calls mutate state and put ARP queries on the wire

**Location:** `internal/engine/engine.go` (`getStateLocked`, `GetIPState`)
**Severity:** high. **Status:** VERIFIED

`getStateLocked` was made mutating: on a map miss it calls `setStateLocked`, writing
`state`, `stateMtime`, `stateAtime`, and — under `--init PENDING` — `pending`.

`GetIPState` calls it, and `GetIPState` serves `GET /v1/ip/<addr>`. Measured:

```
init=ALIVE    state entries:   before GET=1   after 2 GETs=2
init=PENDING  pending entries: before 20 GETs=0  after=20
```

Twenty read-only API queries enqueued twenty addresses for active ARP probing. That means
`arpspongectl ip show`, or any monitoring system polling the control API, causes the daemon
to transmit ARP queries for addresses nothing asked it to probe. A read with side effects
on the wire.

It also reopens finding 6 through the back door: anything walking the range via the API
rebuilds the dense map that lazy init existed to avoid.

**This was deliberate, not an oversight.** `TestPendingInitialStateIsSparseUntilFirstAccess`
asserts `len(eng.pending) == 1` after a `GetIPState` call — the behavior is designed, tested,
and locked in. Read that test before changing anything; it must be rewritten, not repaired.

**Fix:** `effectiveStateLocked` already exists, is non-mutating, and is correctly used by the
sweep. Route every read path through it; materialize only on write paths that already write.
Then delete the mutating getter — two near-identical lookups where one silently writes is a
trap for the next person in this file.

**Verify:** assert `len(eng.state)` and `len(eng.pending)` are unchanged across repeated
`GetIPState` calls, under both `--init ALIVE` and `--init PENDING`.

---

## Regressions

### NEW-3 — `arpsponge --help` no longer works

**Location:** `cmd/arpsponge/main.go:42-43`. **Status:** VERIFIED

`flag.ContinueOnError` combined with `flags.SetOutput(io.Discard)`:

```
$ arpsponge --help
flag: help requested          (exit 2)
$ arpsponge -h
flag: help requested          (exit 2)
```

There is now no way to discover the daemon's flags. The old `ExitOnError` printed full
usage and exited 0. `arpspongectl -h` still prints its command list and exits 0, so the two
binaries now behave differently.

**Fix:** handle `flag.ErrHelp` explicitly in `run` — print usage to stdout, exit 0.

### NEW-4 — `--daemon` is now a hard startup failure

**Location:** `cmd/arpsponge/main.go` flag set. **Status:** VERIFIED

```
$ arpsponge --daemon 192.0.2.0/24 dev eth0
flag provided but not defined: -daemon    (exit 2)
```

Previously accepted with a warning to stderr. Any existing init script or systemd unit
carrying `--daemon` — plausible for a daemon ported from Perl — now fails to start.

Round-1 finding 12 said "consider removing"; the session removed it, added
`TestRunRejectsRemovedDaemonFlagWithoutExiting` to lock it in, and did not mention it in
the README.

**Fix:** either restore it as a documented no-op, or add it to the README as an explicit
breaking change. Silent removal is not an option for a flag that appears in service units.

### NEW-5 — Sweeps still prevent the daemon from sponging

**Location:** `internal/engine/engine.go` (`Tick`, `passInProgress`). **Status:** VERIFIED

A single `passInProgress` flag guards both passes, and `sweepIfNeeded` runs after
`probePending` inside the same goroutine. While a sweep is in flight every later `Tick`
returns immediately, so `probePending` never runs:

```
after 10 ticks during a long sweep, address state = PENDING(0)
```

A `/16` sweep at the default `proberate=100` runs ~11 minutes, during which no address can
advance from PENDING to DEAD — the daemon cannot sponge anything.

In fairness this starvation predates round 1 (the old synchronous `Tick` dropped ticker
ticks the same way). It is not a new regression. But it was the moment to fix it, and it now
hides behind an early return instead of a visibly blocked loop.

**Fix:** separate guards for the two passes, or separate goroutines. Probing drives the
daemon's entire purpose; background sweeping must not be able to block it.

---

## Implementation quality

### NEW-6 — ARP expiry is an O(n) scan under the packet lock at 1 Hz

**Location:** `internal/engine/engine.go`, top of `Tick`

The finding-9 implementation walks the whole `arpTable` while holding `e.mu` — the lock the
packet path contends for — every single tick. `--age` defaults to 600, so this runs in every
deployment. At 65k entries it is a sustained per-second stall on packet processing.

**Fix:** amortize across ticks, or track expiry so it does not need a full scan.

### NEW-7 — `ip clear` permanently disables `--init` for the process lifetime

**Location:** `internal/engine/engine.go` (`ClearAllState`)

```go
// Clear is an explicit reset, so do not recreate --init state afterwards.
e.initialState = StateNone
```

A defensible reading of "clear", but it is irreversible without a daemon restart, it
silently changes what the API returns for unseen addresses (`ALIVE` → `404`), and it is
documented nowhere outside this comment. Decide it deliberately and put it in the README.

### NEW-8 — Over-engineering

- **Windows port.** Round-1 finding 18 asked for a build stub so `go vet ./...` works on
  **macOS**. The session shipped `cmd/arpsponge/pidfile_windows.go`,
  `cmd/arpsponge/signals_windows.go`, and two Windows test files — for a libpcap-based Linux
  ARP daemon that can only ever return `ErrUnsupportedPlatform` there. Delete them; keep
  `internal/platform/linux/stub.go`, which does the actual job.
- **`unixsocket.socketOps`** injects seven function pointers to make chmod/chown failures
  testable, a permanent indirection layer over a 40-line security-critical function.
- **`cliargs.ParseLegacyDaemonArgs(args, parseFlags func([]string) error, parsedArgs func() []string)`**
  takes two callbacks to avoid naming `*flag.FlagSet`. Pass the FlagSet.

### NEW-9 — `unixsocket` bypasses its own injection seam

**Location:** `internal/platform/unixsocket/socket.go:115`

`cleanup` calls `ops.remove`, but `removeExistingSocket` calls `os.Remove` directly. If the
seam is worth building it should be used consistently; the non-socket-refusal path is
currently untestable through it.

### NEW-10 — `extractLegacyDaemonArgs` takes the first `dev` it finds

**Location:** `internal/cliargs/daemon.go:30`

No check that the preceding token is a CIDR. Malformed inputs fail loudly rather than
silently, which is acceptable — but requiring `args[i]` to parse as a network removes the
whole class in one line.

### NEW-11 — `syscall.Umask` promoted to a reusable exported API

**Location:** `internal/platform/unixsocket/socket.go:50-52`

`Umask` is process-global and not thread-safe. The umask-then-listen ordering is correct and
preserved (as `CLAUDE.md` requires), and it is safe where it is called today — but it has
moved from a private helper into an exported `unixsocket.Listen` that invites reuse,
including from goroutines, with no warning in the package doc. Document the constraint.

### NEW-12 — Argument parsing is still inconsistent about failing loudly

**Location:** `cmd/arpsponge/main.go:246-259` and `:261-272`

`parseSweep("nonsense")` returns `0,0` (silently disabling sweeps) and discards both
`strconv.Atoi` errors; `parseInitState("BOGUS")` silently returns `ALIVE`. This directly
contradicts the fail-loudly principle the same session applied to flag parsing.

### NEW-13 — Undocumented behavior changes

- `--age` expiry is now functional, visibly changing `arp list` output over time. Not in the
  README.
- `removeExistingSocket` replaced `os.RemoveAll` with `os.Remove` plus a refusal to replace
  a non-socket path. Good hardening, but a stale *directory* at the socket path now fails
  startup instead of being removed. Worth a release note.
- The pidfile `.lock` file is never removed. Probably deliberate (removing it races), but
  undocumented.

---

## Credit where due

Not one of my findings: the `.gitignore` fix. The bare `arpsponge` / `arpspongectl` patterns
were matching the `cmd/` **directories**, which is why the entire `cmd/` tree has never been
committed — it was silently ignored. Anchoring both with `/` is correct and deserves its own
commit message so the history explains why `cmd/` suddenly appears.

---

## Round-1 scorecard

| # | Finding | Status |
|---|---|---|
| 1 | Daemon ignores flags in legacy form | Fixed, verified |
| 2 | `arpspongectl --interface eth0 status` | Fixed, verified — clean stdlib rewrite |
| 3 | `Queue.Reduce` over-reduction | Fixed, verified: 11 → 6 entries, rate 60 q/min |
| 4 | Two data races | Fixed, `-race` clean |
| 5 | Probe/sweep block the ticker | **Partial** — see NEW-1, NEW-5 |
| 6 | `--init PENDING` blowup | **Partial** — see NEW-2 |
| 7 | Engine tests don't compile | Fixed, 47 tests |
| 8 | `incrPendingLocked` resurrection | Fixed, guarded in both places |
| 9 | `--age` dead config | Implemented — see NEW-6 |
| 10 | Socket chmod/chown errors | Fixed well; non-socket refusal is a good addition |
| 11 | No HTTP timeouts | Fixed well; SSE write-deadline clearing is the right detail |
| 12 | Lifecycle gaps | Fixed; pidfile is solid — see NEW-4 |
| 13 | `archive/` references | Fixed, upstream link |
| 14 | `--pending=N` off-by-one | Fixed, `>=`, 5 probes |
| 15 | Misleading `clearing:` log | Fixed |
| 16 | Dead code | Fixed |
| 17 | `learning` no-op | Fixed |
| 18 | No non-Linux stub | Fixed, then gold-plated — see NEW-8 |
| 19 | No netutil/packet tests | Fixed |
| 20 | `--mac` constraints | Documented well |

## Round-2 implementation order

> **Historical — this plan was carried out.** All six steps landed. See Round 3 for the
> verification and for what the NEW-5 fix broke on its way in.

| Step | Findings | Why here |
|------|----------|----------|
| 1 | NEW-2 | Requires a design decision and deleting a test that asserts the defect. Do it before anything else touches engine state. |
| 2 | NEW-1 | The crash. Needs an `Engine` lifecycle, which changes shutdown ordering in `main`. |
| 3 | NEW-5 | Falls out of the NEW-1 lifecycle work — same code, same goroutines. |
| 4 | NEW-3, NEW-4 | CLI surface. Independent, quick. |
| 5 | NEW-6, NEW-7, NEW-13 | Behavior and docs. |
| 6 | NEW-8 … NEW-12 | Cleanup. Deleting the Windows files is the largest single win. |

### Decisions needed from the repo owner

1. **NEW-2** — should first *access* materialize state at all, or only first *packet*? This
   determines whether the control API is read-only.
2. **NEW-4** — restore `--daemon` as a no-op, or document the break?
3. **NEW-7** — should `ip clear` permanently disable `--init`, or only clear current state?

---
---

# Round 3 — review of the round-2 implementation

Review date: 2026-08-21. Reviewed against the **uncommitted working tree** containing the
round-1 and round-2 changes.

> **Status: implemented.** All 4 findings below were addressed by a follow-up session and
> independently verified in [Round 4](#round-4--review-of-the-round-3-implementation).
> R3-1's fix is the most carefully done work of the whole effort — see round 4 for the
> before/after numbers.

## Verdict

All 13 round-2 findings are fixed, each verified by re-running the round-2 reproduction
rather than by reading the code. Both blockers were fixed at the root, not patched — the
mutating getter was deleted outright, and the engine gained a real lifecycle.

One new defect: the NEW-5 fix gave pending probes strict priority in a shared pacer, which
starves sweeps indefinitely instead. It is the mirror image of the bug it replaced, and it
is a bounded change to one function.

**Hold a commit for R3-1. R3-2 through R3-4 are tidy-ups.**

## Baseline measured at review time

```
gofmt -l ./cmd ./internal      clean
go vet ./...                   clean
go build ./...                 clean (darwin)
GOOS=windows go build ./...    BROKEN — see R3-2
go test ./...                  all 9 packages ok
go test -race ./...            all 9 packages ok
```

Coverage movement since round 2:

| Package | Round 2 | Round 3 |
|---|---|---|
| `internal/engine` | 57.7% | **68.9%** |
| `cmd/arpsponge` | 18.7% | **34.5%** |
| `internal/cliargs` | 93.3% | 94.1% |
| `internal/platform/unixsocket` | 88.0% | 74.5% |
| `internal/platform/linux` | 100.0% | 100.0% |
| `internal/netutil` | 82.9% | 82.9% |
| `internal/packet` | 64.1% | 64.1% |
| `internal/control` | 41.2% | 41.2% |
| `cmd/arpspongectl` | 5.2% | 5.2% |

The `unixsocket` drop is expected and fine — the `socketOps` injection seam and its tests
were deleted per NEW-8, so the remaining tests cover a smaller, simpler file.

### Extra verification run beyond the finding list

A 1.5-second six-way stress under `-race` — ARP and IPv4 packets, concurrent `Tick`,
`UpdateConfig` churning `Proberate`/`ArpAge`/`LearnSeconds`, API reads, and periodic
`ClearIPState`/`ClearAllState`/`ClearARP` — then `Stop()`:

```
Stop() returned cleanly under load
```

No races, no deadlock. Also confirmed independently: the pacer honors its configured rate
(5 grants at 50 q/s in 84ms), reconfiguring wakes blocked waiters rather than losing them,
`Stop()` is idempotent, `Tick`-after-`Stop` is safe, and ARP expiry works through the new
bucketed index.

---

## R3-1 — Sweeps are starved indefinitely by sustained pending probes

**Location:** `queryPacer.wait` in `internal/engine/engine.go`
**Severity:** medium. **Status:** VERIFIED

NEW-5 was fixed by giving pending probes strict priority in the shared pacer:

```go
if p.next.IsZero() || !now.Before(p.next) {
    if pending || p.pendingWaiters == 0 {
        // grant
    }
    // sweep waiter blocks on p.changed instead
}
```

A sweep waiter is granted only when `pendingWaiters == 0`. On a busy network — the
condition this daemon exists to handle — there is always pending work, so that never
happens. Strict priority with no aging.

Pacer level, four sustained probe waiters and one sweep waiter over 600ms:

```
probe grants=108   sweep grants=0
```

Engine level, a permanent 200-address pending backlog, 12 ticks:

```
sweepInProgress=true, addresses swept in first 500=1, total sends=108
```

The sweep goroutine parks inside `waitForProbeRate` and holds `sweepInProgress` true for as
long as the backlog lasts, so no later sweep starts either. `sweep_period` is silently not
honored — the same "knob that appears to work and does nothing" shape as round-1 finding 9.

**Why the existing tests miss it:** `TestSweepDoesNotStarvePendingProbes` and
`TestProbeAndSweepShareAggregateProbeRate` both use a **single transient** pending address,
so `pendingWaiters` drops to zero almost immediately and the starving case is never
reached. They prove a probe can preempt a sweep; they do not prove a sweep ever finishes.

**Fix:** deprioritizing sweeps is correct, starving them forever is not. Add aging — grant a
sweep waiter once it has waited past some bound — or reserve a fraction of the rate budget
for sweeps. Either keeps probe latency low while guaranteeing forward progress.

**Verify:** a test with a *sustained* pending backlog (not one address) asserting the sweep
makes measurable progress and that `sweepInProgress` returns to false. The two probes above
are the shape of it; both belong in the repo.

---

## R3-2 — `GOOS=windows go build ./...` is broken

**Location:** `cmd/arpsponge/main.go`, `internal/platform/unixsocket`, `internal/platform/linux/stub.go`
**Severity:** low. **Status:** VERIFIED

```
cmd/arpsponge/main.go:177:15: undefined: pidFile
cmd/arpsponge/main.go:179:18: undefined: acquirePIDFile
cmd/arpsponge/main.go:247:22: undefined: signalSet
cmd/arpsponge/main.go:260:7: undefined: isDumpSignal
```

The Windows files were deleted per NEW-8 — correct — but `main.go` still calls into them,
while `//go:build !windows` on `unixsocket` and `//go:build !linux` on the stub leave the
tree half-claiming Windows support.

For a libpcap-based ARP daemon, "does not build on Windows" is a fine outcome. Make it
deliberate rather than accidental so nobody adds a Windows CI job expecting green: either
constrain the remaining tags to the platforms actually supported, or note the intent in
`ARCHITECTURE.md`.

Keep `internal/platform/linux/stub.go` regardless — the `!linux` stub is what makes the
tree build and test on macOS, and that still works.

**Not a defect:** `GOOS=linux go build` from macOS fails on gopacket's cgo pcap bindings.
That is cross-compilation without cgo, not a code problem.

---

## R3-3 — NEW-3 was fixed for one binary only

**Location:** `cmd/arpspongectl/main.go`
**Severity:** low. **Status:** VERIFIED

```
$ arpsponge --help
Usage of arpsponge:
  -age int
        arp cache age seconds (default 600)
  ...                                          (exit 0)

$ arpspongectl --help
flag: help requested
usage: arpspongectl [--socket PATH|--interface IFACE] <command> [args]
  ...                                          (exit 2)
```

`arpspongectl` still leaks the raw `flag.ErrHelp` string and exits 2 for a successful help
request. Apply the same `errors.Is(err, flag.ErrHelp)` handling `arpsponge` now uses.

While there: a bad flag on `arpsponge` prints only `flag provided but not defined: -x` with
no pointer to `--help`. One extra line would close the loop.

---

## R3-4 — Nits

- `sendPendingProbe` returns a `bool` that its only call site discards
  (`internal/engine/engine.go`, in `probePending`). Either use it or return nothing.
- `processed` in `probePending` counts addresses that were skipped by the
  `!ok || state <= StateAlive` guard, so the "N pending address(es) processed" log
  overcounts.
- Missing blank line between `sweepIfNeeded` and `sendQuery` in `internal/engine/engine.go`.
  `gofmt` does not care; every other function boundary in the file has one.

---

## Round-2 scorecard

| # | Round-2 finding | Status |
|---|---|---|
| NEW-1 | Shutdown use-after-free | **Fixed** — `ctx`/`passWG`/`Stop()`, explicit shutdown order in `main`, plus `sendMu` in `pcap.go`. Verified: 0 sends after `Stop()` (was 1,264) |
| NEW-2 | Reads mutate state | **Fixed** — mutating getter deleted, materialization moved to the packet path. Verified pure under both `--init` modes |
| NEW-3 | `--help` gone | **Fixed** for `arpsponge`; not for `arpspongectl` — see R3-3 |
| NEW-4 | `--daemon` hard-fails | **Fixed** — deprecated no-op with warning, documented in README |
| NEW-5 | Sweep starves probes | **Fixed, but inverted** — see R3-1 |
| NEW-6 | O(n) expiry under lock | **Fixed** — bucketed expiry index with `nextARPExpiry` |
| NEW-7 | `ip clear` disables `--init` | **Fixed** — policy retained; single-address tombstone still works |
| NEW-8 | Over-engineering | **Fixed** — Windows files, `socketOps`, and both `cliargs` callbacks all gone |
| NEW-9 | Seam bypassed | **Moot** — seam removed entirely |
| NEW-10 | `dev` scan too loose | **Fixed** — CIDR validation added |
| NEW-11 | Umask undocumented | **Fixed** — package-level and function-level docs |
| NEW-12 | Silent parse failures | **Fixed** — `parseSweep` and `parseInitState` both return errors |
| NEW-13 | Undocumented changes | **Fixed** — `--age`, `--daemon`, `--init`, the pidfile sidecar, and the non-socket refusal all documented |

## Round-3 implementation order

> **Historical — this plan was carried out.** All four steps landed, and the R3-1 decision
> below was answered with "strict priority with aging". See Round 4.

| Step | Findings | Why here |
|------|----------|----------|
| 1 | R3-1 | The only behavioral defect. Bounded change to `queryPacer.wait` plus two tests with a sustained backlog. |
| 2 | R3-3 | Two-line fix, makes the binaries consistent. |
| 3 | R3-2 | Decide whether Windows is supported, then make the build tags say so. |
| 4 | R3-4 | Cosmetic. |

### Decision needed from the repo owner

**R3-1** — how should probe and sweep share the query budget? Options: strict priority with
aging (sweep waiter forced through after N seconds), or a fixed split (e.g. sweeps get 20%
of `proberate`). The first keeps probe latency lowest; the second makes `sweep_period` a
predictable guarantee. Either is defensible — pick one deliberately rather than leaving
sweeps at the mercy of load.

---
---

# Round 4 — review of the round-3 implementation

Review date: 2026-08-21. Reviewed against the **uncommitted working tree** containing the
round-1, round-2, and round-3 changes. Nothing in this round has been implemented.

## Verdict

All four round-3 findings are resolved. R3-1's fix is the most careful work of the effort:
it solved the fairness problem without breaking the rate cap, added the sustained-backlog
test that was specifically missing, and covered four edge cases that were not asked for.

**Nothing blocks a commit.** The single finding (R4-1) is documentation.

## Baseline measured at review time

```
gofmt -l ./cmd ./internal      clean
go vet ./...                   clean
go build ./...                 clean (darwin)
GOOS=windows go build ./...    fails — deliberate, see R3-2
go test ./...                  all 9 packages ok
go test -race ./...            all 9 packages ok
```

| Package | Round 3 | Round 4 |
|---|---|---|
| `internal/engine` | 68.9% | **70.3%** |
| `cmd/arpsponge` | 34.5% | 34.9% |
| `internal/control` | 41.2% | 41.2% |
| `cmd/arpspongectl` | 5.2% | 5.1% |

`cmd/arpspongectl` remains the thinnest-covered package in the tree. Not a finding — the
file is mostly HTTP plumbing — but it is where coverage would buy the most if anyone wants
to spend effort there.

---

## R3-1 verification — sweep starvation

The pacer gained aging: a sweep waiter that has waited `>= 10*interval` becomes eligible via
`oldestAgedSweepWaiterLocked`, and `pendingGrantRequired` then forces the following slot back
to a pending probe so a sweep cannot take two grants in a row.

| Measurement | Round 3 | Round 4 |
|---|---|---|
| Pacer: 600ms, 4 probe + 1 sweep waiter | 108 probe / **0** sweep | 97 probe / **11** sweep |
| Engine: 12 ticks, permanent 200-address backlog | **1** of first 500 swept | **11** swept |
| Pending address during a long sweep | DEAD | DEAD (NEW-5 not regressed) |

Two ways the fix could plausibly have gone wrong, both checked and both fine:

- **Aggregate rate cap holds.** 100 q/s with five probe waiters and one sweep waiter yields
  56 grants in 600ms (cap ~60). Every grant path sets `p.next = now.Add(p.interval)`, so the
  aged-sweep escape hatch cannot leak extra queries onto the wire.
- **Aging survives rate churn.** Swinging `proberate` from 50 to 490 q/s against live blocked
  waiters: 115 probe / 14 sweep grants, no hang, no lost wakeup.

A 2-second six-way `-race` stress — ARP and IPv4 packets, concurrent `Tick`, `UpdateConfig`
churning proberate/ArpAge/LearnSeconds/SweepPeriod, API reads, periodic clears — ends with
`Stop()` returning cleanly. No deadlock in the more elaborate pacer.

**The test gap is closed.** `TestDurableMultiAddressPendingBacklogAllowsSweepToFinish`
maintains a real backlog with a goroutine re-running `probePending` over five addresses,
asserts the sweep *completes* (`sweepInProgress` returns false), and asserts >= 20 pending
probes fired during it so the backlog was genuinely sustained. Four edge cases beyond what
was asked for: a later sweep not inheriting a granted waiter's age, not inheriting a canceled
waiter's age, restoring pending priority between independently aged sweeps, and tracking each
waiter's age against the *current* interval so a proberate change rebases it.

---

## R4-1 — The concurrency design is undocumented

**Location:** `ARCHITECTURE.md`, `internal/engine/engine.go` (`queryPacer`), `README.md`
**Severity:** low. **Status:** VERIFIED

`ARCHITECTURE.md` still describes the design that rounds 2 and 3 replaced:

```
## Concurrency Model
- One goroutine runs pcap capture and dispatches packets to the engine.
- A 1-second ticker drives periodic timers (pending probes, sweep).
- Control API serves concurrently via Go's HTTP server.
```

Nothing there is true of the current engine in the parts that matter. Undocumented:

- Probe and sweep run as **detached passes** started by `startPass`, guarded by separate
  `probeInProgress` / `sweepInProgress` flags so neither blocks the ticker or each other.
- `Engine.Stop()` is the **shutdown contract** — it cancels the pass context and waits on
  `passWG`, and `main` must call it before `capture.Close()`. This is what prevents the
  round-2 use-after-free (NEW-1); a future edit that reorders those calls reintroduces it.
- A shared `queryPacer` **splits the query budget**: probes take priority, sweeps age in
  after ten intervals, and the aggregate never exceeds `proberate`.

`queryPacer` also has no doc comment — the only explanation in the code is the two-line note
on `pendingGrantRequired`. And the README documents `--proberate` as "probe rate (q/s)"
without saying the budget is shared with sweeping, which is what determines whether
`--sweep`'s period is honored under load.

This is worth more than a routine doc nit for two reasons. `CLAUDE.md` instructs the next
person to read `ARCHITECTURE.md` before making structural changes, so a stale concurrency
section actively misleads exactly the reader who most needs it. And the pacer is now the
subtlest code in the repository — the reasoning is worth writing down while someone still
remembers it.

**Fix:**
1. Rewrite `ARCHITECTURE.md`'s Concurrency Model to describe passes, the `Stop()` contract
   (including the ordering requirement in `main`), and the shared pacer policy.
2. Add a doc comment on `queryPacer` covering priority, the `10*interval` aging rule, and
   the aggregate-rate guarantee.
3. Extend the README's `--proberate` line to say the budget is shared between pending probes
   and sweeping, with probes prioritized.

**Nit alongside it:** `//go:build !windows` on `cmd/arpsponge/pidfile_unix.go`,
`cmd/arpsponge/signals_unix.go`, and `internal/platform/unixsocket/socket.go` is vestigial
now that `ARCHITECTURE.md` declares Windows unsupported. The tags imply a portability the
tree no longer claims. Removing them is optional; leaving them is a small ongoing lie.

---

## Round-3 scorecard

| # | Round-3 finding | Status |
|---|---|---|
| R3-1 | Sweeps starved by sustained probes | **Fixed** — aging + `pendingGrantRequired`. Verified 11 sweep grants (was 0), 11 addresses swept (was 1), rate cap intact, survives rate churn |
| R3-2 | `GOOS=windows` build broken | **Resolved as documented** — `ARCHITECTURE.md` declares Windows unsupported. Build still fails, now intentionally |
| R3-3 | `--help` fixed for one binary only | **Fixed** — `arpspongectl --help` prints clean usage, exit 0; bad flags on `arpsponge` now point at `--help` |
| R3-4 | Nits | **Fixed** — all three: unused return removed, `processed` counts only real work, blank line restored |

## Round-4 implementation order

One item, three parts, no ordering constraint:

| Step | Finding | Why here |
|------|---------|----------|
| 1 | R4-1 | Documentation only. `ARCHITECTURE.md` first — it is the file `CLAUDE.md` points new contributors at. |

No decisions needed from the repo owner this round.

## Where this leaves the work

Four rounds, 38 findings, all resolved. The tree is clean under `gofmt`, `vet`, `test`, and
`-race`; engine coverage went from an unrunnable test package to 70.3%. The remaining work
is one documentation pass.

Worth remembering when this is finally committed: `cmd/` has never been in a commit — the
`.gitignore` bug found in round 2 was hiding it. The first commit that includes this work
will appear to add both binaries from nothing, so its message should say why.

---
---

# Round 5 — review of the round-4 implementation, and close-out

Review date: 2026-08-21. **No findings.** R4-1 is resolved; the review cycle is closed.

## What landed

Documentation plus one comment block. `internal/engine/engine.go` grew exactly the six lines
of the `queryPacer` doc comment — no code changed, and the test suite is untouched.

- **`ARCHITECTURE.md`** — Concurrency Model rewritten to cover detached passes via
  `startPass`, the two independent in-progress guards, the shared pacer policy, and the
  `Engine.Stop()` shutdown contract including *why* the ordering matters.
- **`queryPacer` doc comment** — priority, the ten-interval aging rule, the shared-slot
  guarantee, and why an aged sweep grant forces a pending grant next.
- **`README.md`** — `--proberate` now states the budget is aggregate and shared with
  sweeping, with pending probes prioritized.

They also added a clarification that was not asked for and is worth keeping: the in-progress
guards prevent overlapping passes *of the same kind*, not a probe pass and a sweep pass
running concurrently. That is exactly the detail a reader would otherwise get backwards.

## Verification

For a documentation round the question is whether the documentation is **true**, so the
claims were tested rather than read:

| Documented claim | Measured |
|---|---|
| "a sweep waiter becomes eligible after ten current pacing intervals" | 218ms against a documented 200ms at a 20ms interval |
| "sweeps cannot receive consecutive grants" | 33 sweep grants of 305 total, **zero** consecutive pairs |
| "zero disables pacing" | 10,000 grants in 16ms, all granted |
| main "cancels capture, calls `Engine.Stop()`, waits for the capture goroutine, then `capture.Close()`" | matches `cmd/arpsponge/main.go` exactly |

The structural claims — detached passes, independent guards, concurrent HTTP serving — are
true by construction in the code.

```
gofmt -l ./cmd ./internal      clean
go vet ./...                   clean
go build ./...                 clean (darwin)
go test ./...                  all 9 packages ok
go test -race ./...            all 9 packages ok
internal/engine coverage       70.5%
```

## Still open by choice

`//go:build !windows` on `cmd/arpsponge/pidfile_unix.go`, `cmd/arpsponge/signals_unix.go`,
and `internal/platform/unixsocket/socket.go` remains vestigial now that Windows is declared
unsupported. Flagged as optional in R4-1; left in place. Not a defect — just a tag that
implies a portability the tree no longer claims.

---

# Close-out

Five rounds, 39 findings, all resolved.

**Where it started:** the documented daemon invocation silently ignored every flag; the
documented `arpspongectl` invocation failed outright; flood protection collapsed queues so
sponged addresses could never be sponged; the engine's test package did not compile, so its
two tests had never run — and both failed when it did; and `cmd/` was invisible to git.

**Where it ended:** clean under `gofmt`, `vet`, `test`, and `-race`; engine coverage at
70.5%; a documented concurrency design with a shutdown contract that closes a cgo
use-after-free; and both binaries actually tracked in version control.

**Two defects were introduced by fixes and caught in later rounds** — a shutdown
use-after-free from the async-`Tick` fix (NEW-1), and read-only API calls mutating state and
emitting ARP traffic from the lazy-init fix (NEW-2). Both came from changes that solved the
reported symptom without tracing what else the change touched. That is the argument for the
review rounds having existed at all, and worth remembering the next time a fix in this
engine looks locally obvious.

**A note for whoever reads the history:** `cmd/` had never been committed before this work.
The `.gitignore` patterns `arpsponge` and `arpspongectl` were unanchored and matched the
`cmd/` **directories**, not just the built binaries at the repo root. Anchoring them with a
leading `/` is what made both programs visible to git. The commit that introduces this work
therefore appears to add both binaries from nothing; it did not — they were merely hidden.

This document is retained as the record of that work. Its "uncommitted working tree"
language throughout refers to the state at each review, not to the state of the repository
now.
