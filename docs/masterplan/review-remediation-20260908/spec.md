# September 8 review remediation

Status: scope and goals approved by the user on September 8, 2026.

Source: `REVIEW-2026-09-08.md`. Verify each finding against current source and reproduce failures before changing behavior. Address all eight findings, preserving existing pacing fairness, sparse initial state, and clear-versus-send synchronization.

## Required behavior

1. **R1 — Gratuitous ARP:** State transitions must complete without recursive locking. Send announcements outside the engine state mutex, preserve dummy suppression, and retain tracked shutdown semantics.
2. **R2 — Probe accounting:** Only successful active transmissions advance pending counts. Preserve passive and dummy simulation, one response cycle after the last probe, and pending-episode identity across clear/re-pending races. Failed sweeps must not count as successful or postpone their targets. Report transmission errors with bounded repetition.
3. **R3 — Capture supervision:** Use a tracked synchronous reader, continue on read timeouts, surface terminal failures, and treat unexpected capture termination as daemon failure. Cancel and join users before closing the capture handle.
4. **R4 — Socket ownership:** Hold a persistent sidecar lock for the listener lifetime. Refuse live or uncertain existing sockets, recover demonstrably stale sockets, and preserve filesystem protections and idempotent cleanup. Update documented replacement behavior.
5. **R5 — Log following:** Use a streaming client without a total request timeout while retaining bounded connection and header waits. Flush initial headers, support cancellation and JSON events, and propagate connection, HTTP, and read failures to the CLI exit status.
6. **R6 — Configuration validation:** Share pure, field-specific validation between startup and atomic runtime updates. Reject invalid ranges, nonfinite rates, and overflowing durations; preserve documented zero values and safely handle very small positive probe rates.
7. **R7 — Configuration arguments:** Track explicitly supplied flags, reject malformed booleans/numbers and extra arguments before sending requests, and preserve explicit false and zero values.
8. **R8 — Logging masks:** Apply normal negation to `all`, preserving `none`, `!none`, and empty-input behavior.

## Execution and ownership

Keep engine transition/accounting work ordered R1 then R2. Coordinate R6 with that engine ownership and with startup changes for R3. Socket, logging-mask, and CLI work may be delegated independently with explicit file ownership. Choose available models by task complexity: stronger reasoning for concurrency and lifecycle changes; Terra for bounded CLI/parser and filesystem changes. Use independent review after integration.

## Verification

Add regression tests for each review acceptance criterion, including blocked senders, episode changes, cancellation, concurrent socket starts, stream duration, invalid configuration atomicity, and mask negation. Run focused tests during implementation, then the full test suite, race tests, vet, lint, build, and formatting checks. Add Linux CI with libpcap development headers and exercise capture cancellation/shutdown there where a Linux runner is available. Report any Linux runtime checks that cannot be executed locally as outstanding rather than claiming success.

Use a dedicated remediation worktree under Masterplan. Preserve the untracked source review. Keep code and workflow-state commits separate. Resolve branch disposition at the workflow's final gate.
