topic: |
  full read the recent review and perform remediation, use sub-agents as needed and determine which model to use based on your own judgement

## G1: Resolve all eight findings in REVIEW-2026-09-08.md with source-backed fixes and regression coverage.
signal: test

## G2: Preserve pacing fairness, sparse initial-state behavior, clear-versus-send synchronization, passive/dummy semantics, and safe shutdown.
signal: test

## G3: Validate startup and runtime configuration consistently and atomically; reject invalid CLI input before any request.
signal: test

## G4: Verify portable tests, race tests, vet, lint, build, and formatting; add Linux libpcap CI and explicitly report any unexecuted Linux runtime checks.
signal: command

## G5: Review the integrated fixes, preserve unrelated work and the source review, and record completion evidence and remaining limitations.
signal: test

