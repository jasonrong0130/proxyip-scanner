# Job Lifecycle Hardening Gate

This branch is a regression-hardening branch. It must not be merged until the lifecycle gate is green.

## Scope freeze

Do not change candidate-pool behavior, EDT protocol semantics, UI layout, scan filtering, GeoIP/purity semantics, or deployment defaults while fixing this gate.

The first phase is limited to task lifecycle correctness:

- live in-memory task ownership
- process-restart recovery
- primary scan interruption/resume
- EDT runtime interruption/resume
- speed/purity restart recovery
- primary-scan mutual exclusion
- cancel semantics

## Source of truth

While the process is alive, the in-memory job object and its live asyncio task are authoritative.

Disk snapshots/checkpoints are recovery sources only. They must not overwrite a live job merely because the UI refreshed, login was renewed, the history list was opened, or /api/jobs was requested.

Only startup/recovery code may convert a persisted in-flight state into an interrupted or paused recovery state.

## Required invariants

For every job:

- completed <= total
- runtime_completed <= runtime_total
- runtime_available <= runtime_completed
- final_available <= runtime_available when EDT runtime verification is enabled
- at most one live primary scan task exists
- a live task reference must never be replaced by a lazy history stub
- resume must never start while an older primary task is still alive
- EDT resume must process only base-available rows where edt_available is None
- already successful or failed EDT rows must not be re-counted
- a process restart during speed/purity must recover to a resumable paused state, not a dead interrupted state

## Phase-1 regression matrix

1. checking + GET /api/jobs => remains checking, same live task object.
2. checking interruption => resume only unfinished base rows.
3. runtime_checking with partial EDT results => resume only edt_available is None.
4. runtime counters after resume satisfy all invariants.
5. process restart during speeding => speed_paused with existing speed_session recoverable after hydrate.
6. process restart during purity_checking => purity_paused with existing purity_session recoverable after hydrate.
7. second primary POST /api/jobs while one is active => HTTP 409.
8. resume while an old primary task is still alive => HTTP 409.
9. primary cancel => actual asyncio task is cancelled and awaited.

## Phase-2 gate after lifecycle is stable

Do not mix these changes into Phase 1:

- bounded CIDR/job-size admission before expansion
- complete >50k export via paging/streaming, never silent truncation
- speed/purity append-only checkpointing instead of full-job rewrite per row
- memory/RSS soak tests
- stale migration file cleanup

## Merge policy

The branch can be proposed for merge only after:

1. existing CI remains green;
2. all lifecycle regression tests pass;
3. no unrelated production file is changed;
4. a production-like copied job is tested through start -> refresh -> interrupt -> restart -> resume -> cancel;
5. counters remain monotonic and bounded;
6. no duplicate live primary task is observed.
