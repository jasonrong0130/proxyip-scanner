# Job Lifecycle Hardening Gate

This branch is a regression-hardening branch. It must not be merged until the lifecycle gate is green.

## User-visible lifecycle contract

The browser is only a control and query surface. Closing a tab, refreshing, logging out, or reopening the site must not stop a server-side task.

Primary scan states have explicit semantics:

- `queued/checking/runtime_checking`: running in the server background.
- `paused`: deliberately paused by the user. Progress/results are durable, the full in-memory payload is released, and the task can be continued later from unfinished work.
- `cancelled`: deliberately stopped by the user. This is final and is not resumable.
- `completed`: finished normally and remains queryable/filterable from history.
- `interrupted`: process/service interruption. This is not equivalent to user Stop and is resumable when the retained job size permits it.

Speed and purity post-processing keep their existing `speed_paused` / `purity_paused` semantics.

## Scope

Lifecycle hardening covers:

- live in-memory task ownership
- browser-independent background execution
- explicit primary Pause / Continue / Stop
- process-restart recovery
- primary scan and EDT interruption/resume
- speed/purity restart recovery
- primary-scan mutual exclusion
- paused/completed/cancelled memory release

Candidate-pool behavior, EDT pass/fail semantics, scan filtering, GeoIP/purity semantics, export semantics, and deployment defaults are otherwise unchanged.

## Source of truth

While a coroutine is running, the in-memory job object and its live asyncio task are authoritative.

Disk snapshots/checkpoints are recovery sources only. They must not overwrite a live job merely because the UI refreshed, login was renewed, the history list was opened, or `GET /api/jobs` was requested.

A deliberate Pause flushes the current checkpoint/snapshot before the job is converted to a lazy metadata stub, so an hours-long pause does not pin the full result set in RAM.

## Required invariants

For every job:

- `completed <= total`
- `runtime_completed <= runtime_total`
- `runtime_available <= runtime_completed`
- `final_available <= runtime_available` when EDT runtime verification is enabled
- EDT display semantics remain `runtime_available/runtime_total` (for example 55 passed out of 2487 attempted is a valid completed result)
- at most one held primary scan exists at a time
- a live task reference must never be replaced by a lazy history stub
- Pause lets in-flight probes finish, then stops taking new work
- Continue processes only unfinished work
- Stop is the only primary action that produces `cancelled`
- service/process cancellation must not be mistaken for user Stop
- EDT completion is durably checkpointed per row so abrupt restart cannot roll a partial EDT count back to the previous batch boundary
- paused, completed, cancelled, and interrupted jobs release full in-memory targets/results and remain lazy until opened/resumed
- EDT resume must process only base-available rows where `edt_available is None`
- already successful or failed EDT rows must not be re-counted
- a process restart during speed/purity must recover to a resumable paused state

## Regression matrix

1. checking + `GET /api/jobs` => remains checking, same live task object.
2. closing/reopening the browser requires no server lifecycle transition.
3. primary Pause => in-flight probes settle, state becomes `paused`, remaining work is retained.
4. paused job => full payload is released from `JOBS` and can be hydrated hours later.
5. Continue from `paused` => only unfinished base/EDT rows run.
6. Stop from running or paused => `cancelled`, not resumable.
7. process/service cancellation during primary scan => `interrupted`, not `cancelled`.
8. runtime_checking with partial EDT results => restart/resume only `edt_available is None`.
9. partial EDT progress below the normal checkpoint batch remains durable after abrupt process loss.
10. completed EDT result such as 55/2487 remains `completed`; pass count is not confused with processed count.
11. process restart during speeding => `speed_paused` with existing session recoverable after hydrate.
12. process restart during purity_checking => `purity_paused` with existing session recoverable after hydrate.
13. second primary scan while a running/paused primary exists => HTTP 409.
14. duplicate resume while an older primary task is still alive => HTTP 409.
15. primary Stop cancels and awaits the real asyncio task.

## Memory requirements

Lifecycle state must not retain a large completed/paused payload indefinitely:

- checkpoint buffers are bounded;
- EDT checkpoints flush durably per completed EDT row;
- paused/completed/cancelled/interrupted jobs are replaced by lightweight lazy stubs;
- opening historical results may hydrate temporarily, but the payload is released again afterward;
- `gc.collect()` is triggered when a full job is released.

Long-duration RSS soak measurement remains a deployment/staging verification item; it is not replaced by the structural memory tests above.

## Follow-up gate

Keep these separate from this lifecycle change unless a later phase explicitly approves them:

- bounded CIDR/job-size admission before expansion
- complete >50k export via paging/streaming, never silent truncation
- speed/purity append-only checkpointing instead of full-job rewrite per row
- long-duration RSS soak tests
- stale migration file cleanup

## Merge policy

The branch can be proposed for merge only after:

1. Python/shell/JavaScript validation passes;
2. all lifecycle and candidate-pool regression tests pass;
3. deterministic tests cover Pause -> Continue -> Stop and restart recovery;
4. counters remain monotonic and bounded;
5. paused/final jobs release their full in-memory payload;
6. no unrelated production behavior is changed.

Production `main` must remain untouched until this draft gate is explicitly approved for merge.
