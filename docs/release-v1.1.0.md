# ProxyIP Scanner v1.1.0

Release date: 2026-09-13

## Highlights

This release focuses on task lifecycle correctness, memory reclamation and explicit history cleanup.

### Memory and cancellation fixes

- Primary scan cancellation now cancels and awaits the running asyncio task before returning.
- Cancelled/interrupted scans no longer keep full target/result payloads pinned in the global job registry.
- Job execution has a unified cancellation/error cleanup wrapper.
- Finished jobs are reduced to lightweight lazy stubs and hydrate only when history results are opened.
- EDT-stage cancellation follows the same cleanup lifecycle.
- Stable completed/cancelled history no longer replays large checkpoint journals on every service startup.
- Upgrade readiness polling now waits up to 30 seconds before reporting failure.

### History cleanup

The task history UI now supports:

- deleting a single inactive historical task;
- one-click cleanup of all inactive history tasks.

Deletion permanently removes:

- in-memory job references;
- post-speed/purity task registry references;
- task JSON snapshots;
- metadata files;
- checkpoint journals;
- stored scan, EDT, speed and purity results contained in the job files.

Running and paused tasks are protected from accidental history deletion and must be stopped first.

## Upgrade

On an existing installation:

```bash
cd /opt/proxyip-scanner
bash update.sh
```

After upgrading, confirm the service reports v1.1.0:

```bash
curl -fsS http://127.0.0.1:8788/health
```

## Notes

Python and the system allocator may keep already-freed heap pages reserved for future reuse, so process RSS does not always fall by exactly the amount of deleted job data immediately. The v1.1.0 cleanup guarantees that deleted or finished jobs are no longer strongly retained by the application and their persisted history files are removed when explicitly deleted.
