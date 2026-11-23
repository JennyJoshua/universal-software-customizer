# Stage 1 — local runner separation prototype

**Status:** protocol contract and test-only local socket broker implemented  
**Scope:** synthetic metadata requests and in-memory job state. No build execution.

## Batch 1 — strict protocol contract

- A bounded UTF-8 JSON message contract with duplicate-key rejection and a 16 KiB ceiling.
- Exact field sets and protocol-version checks; unknown fields fail closed.
- Only four operations: `submit`, `status`, `cancel`, and `result`.
- Submit carries a content digest, fixed profile ID, digest-pinned build/exporter images, policy version, expiry, and an explicit no-release flag.
- The message cannot carry shell commands, Docker flags, host paths, environment variables, output destinations, registry credentials, or publish/deploy instructions.
- Status, cancel, and result identify a job but do not authorize access to it.
- CI #319 passed after malformed-type and non-standard JSON regression tests were added.

## Batch 2 — local Unix-domain socket broker

- A test-only broker and client communicate over a Unix-domain stream socket.
- The broker requires a current-user-owned private directory (0700) and creates a current-user-owned socket (0600).
- Linux `SO_PEERCRED` supplies the connecting UID; platforms without kernel peer credentials fail closed.
- Separate submitter/operator UID allowlists are applied; status, cancel, and result are checked against the job owner or an operator on every request.
- Duplicate request IDs and approval IDs are rejected during the broker process lifetime.
- The in-memory registry accepts synthetic jobs, reports status, marks queued jobs cancelled, and reports no result artifacts.

## What this prototype does not establish

- The broker still runs as the current user. It does **not** create separate control-plane and runner OS accounts, group provisioning, or a protected runner identity.
- The peer UID is trustworthy only because the socket adapter reads it from the kernel; callers cannot supply it in JSON.
- Job and replay state are in memory and disappear on restart. This is not durable replay protection or crash recovery.
- The broker does not verify an independently signed approval or prove human consent.
- No Docker daemon is contacted, no command is run, no source path is opened or transferred, and no artifact is produced.
- Same-host process separation does not protect against host root or a privileged administrator.

See [the broker deployment and permission limitations](local-runner-broker-prototype.md) before considering a separate service identity.

## Next Stage 1 gates

1. Review and implement a dedicated service UID/group and filesystem ownership model without granting the control plane access to runner keys, replay state, workspace, or Docker authority.
2. Define crash-safe, broker-owned persistent job/replay state and retention before implementing persistence.
3. Add service lifecycle, crash/restart, malformed-stream, duplicate-operation, and cleanup-failure coverage.
4. Keep Docker and the existing build runner disconnected until the independent service identity and approval model have been reviewed.
