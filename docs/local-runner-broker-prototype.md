# USC Stage 1 — local Unix-socket broker prototype

**Status:** test-only local IPC prototype  
**Scope:** synthetic metadata requests and in-memory job state. No build execution.

## Local test deployment

The prototype broker:
- Listens on one Unix-domain stream socket.
- Requires a current-user-owned socket directory with no group/other permissions (0700).
- Creates a current-user-owned socket with mode 0600; refuses to unlink a live socket and removes only an owned stale socket after a failed connection probe.
- Rejects root execution, bounds Unix socket path length, applies a per-connection timeout, and caps the in-memory registry at 1,000 jobs / 10,000 requests.
- Uses Linux kernel peer credentials (`SO_PEERCRED`) to obtain the connecting UID. If the platform cannot provide peer credentials, the request fails closed.
- Applies separate submitter and operator UID allowlists. Status, cancel, and result operations are checked against the job owner's UID or an operator UID for every request.
- Accepts only the strict protocol contract defined in `customizer.runner_protocol`.
- Stores synthetic job metadata, request IDs, and approval IDs in memory only.
- Exposes status/cancel/result metadata only. It does not return artifacts.

## Service identity and permissions — important deployment limitation

This test implementation deliberately runs as the current user and uses a 0700 directory / 0600 socket. It demonstrates kernel peer-credential use and message authorization, but **does not yet create separate control-plane and runner OS accounts**.

A future service deployment must not simply loosen these permissions. Before a separate-identity deployment is attempted, define and test:
- A dedicated runner service UID with no interactive login and no membership in unrelated groups.
- A dedicated client/control-plane group and explicit UID allowlists.
- A socket directory provisioned by an administrator with the minimum traversal/write permissions needed for the client to connect but not list or modify runner-owned state.
- A socket mode/group policy consistent with the actual OS account/group layout.
- Separate runner-private state/workspace directories that are not traversable by the control-plane identity.
- Service startup ordering, stale-socket handling, restart behavior, graceful shutdown, audit logging, and cleanup ownership.
- Explicit proof that the control-plane UID cannot read runner keys/replay state or access the Docker socket.

Do not infer those properties from the current single-user prototype. Host root and administrators remain trusted.

## Security and functional limitations

- The in-memory job registry and replay sets disappear on restart; this is not durable replay protection or crash recovery.
- The broker does not verify a signed approval or independently authenticate a human approver.
- A queued job is only a synthetic record. No process is started, no Docker daemon is contacted, no source path is opened, and no artifact is produced.
- Cancellation only changes the synthetic queued state.
- Result lookup reports `result_available: false`.
- No source upload, VM orchestration, cross-host transport, or customer repository is supported.
- The current service is single-threaded and intended only for local tests.

## Stage 1 next gates

1. Review the service UID/group and filesystem ownership plan before changing from same-user mode.
2. Add persistent, broker-owned replay/job state only after defining crash-safe atomicity and retention.
3. Add lifecycle, crash, malformed-stream, duplicate-operation, and cleanup-failure tests.
4. Keep Docker and the existing build runner disconnected until the independent service identity and approval model have been reviewed.
