# USC Stage 1 — local Unix-socket broker prototype

**Status:** test-only local IPC prototype  
**Scope:** synthetic metadata requests and in-memory job state. No build execution.

## Local test deployment

The prototype broker:
- Listens on one Unix-domain stream socket.
- Default development mode requires a current-user-owned socket directory with no group/other permissions (0700) and creates a socket with mode 0600.
- Optional group mode requires an administrator-preprovisioned directory owned by the broker UID and configured client group with mode 2710 (setgid, owner rwx, group traverse only); it creates a socket with mode 0660. The broker never creates or loosens this shared directory.
- Both modes refuse to unlink a live socket and remove only an owned stale socket after a failed connection probe.
- Rejects root execution, bounds Unix socket path length, applies a per-connection timeout, and caps the in-memory registry at 1,000 jobs / 10,000 requests.
- Uses Linux kernel peer credentials (`SO_PEERCRED`) to obtain the connecting UID. If the platform cannot provide peer credentials, the request fails closed.
- Applies separate submitter and operator UID allowlists. Status, cancel, and result operations are checked against the job owner's UID or an operator UID for every request. Group membership permits connecting only; kernel-reported UID authorization remains mandatory.
- Accepts only the strict protocol contract defined in `customizer.runner_protocol`.
- Stores synthetic job metadata, request IDs, and approval IDs in memory only.
- Exposes status/cancel/result metadata only. It does not return artifacts.

## Service identity and permissions — important deployment limitation

The default local test mode runs as the current user with a 0700 directory / 0600 socket. The optional group mode supports a distinct runner UID and client group only when an administrator has provisioned the directory with the exact 2710 ownership/mode policy. The broker checks the connecting UID with kernel peer credentials; group membership alone never authorizes an operation.

CI includes an ephemeral Linux integration test that creates temporary runner, client, and unauthorized-client accounts. It starts the broker as the runner UID, verifies that the client can connect through the group socket but cannot list the socket directory or read a runner-private synthetic key file, and confirms that an unapproved UID in the same group is denied. It also verifies that the runner/client accounts are not members of the Docker group and cannot read a Docker socket when one is present. These accounts are removed after the test.

This is a test of the proposed OS permission boundary, not a persistent installation or production service. A future service deployment must still provision and manage its own identities. Before such a deployment, define and test:
- A dedicated runner service UID with no interactive login and no membership in unrelated groups.
- A dedicated client/control-plane group and explicit UID allowlists.
- A socket directory provisioned by an administrator with mode 2710, owned by the runner UID and client group; the client can traverse but cannot list or modify the directory.
- A socket mode/group policy of 0660 consistent with the actual OS account/group layout; explicit UID allowlists remain the authorization control.
- Separate runner-private state/workspace directories that are not traversable by the control-plane identity.
- Service startup ordering, stale-socket handling, restart behavior, graceful shutdown, audit logging, and cleanup ownership.
- Explicit proof that the control-plane UID cannot read real runner keys/replay state or access the Docker socket in the intended deployment.

The ephemeral CI test proves the fixture-level boundary only. It does not provision permanent users/groups or install a system service. Host root and administrators remain trusted.

## Security and functional limitations

- The in-memory job registry and replay sets disappear on restart; this is not durable replay protection or crash recovery.
- The broker does not verify a signed approval or independently authenticate a human approver.
- A queued job is only a synthetic record. No process is started, no Docker daemon is contacted, no source path is opened, and no artifact is produced.
- Cancellation only changes the synthetic queued state.
- Result lookup reports `result_available: false`.
- No source upload, VM orchestration, cross-host transport, or customer repository is supported.
- The current service is single-threaded and intended only for local tests.

## Stage 1 next gates

1. Review the ephemeral CI evidence and finalize an administrator-run service UID/group provisioning and lifecycle plan.
2. Add persistent, broker-owned replay/job state only after defining crash-safe atomicity and retention.
3. Add lifecycle, crash, malformed-stream, duplicate-operation, and cleanup-failure tests.
4. Keep Docker and the existing build runner disconnected until the independent service identity and approval model have been reviewed.
