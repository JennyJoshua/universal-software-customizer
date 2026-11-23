# Stage 1 — local runner protocol prototype

**Status:** first implementation batch; synthetic fixtures only  
**Scope:** strict protocol contract and authorization primitives. This is not yet a running service or an execution boundary.

## What this batch establishes

- A bounded UTF-8 JSON message contract with duplicate-key rejection and a 16 KiB ceiling.
- Exact field sets and protocol-version checks; unknown fields fail closed.
- Only four operations are represented: `submit`, `status`, `cancel`, and `result`.
- A submit message carries a content digest, fixed profile ID, digest-pinned build/exporter images, policy version, expiry, and an explicit no-release flag.
- It cannot carry a shell command, Docker flags, host path, environment variables, output destination, registry credentials, or publish/deploy instruction.
- Status, cancel, and result messages identify a job but do not authorize access to it.
- Operation-level authorization uses a peer UID supplied by a trusted local transport. The broker must resolve the job's owner UID from its own protected state before authorizing status/cancel/result.

## What this batch does not establish

- No Unix socket listener, service account, directory layout, permission installation, lifecycle manager, or OS-level isolation is implemented yet.
- The peer UID is not authenticated by this module. A future socket adapter must obtain it from kernel peer credentials (for example, Linux `SO_PEERCRED`), never from JSON supplied by the caller.
- The prototype does not move the approval key or replay ledger out of the current user account.
- No build is executed and no source is fetched or transferred.
- Same-host process separation does not protect against host root or a privileged administrator.

## Next Stage 1 batch

Add a minimal local Unix-domain socket broker and client around this contract, using a private socket directory and kernel peer credentials. Keep the broker in test mode: accept/reject synthetic requests and maintain an in-memory job registry only. Do not connect it to Docker, the existing build runner, customer repositories, or artifact export until a separate review of the service identity and filesystem ownership model is complete.

Run the focused protocol tests and the full existing suite in CI before expanding the prototype.
