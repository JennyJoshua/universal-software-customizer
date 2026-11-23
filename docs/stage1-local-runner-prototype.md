# Stage 1 — local runner separation prototype

**Status:** protocol, test-only Unix socket broker, and ephemeral separate-identity tests implemented  
**Scope:** synthetic metadata requests and broker-owned state only. No build execution.

## Batch 1 — strict protocol contract (PR #87; CI #319)

- Bounded UTF-8 JSON messages with duplicate-key rejection and a 16 KiB ceiling.
- Exact field sets and protocol-version checks; unknown fields fail closed.
- Only four operations: `submit`, `status`, `cancel`, and `result`.
- Submit carries a content digest, fixed profile ID, digest-pinned build/exporter images, policy version, expiry, and an explicit no-release flag.
- No shell commands, Docker flags, host paths, environment variables, output destinations, registry credentials, or publish/deploy instructions are accepted.

## Batch 2 — local Unix-domain socket broker (PR #88; CI #330)

- Test-only broker/client over a Unix-domain stream socket; Linux `SO_PEERCRED` supplies the connecting UID.
- Private development mode uses a service-owned 0700 directory and 0600 socket.
- Group mode uses an administrator-preprovisioned service-owned 2710 directory and 0660 socket; the group permits connection but does not grant authorization.
- Separate submitter/operator UID allowlists and per-operation job-owner checks.
- Duplicate request and approval IDs are rejected; message sizes, connections, jobs, and requests are bounded.
- Unknown-job and unauthorized-job responses are deliberately indistinguishable.
- No Docker, shell execution, source transfer, or artifact export.

## Batch 3 — separate OS identities (PR #89; CI #338)

- An ephemeral Linux CI test creates temporary runner, client, and unauthorized-client accounts and a dedicated group.
- The broker runs under the runner UID; the control-plane UID connects through the group socket but cannot list the socket directory or read runner-private fixture state.
- A different UID in the same group is denied by kernel peer-UID policy.
- The test verifies runner/client accounts are not in the Docker group and cannot read a Docker socket when present.
- Temporary accounts, groups, and fixtures are removed after the test; no permanent host accounts are provisioned.

## Batch 4 — durable broker-owned replay state (in progress)

- Group-access mode now requires a SQLite database in a runner-owned 0700 directory; the database must be a single-link runner-owned regular file with mode 0600.
- SQLite uses explicit write transactions, unique request/approval IDs, full synchronous commits, rollback journaling, schema versioning, and a startup integrity check.
- Job state and replay identifiers survive normal broker restarts; the control-plane identity cannot read the database in the ephemeral CI fixture.
- The private same-user development mode may still run in memory unless a database path is supplied.

## What this prototype does not establish

- The broker does not verify an independently signed approval or prove human consent; an approval ID is only a replay identifier at this stage.
- Corrupt database startup is rejected, and an injected mid-submit failure proves the transaction rolls back both the job and replay record.
- Recovery during an active commit or power loss, disk-full conditions, backup/restore, retention, and long-duration stress still require testing.
- Permanent OS users/groups, a systemd unit, host provisioning, and production service lifecycle are not installed.
- No Docker daemon is contacted, no command is run, no source path is opened or transferred, and no artifact is produced.
- Same-host process/account separation does not protect against host root, kernel compromise, or a privileged administrator.

## Next Stage 1 gates

1. Test abrupt process termination, SQLite recovery, corruption handling, capacity exhaustion, retention, and cleanup failure.
2. Finalize administrator-run service UID/group provisioning, systemd lifecycle, logging, and cleanup documentation without enabling customer execution.
3. Add protocol fuzzing and independent approval-signature verification before treating approvals as external consent.
4. Obtain independent security review before any customer-source pilot; customer repositories remain disabled.


## Batch 6 — service lifecycle and host configuration examples (in progress)

- Adds a foreground `usc-runner-broker` CLI entry point with fixed socket/state/UID arguments only; it exposes no shell or build command.
- SIGTERM/SIGINT stop new accepts, allow an active request to finish, close SQLite, and remove the socket.
- Adds a guarded, hardened systemd example and a host-provisioning runbook. The example requires an explicit `ENABLE_SYNTHETIC_ONLY` marker and uses `Restart=no`.
- CI checks the service configuration and exercises graceful shutdown using temporary service accounts.
- No permanent users/groups are created by the repository, and no unit is installed, enabled, or started on a real host.

