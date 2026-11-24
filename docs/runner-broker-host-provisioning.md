# USC runner broker host provisioning — prototype only

**Do not install or start this service without separate deployment approval.**  
This runbook describes a dedicated Linux host configuration for the synthetic-only broker. It is not approval for customer-source execution or a production pilot.

## Preconditions

- Use a disposable or dedicated Linux host with systemd. Do not use a personal daily-use machine.
- Keep personal files, browser sessions, SSH keys, cloud credentials, and production secrets off the host.
- The broker accepts only synthetic metadata. It is not connected to Docker or the build runner.
- The standalone/broker Ed25519 verification path is implemented for synthetic requests, but an authenticated human-consent workflow, approval-authority governance, and independent security review are still required before customer-source work.

## Intended identities

- `usc-runner`: dedicated, non-login service UID. Owns the broker process and private SQLite state.
- `usc-clients`: restricted group used only to traverse the socket directory and connect to the socket.
- `usc-control`: dedicated non-login control-plane UID, member of `usc-clients`, and the only initial submitter UID.
- `usc-approver` (or a separately managed approval authority): separate identity that holds the Ed25519 private key. It is not a member of `usc-clients`, cannot access the broker state/socket, and its private key is never copied to the runner host.
- Neither service account should be a member of the Docker group or any unrelated privileged group.

Illustrative account creation commands (not executed by this project):

```sh
sudo groupadd --system usc-clients
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --user-group usc-runner
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid usc-clients usc-control
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --user-group usc-approver
id usc-runner
id usc-control
id usc-approver
```

Review the resulting numeric UIDs/GIDs and group memberships before proceeding. Do not add either account to `docker`, `sudo`, or broad administrative groups.

## Filesystem and socket ownership

The example systemd unit provisions:
- `/run/usc-runner`: owner `usc-runner`, group `usc-clients`, mode 2710. The client group can traverse but cannot list or modify the directory.
- `/run/usc-runner/runner.sock`: owner `usc-runner`, group `usc-clients`, mode 0660. Group access permits connecting; kernel `SO_PEERCRED` UID allowlists remain the authorization control.
- `/var/lib/usc-runner`: owner `usc-runner`, group `usc-clients`, mode 0700.
- `/var/lib/usc-runner/broker.sqlite3`: owner `usc-runner`, mode 0600, single link. The control-plane UID must not be able to read this database.
- `/var/lib/usc-runner/approval-public.pem`: trusted Ed25519 public key, owner `root` or `usc-runner`, a single-link regular file no larger than 4 KiB, and not group/world writable. Only the public key is installed here; the private key remains with the separate approval authority.

The broker refuses root execution, does not loosen pre-provisioned directory permissions, and fails closed if the group or state-directory policy does not match.

## Example installation sequence

1. Install the USC package into `/opt/usc/venv` using a reviewed, hash-locked build.
2. Create `/etc/usc-runner` as root-owned mode 0750.
3. Install the approval authority's public key at `/var/lib/usc-runner/approval-public.pem`; verify its fingerprint out of band. Never copy the private key to this host.
4. Copy `deploy/systemd/broker.env.example` to `/etc/usc-runner/broker.env`; set the numeric client-group GID, control-plane UID, and absolute public-key path.
5. Set the environment file owner to root and mode 0640.
6. Review `deploy/systemd/usc-runner-broker.service.example`; install it only after confirming systemd version support for every hardening directive.
7. Create `/etc/usc-runner/ENABLE_SYNTHETIC_ONLY` only after the operator explicitly decides to start the synthetic-only broker.
8. Run `systemctl daemon-reload`, then start the service manually. Do not enable automatic boot start during the prototype phase.

No command in this repository or CI performs these host changes.

## Lifecycle and operations

- The broker can run in the foreground as `python -m customizer.local_runner_broker` or through the installed `usc-runner-broker` entry point. Both accept only the fixed socket, state database, trusted approval public-key path, submitter UID, and operator UID settings; neither exposes a shell or build command.
- The sample unit uses `Restart=no`: after an unexpected exit, inspect the journal and state database before manually restarting.
- A graceful SIGTERM stops accepting new connections, allows the current request to finish, closes SQLite, and removes the socket. The CLI installs this signal handler; the ephemeral CI integration test exercises it.
- After SIGKILL, the socket path may remain stale; the broker checks whether it is live before removing an owned stale socket.
- SQLite schema v2 retains committed job, request, approval, and nonce replay records across normal restarts. Existing schema-v1 databases are rejected and require an explicit, reviewed state reset; the prototype does not silently migrate them. Power-loss/active-commit, disk-full, backup/restore, and retention behavior remain open tests.
- Review `journalctl -u usc-runner-broker` for startup/shutdown errors. Do not log request contents, credentials, or source material.
- Never grant access to `/var/run/docker.sock`, host paths, personal directories, or production secrets.

## Explicit non-goals and gates

This sample service:
- Does not execute commands or builds.
- Does not fetch repositories or accept source uploads.
- Does not export artifacts or authorize release/deployment.
- Verifies an Ed25519 signature from the configured approval key over the canonical job-bound request. This proves only that the key signed the request; it does not prove that a human personally approved it or that the approval authority's authentication/consent process is trustworthy.
- Is not a customer pilot or production service.

Before any customer-source pilot: complete independent security review, define an authenticated human-consent and approval-authority governance process, complete crash and storage fault testing, validate retention/deletion policy, review permanent host provisioning, and obtain explicit owner approval. Keep customer repositories disabled until those gates are satisfied.
