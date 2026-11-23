# USC runner broker host provisioning — prototype only

**Do not install or start this service without separate deployment approval.**  
This runbook describes a dedicated Linux host configuration for the synthetic-only broker. It is not approval for customer-source execution or a production pilot.

## Preconditions

- Use a disposable or dedicated Linux host with systemd. Do not use a personal daily-use machine.
- Keep personal files, browser sessions, SSH keys, cloud credentials, and production secrets off the host.
- The broker accepts only synthetic metadata. It is not connected to Docker or the build runner.
- A separate independent security review and approval-signature design are still required before customer-source work.

## Intended identities

- `usc-runner`: dedicated, non-login service UID. Owns the broker process and private SQLite state.
- `usc-clients`: restricted group used only to traverse the socket directory and connect to the socket.
- `usc-control`: dedicated non-login control-plane UID, member of `usc-clients`, and the only initial submitter UID.
- Neither service account should be a member of the Docker group or any unrelated privileged group.

Illustrative account creation commands (not executed by this project):

```sh
sudo groupadd --system usc-clients
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --user-group usc-runner
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid usc-clients usc-control
id usc-runner
id usc-control
```

Review the resulting numeric UIDs/GIDs and group memberships before proceeding. Do not add either account to `docker`, `sudo`, or broad administrative groups.

## Filesystem and socket ownership

The example systemd unit provisions:
- `/run/usc-runner`: owner `usc-runner`, group `usc-clients`, mode 2710. The client group can traverse but cannot list or modify the directory.
- `/run/usc-runner/runner.sock`: owner `usc-runner`, group `usc-clients`, mode 0660. Group access permits connecting; kernel `SO_PEERCRED` UID allowlists remain the authorization control.
- `/var/lib/usc-runner`: owner `usc-runner`, group `usc-clients`, mode 0700.
- `/var/lib/usc-runner/broker.sqlite3`: owner `usc-runner`, mode 0600, single link. The control-plane UID must not be able to read this database.

The broker refuses root execution, does not loosen pre-provisioned directory permissions, and fails closed if the group or state-directory policy does not match.

## Example installation sequence

1. Install the USC package into `/opt/usc/venv` using a reviewed, hash-locked build.
2. Create `/etc/usc-runner` as root-owned mode 0750.
3. Copy `deploy/systemd/broker.env.example` to `/etc/usc-runner/broker.env`; set the numeric client-group GID and control-plane UID.
4. Set the environment file owner to root and mode 0640.
5. Review `deploy/systemd/usc-runner-broker.service.example`; install it only after confirming systemd version support for every hardening directive.
6. Create `/etc/usc-runner/ENABLE_SYNTHETIC_ONLY` only after the operator explicitly decides to start the synthetic-only broker.
7. Run `systemctl daemon-reload`, then start the service manually. Do not enable automatic boot start during the prototype phase.

No command in this repository or CI performs these host changes.

## Lifecycle and operations

- The sample unit uses `Restart=no`: after an unexpected exit, inspect the journal and state database before manually restarting.
- A graceful SIGTERM stops accepting new connections, allows the current request to finish, closes SQLite, and removes the socket.
- After SIGKILL, the socket path may remain stale; the broker checks whether it is live before removing an owned stale socket.
- SQLite retains committed job and replay records across normal restarts. Power-loss/active-commit, disk-full, backup/restore, and retention behavior remain open tests.
- Review `journalctl -u usc-runner-broker` for startup/shutdown errors. Do not log request contents, credentials, or source material.
- Never grant access to `/var/run/docker.sock`, host paths, personal directories, or production secrets.

## Explicit non-goals and gates

This sample service:
- Does not execute commands or builds.
- Does not fetch repositories or accept source uploads.
- Does not export artifacts or authorize release/deployment.
- Does not verify an independently signed human approval.
- Is not a customer pilot or production service.

Before any customer-source pilot: complete independent security review, approval-authority signing/verification, crash and storage fault testing, retention/deletion policy validation, permanent host provisioning review, and explicit owner approval. Keep customer repositories disabled until those gates are satisfied.
