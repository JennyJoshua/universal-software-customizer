# USC Runner Isolation Boundary — Architecture Design

**Status:** Architecture direction approved by project owner; Stage 1 implementation in progress  
**Date:** 23 November 2026  
**Scope:** Approved architecture baseline and staged synthetic-only implementation gates  
**Safety posture:** Synthetic fixtures only. Customer repositories remain disabled. No API, SaaS endpoint, deployment, artifact release, or production execution is introduced.

## 1. Executive decision

The current runner has meaningful container-level controls, but it shares a local trust domain with the invoking Python user and a Docker daemon that is powerful enough to affect the host. Renaming the low-level function or starting it in another Python process does not solve those trust problems.

The recommended target is a separate, disposable runner environment with an independently controlled service identity and execution daemon. The control plane must not have access to the runner's Docker socket, HMAC key, replay ledger, or writable workspaces. It may submit only a small, typed, bounded build request through an authenticated local transport. The runner independently validates the request and enforces the fixed policy.

For stronger protection against a compromised build or runner, use a disposable VM per job (or an equivalent isolated host/VM boundary) and destroy it after the job. A separate OS account on the same host is a useful interim separation only when the host administrator is trusted; it is not equivalent to a disposable VM.

The project owner has approved this architecture direction. Stage 1 may proceed only within its synthetic-only gates. This approval does not authorize customer-source execution, a production service, Stage 2 VM provisioning, release, or deployment.

## 2. Current trust-boundary gaps

The present implementation:
- Consumes a short-lived, HMAC-authenticated, single-use approval receipt before routing through the supported CLI.
- Uses fixed named command profiles, digest-pinned images, bounded execution, network-disabled containers, read-only source/root mounts, and a restricted output-export helper.
- Keeps the low-level Python runner underscore-prefixed, but Python naming conventions do not prevent deliberate imports or same-process tampering.
- Stores the local approval key and replay state under the invoking OS user's control. A process running as that same user can potentially alter the code, key, state, receipt, or Docker state.
- Uses a Docker daemon whose administrator is effectively trusted with host-level authority. Container flags do not defend against a hostile or compromised daemon/host administrator.
- Produces consistency-checked but unsigned provenance. It is not independent proof of producer identity.
- Uses finite source-secret detection and best-effort log redaction. Neither can prove a source tree or output is secret-free.

The existing live Docker smoke test is useful runtime evidence, not a container-escape test, independent penetration test, or general security certification.

## 3. Target architecture

### 3.1 Components and responsibilities

1. **User / approval client**
   - Displays the exact source identity, profile, image digest, limits, and expiry before requesting approval.
   - Requires an explicit owner action for each build request.
   - Does not accept arbitrary shell strings, arbitrary Docker arguments, arbitrary host paths, or caller-selected resource ceilings.

2. **Control plane**
   - Runs under a distinct, unprivileged OS identity.
   - Authenticates the caller and checks that the caller may request the named operation.
   - Creates a canonical, versioned request and records an audit event.
   - Has no membership in the runner's Docker group and no access to the Docker socket, runner signing key, replay ledger, or runner-private workspace.
   - Cannot execute builds directly and cannot fall back to local host execution.

3. **Narrow request transport**
   - Prefer a Unix-domain socket on a single host, protected by filesystem permissions and peer-credential checks; for a VM boundary, use a mutually authenticated, encrypted channel.
   - Accepts only a strict, versioned request schema with bounded field lengths and enumerations.
   - Rejects unknown fields, duplicate JSON keys, invalid encodings, path traversal, symlinks, unsupported profiles, oversized payloads, and unexpected protocol versions.
   - Exposes only submit/status/cancel/result operations. It is not a shell, generic RPC, Docker proxy, file browser, or arbitrary command endpoint.
   - Authorizes each operation independently: a requester may inspect only jobs they are entitled to see; cancellation is limited to an authorized job owner/operator; result retrieval is read-only and scoped to that job. Request IDs are not bearer credentials.
   - Treats source transfer as a separate bounded protocol operation, not an arbitrary path supplied in the build request. The trusted staging component validates and snapshots the source, then transfers a content-addressed immutable object into runner-controlled staging. Enforce upload size/file-count limits, timeouts, integrity checks, and per-job quotas; never expose a host filesystem path to the caller.

4. **Runner broker**
   - Runs under a dedicated service identity, separate from the control plane and ordinary user account.
   - Independently authenticates and validates each request.
   - Owns the approval verification key and atomic replay ledger; neither is readable or writable by the control plane, build container, or ordinary user.
   - Maps a profile identifier to a server-side fixed command and policy. Caller-supplied command arrays are never executed.
   - Enforces expiry, one-time nonce/approval ID, source digest, image digest, resource limits, timeout, output limits, and no-release policy.
   - Emits an audit record for accepted, rejected, started, cancelled, completed, timed-out, and cleanup-failed jobs.

5. **Disposable execution environment**
   - Preferred: a fresh VM or equivalently isolated runner host per job, destroyed after results are safely collected.
   - The runner's daemon is inside that isolated environment. No host Docker socket is mounted into the build container or exposed to the control plane.
   - Inside the disposable environment, retain the current defense-in-depth container controls: no network, non-root, read-only root and source, dropped capabilities, no-new-privileges, cgroup limits, bounded tmpfs output, timeout, and bounded logs.
   - If a same-host interim mode is considered, use a dedicated OS account and rootless daemon owned by that account where feasible. Treat this as weaker than VM isolation; do not claim it protects against host administrators or kernel/runtime compromise.

6. **Result and artifact broker**
   - Collects only bounded, regular files from the designated output location.
   - Rejects symlinks, hard links where policy requires, special files, path traversal, excessive file counts/sizes, and collisions.
   - Recomputes artifact hashes and produces evidence bound to the accepted request and exact source snapshot.
   - Returns results through a read-only result interface. Artifact release or deployment remains a separate, explicit future approval.

### 3.2 Request contract

A request should contain only policy inputs, for example:
- schema_version
- request_id (random unique identifier)
- issued_at and expires_at
- authenticated requester_id
- approval_id / single-use nonce
- source identity: repository reference or staged snapshot identifier, commit SHA, tree SHA, and content fingerprint
- profile_id from a server-side allowlist
- build_image_digest and exporter_image_digest
- fixed policy version
- bounded timeout and resource policy identifiers (not arbitrary caller-selected values)
- release_authorized: false

The runner derives the actual command, mount layout, environment, CPU/memory/PID ceilings, timeout ceiling, and output ceiling from its own policy. A request may ask for a stricter bound, never a looser one.

The request must not contain:
- arbitrary shell or command text
- arbitrary Docker flags, image names without approved digests, or registry credentials
- host filesystem paths outside a runner-controlled staging namespace
- environment variables or secret values
- a caller-selected output destination
- instructions to publish, deploy, or release

### 3.3 Approval and replay controls

- Human approval must be an authenticated action by an authorized owner, not merely the presence of a local boolean or a file that the same user can rewrite.
- The approval must bind to the canonical request digest, exact source identity, profile, image digests, policy version, and expiry.
- Use a signing key or MAC key held only by the runner broker or a separately controlled approval authority. The ordinary control-plane identity and build container must not read it.
- Consume a unique approval ID/nonce atomically before execution. Replays, expired requests, altered payloads, mismatched source snapshots, and policy mismatches fail closed.
- Keep the current local HMAC mechanism only as a development convenience until an independent approval authority exists; do not call it proof of external consent.

### 3.4 Approval authority and signing-key placement

Separate the identity that authorizes a job from the process that receives an API request:
- An authenticated approval authority issues a short-lived signed approval over the canonical request digest and policy fields after the owner confirms the displayed request.
- The signing private key stays in that approval authority (or a managed signing facility), not in the control plane, build VM, or ordinary user workspace. The runner broker receives only the public verification key.
- The runner broker owns the durable replay ledger and atomically records a nonce as consumed before starting work. The control plane cannot reset or rewrite this ledger.
- If no independent approval authority exists in a prototype, label the mechanism as local development approval only. Do not represent it as a strong separation or external proof of consent.
- Rotation, revocation, key compromise, clock skew, and emergency disablement need documented procedures before a pilot.

### 3.5 VM lifecycle and orchestration boundary

A disposable VM introduces a privileged orchestration surface that must be included in the threat model. Keep the long-lived broker/orchestrator outside the job VM; the VM should contain only a minimal, short-lived guest agent and the build runtime:
- The broker validates approvals, owns replay state, schedules jobs, and verifies results. The guest agent receives one already-authorized job and reports bounded status/output; it cannot approve jobs, create VMs, alter policy, or access broker state.
- The orchestrator provisions and terminates the VM through a narrow, separately controlled interface. The broker requests only a predefined job launch; it does not receive general hypervisor or cloud-administrator credentials.
- Define the guest-to-broker communication explicitly: authenticate the guest with a per-job identity, accept only the expected job ID and protocol version, enforce message size/rate limits, and permit only the minimum status/result operations. A job ID alone is not authentication.
- The control plane must not hold broad cloud-account, hypervisor, or VM-administrator credentials.
- A narrowly scoped runner orchestrator creates a VM only from an approved immutable image digest and a versioned launch policy. It must enforce the expected CPU/memory/disk limits, network policy, identity, and expiry server-side.
- The runner broker validates the launch descriptor and guest identity before sending the job. The guest must authenticate to the broker; an IP address or VM name alone is not identity.
- Do not attach host directories, shared folders, user home directories, metadata credentials, SSH agents, Docker sockets, or control-plane secrets to the guest.
- Use a job-scoped, short-lived credential or capability that permits only the exact job and result-upload operation. It must not permit new VM creation, policy changes, or access to other jobs.
- Prefer a one-way, bounded result channel. The guest cannot choose a host path or ask the orchestrator to run host commands.
- The orchestrator records VM creation, policy, image digest, guest identity, termination, and cleanup status. Failed termination quarantines the job and blocks success.
- Treat the hypervisor, host kernel, orchestration service, image build pipeline, and signing authority as trusted infrastructure. If any of those administrators are adversaries, a single-provider VM does not meet that threat model.

### 3.6 Source and output handling

- The trusted staging component creates a bounded immutable snapshot; the build environment sees it read-only.
- Revalidate the staged snapshot digest immediately before execution.
- Define which trusted component fetches repository content and which credentials it may use. Repository credentials, if ever required, stay in the staging/control boundary, are read-only and short-lived, and are never copied into the build VM; synthetic prototypes should use local fixture snapshots and no repository credentials.
- Bind upload completion to the job ID and expected snapshot digest; reject partial, duplicate, substituted, or cross-job objects and expire abandoned staging data under a documented retention policy.
- Do not trust caller-provided paths. Resolve source references into runner-owned directories and reject traversal, symlinks, unexpected hard links, special files, and path races.
- Keep build output in a bounded, disposable filesystem. Do not mount user home directories, repository metadata, credentials, host sockets, or unrelated host paths.
- Export through a separate constrained component. Re-inventory after export and reject overwrite/collision conditions.
- Cleanup failure blocks a successful result and triggers quarantine/alerting. Do not use broad host-wide Docker pruning as routine cleanup.
- Retention and physical secure-erasure claims remain limited by host storage, snapshots, swap, backups, and provider infrastructure.

## 4. Threat model

### Protected assets
- Host and control-plane integrity
- Approval keys, replay state, and authenticated requester identity
- Source snapshots, repository metadata, and user credentials
- Build outputs, evidence, and provenance
- Other jobs' data and workspaces

### Adversaries considered
- Malicious or compromised project build/test code
- Malicious input submitted through a control-plane request
- A compromised control-plane process
- A compromised build container
- A same-host ordinary user attempting to alter approvals or runner state
- A compromised runner process or runtime

### Trust assumptions and residual limits
- A host administrator, hypervisor administrator, or kernel compromise remains outside the protection of ordinary containers and same-host service accounts. If these actors are in scope as adversaries, use a separately administered VM/host boundary and independent control of its lifecycle.
- A disposable VM reduces persistence and cross-job exposure but does not by itself prove the hypervisor, image supply chain, or orchestration control plane trustworthy.
- No design can guarantee detection of every secret. Source review and user responsibility remain required.
- Network-disabled build containers do not make the whole host network-disabled; the control plane and provisioning path need their own network policy.
- Signed evidence proves integrity relative to a signing identity, not that the build was safe or correct.

## 5. Failure and security behavior

The system must fail closed when:
- caller authentication or authorization fails
- the approval is missing, expired, replayed, or bound to another request
- source, image digest, policy version, or profile differs from the approved request
- schema validation, staging, snapshot verification, or resource setup fails
- the isolated VM/daemon is unavailable or isolation checks cannot be verified
- resource, timeout, output, or log limits are exceeded
- result inventory validation fails
- cleanup cannot be confirmed

On failure:
- stop the job where possible
- quarantine the job environment if cleanup is uncertain
- do not return a success status or release artifacts
- record a bounded, redacted audit event without secret values
- require operator review before retrying a cleanup-failed job

## 6. Staged implementation and acceptance gates

### Stage 0 — design and review (completed for architecture direction)
- [x] Record current limitations and recommended trust boundaries.
- [x] Define request, approval, runner, result, and failure responsibilities.
- [x] Reconcile the architecture with Phase 6 constraints and free-tier requirements.
- [x] Obtain project-owner approval of the architecture direction.
- [ ] Obtain an independent security review before any customer-source pilot.

### Stage 1 — local separation prototype (synthetic fixtures only; in progress)
- [x] Define the versioned, bounded protocol envelope and exact operation schemas (PR #87; CI #319 passed).
- [x] Reject unknown fields, duplicate JSON keys, malformed value types, arbitrary commands/paths, unsupported profiles, invalid digests, expiry violations, and release authorization in the protocol validator (PR #87).
- [x] Add a test-only Unix-domain socket broker using kernel peer credentials, private 0700/0600 development mode, and administrator-provisioned 2710/0660 group mode (PRs #88–#89; CI #330 and #338 passed).
- [x] Add separate submitter/operator UID allowlists, per-operation job-owner checks, bounded job/request counts, replay checks, cancellation, and non-disclosing unknown/unauthorized responses (PR #88).
- [x] In ephemeral Linux CI, run the broker under a temporary runner UID and connect from a separate control-plane UID; verify protected synthetic runner state, group-only socket traversal, kernel peer-UID authorization, and denial of an unapproved UID in the same group (PR #89; CI #338 passed).
- [x] Verify in the ephemeral CI fixture that runner/control-plane accounts are not members of the Docker group and cannot read the Docker socket when present.
- [x] Require a broker-owned SQLite database in group-access mode; enforce a service-owned 0700 state directory, 0600 single-link database file, transactional request/approval replay records, schema version, and startup integrity check (Stage 1 durable-state batch).
- [x] Verify job state and replay identifiers survive a normal broker restart; verify the control-plane UID cannot read the database in the ephemeral CI fixture.
- [x] Require broker-owned SQLite state in group-access mode with a service-owned 0700 parent, a single-link 0600 database, explicit write transactions, unique request/approval IDs, full synchronous commits, rollback journaling, schema versioning, and startup integrity checks (PR #91; CI #342 passed).
- [x] Verify job state and replay identifiers survive a normal broker restart, and that the control-plane UID cannot read the database (PR #91).
- [x] Test abrupt broker-process termination after a committed request, stale-socket recovery, normal restart, persisted job state, and replay rejection (Stage 1 crash-recovery test batch).
- [x] Reject a corrupt SQLite database at startup and inject a mid-submit ledger failure to verify transaction rollback leaves no job or replay record.
- [x] Kill the broker after a committed request, restart against the same database, verify stale-socket recovery, persisted job state, and replay rejection; reject corrupt state and test rollback after injected mid-submit failure (PR #93; CI #349 passed).
- [x] Test abrupt process death during an uncommitted SQLite transaction after dirty-page pressure; reopening recovers cleanly with no partial job or replay records.
- [x] Simulate database page exhaustion and verify the complete job/request/nonce transaction rolls back without corrupting the database.
- [x] Exercise SQLite online backup and restore, verifying job and all replay ledgers survive.
- [ ] Actual host power loss, storage-device failure, fsync error injection, retention expiry, and cleanup failure remain untested.
- [x] Add a foreground broker CLI with fixed socket/state/UID arguments and graceful SIGTERM/SIGINT shutdown; add a guarded, hardened systemd example plus a host-provisioning runbook (Stage 1 service-lifecycle batch).
- [ ] Validate the example on a separately approved dedicated host, including real systemd startup/stop, journaling, and cleanup ownership; no permanent service accounts or units are installed by this project.
- [x] Specify the signed-approval contract: Ed25519, a trusted public key, canonical job-bound payload, kernel-UID binding, bounded validity window, nonce, replay persistence, and fail-closed verifier behavior (design only; see `docs/approval-signature-contract.md`).
- [x] Implement standalone protocol-v2 envelope validation, canonical job-bound payload generation, configured-key fingerprinting, and fixed-path OpenSSL Ed25519 verification with trusted public-key file checks and kernel-peer UID binding (PR #99 verifier batch; CI #364 and #367 passed).
- [x] Add a unique durable nonce ledger in SQLite schema v2; reject schema-v1 state rather than silently migrating it (PR #100; CI #369 passed).
- [x] Integrate protocol-v2 signed submissions into broker acceptance; unsigned protocol-v1 submits are rejected while v1 status/cancel/result remain supported.
- [x] Verify the configured Ed25519 signature, key fingerprint, expiry, and exact kernel-authenticated requester UID before acceptance.
- [x] Atomically record the job, request ID, approval ID, and nonce in one broker-owned SQLite transaction; reject duplicate/replayed values and roll back on ledger failure.
- [x] Extend ephemeral Linux CI with a separate approval-authority UID; verify its synthetic private key is unreadable by runner/control-plane identities and test signed submission plus request/approval/nonce replay after restart (PR #101; CI #371 passed).
- [x] Add deterministic bounded-input fuzzing for random byte strings, randomized JSON envelopes, nested JSON recursion, required-field type mutations, unknown-field injection, unsigned-v1 downgrade attempts, and canonical-payload tampering (Stage 1 protocol fuzz batch; PR pending). The fuzz suite uses fixed seeds and no new dependency.
- [ ] Independently verify that production control-plane identities cannot access real runner keys, persistent replay state, workspaces, or the Docker daemon.
- [ ] Define and review a real authenticated approval-authority workflow; a valid signature proves only that the configured key signed the payload, not that a human consented.
  
The CI identity test uses disposable accounts and synthetic key/database fixtures. It is evidence for the proposed permission model, not proof of production deployment security. Same-host process/account separation does not protect against host administrators or kernel compromise.

### Stage 2 — disposable VM execution prototype (synthetic fixtures only)
- [ ] Provision a minimal, digest-pinned runner VM image through a documented trusted process.
- [ ] Create one disposable VM per job; no personal files, browser sessions, SSH keys, cloud credentials, or production secrets.
- [ ] Verify network policy, storage boundaries, resource ceilings, job isolation, result export, and VM destruction.
- [ ] Exercise VM startup failure, interruption, timeout, compromised-job cleanup, and orphan detection.
- [ ] Have an independent reviewer inspect the host/VM/hypervisor assumptions.

### Stage 3 — security acceptance
- [ ] Independent review of host, daemon, VM/hypervisor, protocol, approval, source staging, export, and workflow permissions.
- [ ] Signed provenance from an independently controlled identity, if provenance assurance is required.
- [ ] Documented image publisher trust, digest verification, update review, rollback, and vulnerability response.
- [ ] Explicit pilot threat model and written authorization before any customer-source testing.

### Stage 4 — future service/API consideration (not approved here)
- [ ] Separate commercial/API feasibility and security review.
- [ ] Explicit owner approval of a scoped plan and roadmap position.
- [ ] No public execution endpoint, multi-tenancy, billing, plugins, or customer onboarding under this design-only change.

## 7. Free-tier and operational feasibility

- Documentation, protocol schemas, synthetic tests, and local development can be done with free tools.
- A same-host rootless runner prototype may be feasible without paid services, but its isolation guarantees are limited.
- Disposable VMs require compute, storage, and lifecycle automation. Free hosted CI minutes or free cloud tiers are not a dependable basis for an always-on commercial execution service; quotas, availability, network limits, and provider terms must be assessed before selection.
- Do not promise production-grade isolation, availability, unlimited jobs, or customer data protection on the basis of a free tier.
- Keep the architecture portable so a future trusted runner host can be selected without coupling the core USC engine to a single cloud provider.

## 8. Explicit non-goals

This proposal does not:
- implement a web/API service or SaaS
- add multi-tenancy, customer accounts, billing, plugins, SDKs, or dashboards
- enable customer repositories or arbitrary user code
- introduce a public execution endpoint
- publish, release, or deploy artifacts
- claim independent security certification or container-escape resistance
- change the existing runner or approval implementation

## 9. Review checklist

Reviewers should specifically challenge:
1. Whether the proposed control-plane/runner split actually removes access to runner secrets and Docker authority.
2. Whether the selected VM boundary is independent enough for the stated threat model.
3. Whether every request field is necessary and server policy remains authoritative.
4. Whether approval represents a real authenticated owner action and is cryptographically bound to the exact request.
5. Whether source staging, path handling, output export, and cleanup resist races and malicious filesystem objects.
6. Whether logs, audit records, and provenance avoid leaking secrets and avoid overstating assurance.
7. Whether free-tier operational assumptions are honest and sustainable.

**Architecture decision:** approved by the project owner on 23 November 2026. Remaining stages are implementation and security gates, not authorization for customer-source execution. Customer repositories remain disabled.
