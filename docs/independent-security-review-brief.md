# USC — Independent Security Review Brief

**Status:** Review preparation document; not an independent security assessment  
**Prepared:** 25 November 2026  
**Review target:** `JennyJoshua/universal-software-customizer`, main revision `ce158ddd78998a079582319bbc4f6628eb7c7c61`  
**Execution boundary:** Synthetic fixtures only. Customer repositories and customer-source execution remain disabled.

## 1. Purpose

This brief gives an independent reviewer a bounded starting point for assessing the USC isolated-build and Stage 1 runner-isolation work. It records the current design, implementation evidence, explicit trust assumptions, and known gaps.

The reviewer should independently inspect the source code, workflows, tests, and documentation at the target revision. This brief is not evidence that the design is secure, does not replace a penetration test, and must not be used as customer-pilot authorization.

## 2. Review objectives

The reviewer is asked to determine:

1. Whether the existing Docker build runner's controls are sufficient for the explicitly stated threat model, and what remains trusted about the host, kernel, Docker daemon, and administrators.
2. Whether the Stage 1 broker correctly separates the control-plane UID from the runner UID and approval authority.
3. Whether the Unix socket, kernel peer-credential checks, strict protocol schemas, and per-operation authorization resist spoofing, downgrade, replay, malformed input, and unauthorized job access.
4. Whether Ed25519 verification is correctly bound to the exact job/source/profile/image/policy/expiry/requester fields and to the authenticated socket peer.
5. Whether job creation and request/approval/nonce replay writes are atomic and robust under process crashes, database-full conditions, backup/restore, and restart.
6. Whether filesystem ownership, key custody, SQLite permissions, systemd hardening, and cleanup behavior are safe and accurately documented.
7. Whether GitHub Actions permissions, triggers, dependency/action pinning, and trusted-main gates preserve the intended trust boundary.
8. Which findings must be remediated before any customer-source pilot, and which can remain documented limitations for a synthetic prototype.

## 3. Components and files to inspect

### Stage 1 broker and protocol

- `engine/customizer/local_runner_broker.py` — Unix-domain socket broker, SO_PEERCRED identity, operation dispatch, signature verification, and transactional job acceptance.
- `engine/customizer/runner_protocol.py` — protocol-v1 status/cancel/result validation and peer-UID authorization.
- `engine/customizer/runner_approval.py` — strict protocol-v2 envelope validation, canonical payload construction, trusted public-key checks, and fixed-path OpenSSL Ed25519 verification.
- `engine/customizer/runner_state.py` — broker-owned SQLite state, schema versioning, private-file checks, transactions, and request/nonce replay ledgers.
- `deploy/systemd/usc-runner-broker.service.example` and `deploy/systemd/broker.env.example` — guarded systemd example and configuration.
- `docs/runner-broker-host-provisioning.md` — proposed dedicated-host identities, key placement, filesystem permissions, lifecycle, and deployment gates.

### Existing isolated build and evidence path

Inspect the relevant implementation and schemas in:

- `engine/customizer/build_runner.py`
- `engine/customizer/build_approval.py`
- `engine/customizer/build_evidence.py`
- `engine/customizer/source_snapshot.py` and the source-review/secret-scanning modules
- `engine/customizer/provenance.py` and associated JSON schemas
- `docs/isolated-build-model.md`
- `docs/retention-and-deletion-policy.md`

The reviewer should trace the supported CLI/approval path to the low-level runner and verify that no public interface bypasses receipt consumption. The low-level Python function remains an internal implementation boundary, not a security boundary by itself.

### Tests and workflows

- `tests/test_local_runner_broker.py`
- `tests/test_runner_protocol.py`
- `tests/test_runner_protocol_fuzz.py`
- `tests/test_runner_approval.py`
- `tests/test_runner_approval_verifier.py`
- `tests/test_runner_state.py`
- `tests/integration/test_runner_service_identity.py`
- `.github/workflows/ci.yml`
- `.github/workflows/python-container-smoke.yml`
- `.github/workflows/usc-cleanup-verification-ref.yml`

The reviewer should confirm the actual current workflow permissions, triggers, pinned action commits, dependency lock/hash behavior, and which jobs can access privileged host resources.

## 4. Implemented evidence to reproduce or inspect

| Evidence | Reference | What it establishes — and does not establish |
|---|---|---|
| Fixed-path Ed25519 verifier | PR #99; CI #364 and #367 | Synthetic real-key signing/verification, trusted key-file checks, requester UID binding, bounded OpenSSL execution, and temporary-file cleanup. Not human identity or consent. |
| Durable nonce ledger | PR #100; CI #369 | Unique nonce persistence in SQLite schema v2; schema-v1 databases fail closed rather than silently migrate. |
| Broker signed submissions | PR #101; CI #371 and #373 | Broker-side v2 signature enforcement, rejection of unsigned v1 submit, SO_PEERCRED binding, and atomic job/request/approval/nonce writes. Jobs are metadata only. |
| Protocol fuzz coverage | PR #102; CI #375 | Deterministic bounded malformed-input, schema mutation, downgrade, recursion, and canonical-payload rejection tests. Not exhaustive fuzzing or a formal proof. |
| State crash/storage tests | PR #103; CI #377 | Abrupt process death during an uncommitted transaction, simulated SQLite page exhaustion/rollback, and online backup/restore. Not actual power-loss or storage-hardware certification. |
| Documentation reconciliation | PR #105; CI #379 | Aligns current implementation and remaining gates across the broker, approval, and host-provisioning documents. |
| Signed-field binding tests | PR #106; CI #381 | Real Ed25519 tests reject changes to mutable signed fields and invalid policy-version changes. |
| Live Docker smoke | Trusted-main runs #5 and #6; run evidence is linked in issue #54 | Selected real-Docker behavior on the tested host and synthetic fixture. Not container-escape testing or general runtime certification. |

All cited test runs should be opened and their exact workflow/job results checked. The reviewer should not rely on this summary instead of inspecting the run logs and current source.

## 5. Explicit trust assumptions

The current design still trusts:

- Host root, kernel, and system administrators.
- The Docker daemon and its administrator for the existing build runner.
- The host OpenSSL binary and its package/provisioning chain.
- The approval authority's identity, private-key custody, and signing process.
- The configured trusted public-key file and its provisioning/fingerprint verification.
- The broker executable and runner-owned state directory/database.
- GitHub Actions and the trusted-main CI environment within their configured permissions.
- The host/hypervisor/provider infrastructure used by any future VM stage.

The same-host OS account split is meaningful defence in depth but is not a boundary against root, kernel compromise, or a sufficiently privileged host administrator.

## 6. Known limitations and open gates

These are known and must be independently challenged, not silently treated as solved:

1. **No authenticated human-consent workflow.** A valid Ed25519 signature proves that the configured key signed a payload. It does not prove a human reviewed or approved it. Approval-authority authentication, governance, key rotation/revocation, and emergency disablement are not implemented.
2. **No production key lifecycle.** CI uses synthetic ephemeral keys and disposable identities. No permanent approval authority or signing service has been deployed.
3. **Broker is metadata-only.** It creates synthetic queued job records. It does not fetch source, upload source, invoke Docker, execute builds, export artifacts, or release/deploy.
4. **No disposable VM stage.** The approved architecture prefers a disposable VM per job, but Stage 2 VM provisioning/orchestration is not implemented or approved.
5. **Dedicated-host validation is not done.** The systemd unit and provisioning runbook are examples only. No permanent host users/groups or systemd units have been installed by this project.
6. **Storage assurance is bounded.** CI tests process termination during an uncommitted transaction, simulated page exhaustion, and backup/restore. Actual host power loss, storage-device failure, fsync error injection, and hardware failure are untested.
7. **Retention and cleanup gaps remain.** Retention expiry, cleanup-failure handling, and long-duration stress need explicit design and testing. Physical secure erasure cannot be claimed.
8. **Existing Docker runner risks remain.** Docker daemon trust, same-OS-user tampering, finite secret scanning, and unsigned provenance remain material boundaries from the Phase 6 review.
9. **No independent review yet.** Current ChatGPT implementation review and CI do not count as independent security assessment or penetration testing.

## 7. Required review scenarios

At minimum, independently inspect or test:

- Spoofed, unauthorized, and changed peer UID; control-plane attempts to read runner state or private approval keys.
- Duplicate request ID, approval ID, nonce, expiry, wrong key ID, wrong signer, altered source/profile/image/policy fields, and protocol-v1 downgrade.
- Duplicate JSON keys, malformed UTF-8, oversized payloads, deep nesting, unexpected types, and slow/partial socket clients.
- Broker restart, abrupt termination during transaction, database corruption, disk-full, backup/restore, permissions drift, stale sockets, and interrupted shutdown.
- Public-key symlink/hard-link/FIFO/writable/oversized path attacks; temporary-file permissions and cleanup.
- systemd sandbox compatibility, UID/GID ownership, runtime/state directory modes, journal content, restart behavior, and least privilege.
- Existing Docker runner mount/network/resource boundaries, export races, cleanup failure, and workflow permissions.
- Supply-chain assumptions for the OpenSSL binary, Python dependencies, GitHub Actions, and build/export images.

Do not perform destructive or production-host testing without a separately approved test environment and explicit scope.

## 8. Required reviewer output

Please return a written report containing:

- Reviewer identity, qualifications, date, exact repository revision, and scope.
- Methodology, tools, environments, and tests performed (including tests not performed).
- Findings with severity, affected file/line or workflow, preconditions, impact, reproducible evidence, and recommended remediation.
- Clear distinction between exploitable vulnerabilities, design weaknesses, operational gaps, and accepted residual risks.
- An explicit verdict on whether the current Stage 1 synthetic broker is safe to continue testing.
- A separate verdict on whether any customer-source pilot is acceptable. Do not infer pilot approval from a Stage 1 pass.
- Retest evidence for each remediated finding.

## 9. Project decision gates

- This brief does not authorize installing the sample service, provisioning a permanent host, creating permanent accounts, or starting systemd.
- This brief does not authorize Stage 2 VM implementation, customer repositories, customer-source execution, a public API, production deployment, artifact release, or paid services.
- Continue using synthetic fixtures only.
- Any future customer-source pilot requires independent security review, a written threat model, an authenticated approval authority, validated isolated host/VM infrastructure, and separate explicit owner approval.
