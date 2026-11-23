# USC Retention and Deletion Policy

## Purpose and scope

This policy defines the lifecycle of temporary build data, retained evidence, exported artifacts, logs, Docker resources, and runner caches. It applies to the current local Docker runner and its trusted-main synthetic validation workflow. It does not authorize customer-source execution, artifact release, or deployment.

The policy distinguishes **application cleanup** (removing resources USC creates) from **secure erasure** (proving that all physical copies are unrecoverable). USC can perform the former for resources it controls; it cannot guarantee the latter on general-purpose filesystems, SSDs, virtual disks, hosted runners, snapshots, backups, or cloud-managed storage.

## Data classes and lifecycle

| Data class | Location / owner | Lifecycle requirement | What USC can verify |
|---|---|---|---|
| Staged source snapshot | Private TemporaryDirectory created by the runner | Remove automatically when the build scope exits, including handled errors and interruption paths | Python temporary-directory cleanup completed without raising; no physical-erasure claim |
| Export staging copy | Private .usc-export-* temporary directory beside the selected output directory | Remove automatically when export completes or fails | TemporaryDirectory context exits; cleanup errors make export fail |
| Build and exporter containers | Docker daemon, unique com.usc.build-run label | Stop/remove in the runner's finally path; a build result is blocked unless no labelled containers remain | Label query before and after removal |
| Temporary output volume | Docker-managed bounded tmpfs volume named usc-output-<run-id> | Remove in the runner's finally path; a build result is blocked if Docker does not confirm removal | docker volume rm succeeds |
| Captured logs | In-memory bounded buffer; redacted copy embedded in caller-requested evidence JSON | Do not write a separate raw log file. Persist only when the caller chooses to retain the evidence report | Byte limit, truncation flag, redaction pass, digest of redacted log text |
| Evidence report / provenance manifest | Caller-selected path or external storage | Explicitly retained by the caller; no automatic expiry or deletion by USC | USC validates content and hashes; it does not control the caller's storage lifecycle |
| Exported build artifacts | Caller-selected output directory | Explicitly retained by the caller; no automatic expiry or deletion by USC | Bounded inventory, file hashes, and output path |
| Docker images and build cache | Docker daemon's local image/cache store | Not automatically pruned. Image/cache removal is an operator-managed maintenance action | USC verifies required image presence and digest; it does not enumerate or purge unrelated cache data |
| GitHub Actions logs and artifacts | GitHub-hosted service | Governed by repository/organization retention settings and workflow retention-days where artifacts are uploaded | USC cannot guarantee provider-side deletion timing or erase backups |
| Runner host temp, swap, snapshots and backups | Operating system / hosting provider | Governed by host configuration and provider lifecycle; use disposable, encrypted runner storage for stronger isolation | Outside USC's control |

## Required retention defaults

1. **Transient build data:** keep only for the lifetime of a single build attempt. Use unique per-run names and private temporary directories. Remove containers and the output volume in a finally path.
2. **Evidence and artifacts:** no implicit retention period is imposed by the library. The operator must choose a retention period before a future customer pilot and record it in the operating procedure. Until then, use synthetic evidence only and retain only what is needed for review.
3. **CI evidence:** do not upload source snapshots, raw logs, build artifacts, or evidence bundles unless a workflow explicitly needs them. Any future artifact upload must set a finite retention-days value and must avoid secrets and customer data.
4. **Images and caches:** do not run broad docker system prune or delete shared caches automatically. Cache/image retention is an operator decision because it may affect other workloads and rollback.
5. **Approval receipts and local state:** approval state is stored under the current user's private ~/.usc directory. It is not build evidence and must not be copied into artifacts. A future pilot must define expiry and deletion for the one-time-use ledger separately.

## Cleanup and failure semantics

- The runner uses private temporary-directory scopes for the staged source and export staging copy. Normal return and handled exception paths exit those scopes.
- The runner attempts removal of every container bearing its unique run label and removes only the unique output volume it created.
- If container or volume cleanup cannot be confirmed, the result is blocked_cleanup_failed; evidence must not be interpreted as a successful clean run.
- If the process or host is forcibly terminated, loses power, or the Docker daemon becomes unavailable, Python finally blocks may not run. Orphaned resources may remain. Do not automatically delete resources by broad name prefix; identify the exact run ID/label and inspect ownership before a narrowly scoped operator cleanup.
- If a cleanup attempt fails, preserve the failure evidence and investigate. Do not silently downgrade the cleanup status or report a clean result.

## Secure deletion limitations and stronger deployment model

- Unlinking a file or removing a directory is **not** proof that underlying blocks have been overwritten. SSD wear levelling, copy-on-write filesystems, snapshots, backups, journaling, and cloud storage replication can retain prior data.
- Removing a Docker tmpfs volume ends the container-visible volume lifecycle, but USC cannot attest that no copy remains in host memory, swap, crash dumps, daemon logs, or provider infrastructure.
- Redaction is best-effort. A redacted log digest is an integrity reference for the redacted text, not proof that the original output contained no secret.
- For a future customer-source pilot, use a dedicated disposable VM or isolated runner/OS account with encrypted ephemeral storage, no personal files or credentials, no shared persistent cache, and destroy the VM/storage after each job. This is a recommended architecture gate, not a feature currently implemented or independently verified.
- If policy or law requires verifiable media sanitization, use a storage/provider process that supplies an appropriate sanitization guarantee or cryptographic-erasure evidence. USC itself does not claim NIST-compliant or physical secure erasure.

## Operator response to an orphaned run

1. Stop accepting new builds on the affected runner until the Docker daemon and run state are understood.
2. Use the run ID from the job/evidence context to inspect containers with the exact label `com.usc.build-run=<run-id>` and the exact volume `usc-output-<run-id>`.
3. Confirm that each resource belongs to that interrupted USC run before removing it. Do not use broad prune commands or remove unrelated volumes/images.
4. Record the cleanup incident and whether host storage, logs, snapshots, or backups may retain data.
5. If ownership or impact is uncertain, preserve state for review rather than deleting resources blindly.

## Current status

The current runner already uses temporary directories, unique container labels, a per-run tmpfs output volume, and fail-closed cleanup checks. This document makes the retention boundary explicit. It does not add a background janitor, automatic evidence expiry, host disk sanitization, Docker cache pruning, GitHub artifact deletion, or customer-data handling. Synthetic fixtures only; customer repositories remain disabled pending the independent security review and P0 gates.
