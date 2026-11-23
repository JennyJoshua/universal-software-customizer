# Isolated build execution model

## Purpose and boundary

USC build verification is a separate, explicit operation. Inspection, licence scanning, adapter detection, configuration validation, and dry-run planning must never execute project code. A build result applies only to the exact source tree, approved command, pinned image, and execution profile that produced it.

The first runner is deliberately Docker-only. If the Docker CLI or daemon is unavailable, USC blocks execution; it must not fall back to a host shell, subprocess execution, or another weaker environment.

## Required controls

The runner requires all of the following:

- Explicit approval of the command and image before execution.
- An image reference pinned by sha256 digest and already present locally (--pull=never); USC does not pull images during a build.
- Direct argv execution; shell interpreters and shell command strings are rejected.
- A disposable build container with --network=none, read-only root filesystem, read-only source mount, and a dedicated writable 256 MB Docker-managed local tmpfs volume mounted at /out. A separately pinned BusyBox export helper remains alive as a non-root, network-disabled, read-only container and mounts that volume read-only while USC copies artifacts into a private sibling staging directory. USC verifies the staged inventory, checks that the original output directory is unchanged and empty, then merges files without overwriting concurrent entries. USC then removes both containers and the temporary volume; cleanup failure blocks the result.
- Non-root UID/GID, all Linux capabilities dropped, no-new-privileges, a PID limit, memory and CPU limits, and a small non-executable temporary filesystem.
- A sanitized environment containing only fixed HOME, TMPDIR, and PATH values. Host environment variables, credentials, sockets, and additional mounts are not forwarded.
- A hard timeout and bounded captured logs.
- A unique container label and a post-run cleanup check. If cleanup cannot be confirmed, the result is blocked_cleanup_failed.

When the source is a Git repository root, USC also attempts exact source identity inspection: it requires a clean index/worktree, rejects ignored or untracked files, submodules, symlinks, unsupported entries, and filter/smudge differences, then checks raw tracked file contents against the committed Git blob IDs. During staging, each included file is re-hashed as a Git blob and compared again, so a file changed between identity inspection and copying is rejected. The report records the full commit SHA, tree SHA, and whether this identity check succeeded. Non-Git or dirty fixture directories may still be used for isolated synthetic tests, but they receive no verified Git identity and cannot support a provenance claim.

The source snapshot rejects symlinks and non-regular files, fails on incomplete directory traversal, and is limited to 256 MB, 20,000 files, and 50 MB per file. A deterministic SHA-256 fingerprint covers each included relative path, file mode, size, and content. Known exclusions include .git/.usc, common cloud/CLI credential directories, .env files other than example templates, credential files, and private-key/certificate formats. In addition, USC scans included file content in bounded chunks for selected high-confidence credential formats: private-key PEM headers (including encrypted keys), AWS access-key IDs, GitHub and GitLab tokens, Slack tokens, Google API keys and OAuth client secrets, live Stripe keys, OpenAI and Anthropic API keys, Hugging Face tokens, npm tokens, and PyPI tokens. This list is intentionally finite and is not a comprehensive provider catalogue. Findings block snapshot creation and report only the file path and rule identifier, never the matched value. This is defence in depth, not a complete secret scanner: it can miss unknown, encoded, split, or provider-specific credentials and can produce false positives. Human review remains required, and only synthetic fixtures are permitted at this stage.

The host output directory must exist, be empty, be writable by the non-root runner, and be separate from (not an ancestor or descendant of) the source directory. Build code writes only to the size-limited container tmpfs; USC copies the output back after execution. Exported symlinks are rejected. This avoids exposing an unbounded host directory as a writable container mount.

## Pre-build source review

Before creating a build request, run `usc source-review --path ./candidate --output ./source-review.json`. This read-only command does not invoke Docker or execute project code. It lists candidate source paths, known excluded sensitive paths, and paths containing selected credential-pattern findings; it never prints file contents or matched credential values. The report is bounded to 500 entries and marks truncation. Review the report manually: excluded files and directories are not part of the later build snapshot, and any path marked `review_required` must be investigated and cleaned before proceeding. The inventory is a point-in-time view, not an immutable approval or a guarantee that files cannot change afterward. The build request and runner still perform their own Git identity checks, bounded snapshotting, and secret scanning. This finite scanner cannot prove that a source tree is secret-free. Source review does not approve a build.

## Reviewed CLI approval workflow

The user-facing CLI now separates request creation, explicit review/approval, and execution. The fixed allowlist currently contains `python-pytest` (`python -m pytest -q`) and `python-container-smoke` (a fixed synthetic-only probe of container isolation); callers cannot supply arbitrary commands or shell strings through this workflow. The runner also requires the pinned USC export-helper image `busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662` to be pre-provisioned locally; it never pulls this image during a build.

1. Create a request from a clean Git working tree. The request binds the canonical source path, exact Git commit and tree, digest-pinned image, fixed profile/argv, timeout, log limit, unique approval ID, and expiry (60–1800 seconds; default 900 seconds). Request creation does not execute project code.
2. Review the request JSON, then run `usc build-approve --request build-request.json --output build-approval.json --approve`. The CLI prints the exact source revision, image, profile, argv, timeout, expiry, and explicit no-release status before creating a receipt.
3. Run `usc build-run --approval build-approval.json --path ./candidate --output-dir ./build-artifacts --report ./build-evidence.json`. USC authenticates and atomically consumes the receipt before invoking the Docker runner. A receipt cannot be reused; create a new request and approval if an attempt must be repeated.

Example request creation (replace the image placeholder with a locally provisioned, verified digest):

~~~sh
usc build-request --path ./candidate \
  --image python:3.12-slim@sha256:<verified-64-character-digest> \
  --profile python-pytest --timeout 300 --expires-in 900 \
  --output ./build-request.json
~~~

Approval and execution:

~~~sh
usc build-approve --request ./build-request.json \
  --output ./build-approval.json --approve

usc build-run --approval ./build-approval.json --path ./candidate \
  --output-dir ./build-artifacts --report ./build-evidence.json
~~~

Receipts use an HMAC key stored under the current user's `~/.usc` directory (directory mode 0700; key mode 0600) and a private one-time-use ledger. This detects accidental/tampered receipt edits and blocks replay in the local state store. It is not a digital signature, cannot prove external human identity, and cannot resist a malicious process running as the same OS user who can alter the key or ledger. It is a local approval guardrail, not a remote authorization service.

The `python-container-smoke` profile exists only to validate the runner against a synthetic fixture in the trusted-main Docker validation workflow; it is not intended for customer project testing. Additional profiles require a separate reviewed change and tests. The user-facing workflow requires a clean Git source and refuses non-Git or dirty directories. Keep using synthetic fixtures only; this CLI work does not enable customer repositories.

Before the first build, provision the USC export-helper image locally:

~~~sh
docker pull busybox:1.36.1
docker image inspect busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662 --format '{{.Id}}'
~~~

The second command must resolve successfully. USC never pulls the helper image during a build and blocks execution if this exact digest is unavailable.

## Low-level Python API boundary

The supported Python execution entry point is `customizer.build_approval.execute_approved_build`. It authenticates and consumes the supplied one-time receipt, rechecks the exact source identity and approved profile, and only then invokes the runner. The CLI uses this same entry point; it no longer imports or calls the runner directly.

The Docker execution primitive has been renamed to `customizer.build_runner._run_isolated_build` and marked internal. It is not imported by the CLI or exposed as a supported package API. Application integrations must call `execute_approved_build` or the CLI workflow, never the internal primitive. Tests that exercise Docker mechanics import the internal function explicitly as a test-only seam.

Python module privacy is a software-interface boundary, not a sandbox: code already executing as the same Python user can deliberately import underscore-prefixed internals, modify process state, or access the local HMAC key and replay ledger. The local receipt therefore protects supported workflows from accidental or ordinary API bypass, but it is not a remote authorization service or a defence against malicious same-user code. Any future web/API service must isolate build execution in a separate process or service account and accept only authenticated, scoped approval records; it must never expose a generic command-execution endpoint.

Do not pass secrets in command arguments or source files. A mounted source tree is readable to the build process; the runner does not make arbitrary source contents confidential. The output tmpfs is limited to 256 MB and the temporary filesystem to 64 MB. Keep secrets out of fixture and candidate trees.

## Result states

- blocked_approval_required: no execution occurred because approval was absent.
- blocked_invalid_request: unsafe or invalid request; no execution occurred.
- blocked_isolation_unavailable: Docker was unavailable; no host fallback occurred.
- passed / failed: container command exited with status zero / non-zero.
- timed_out: execution exceeded its time limit and the container was stopped.
- output_limit_exceeded: captured output exceeded the configured bound and the container was stopped.
- blocked_cleanup_failed: USC could not confirm removal of all containers bearing the run's unique label.

## Current limitations

This remains an initial local Docker runner, not a complete CI orchestration or release system. It stages a bounded source snapshot with known-path exclusions plus content checks for selected high-confidence credential formats; neither control is a complete secret scanner. The USC SHA-256 snapshot fingerprint is bound to the inspected Git commit/tree identity when a clean Git source is available. Build evidence includes a bounded inventory of selected tools in the pinned image, artifact hashes, and a detached provenance manifest that cross-checks the source and exported artifacts. The manifest records the exact USC export-helper image reference and local image ID, plus whether the bounded output volume was cleaned up. A successful build provenance manifest requires the cleanup result to be true. Artifact export uses a bounded Docker-managed tmpfs volume held by a restricted, read-only helper container; files are copied to private staging, re-inventoried, and merged without overwriting existing output entries. Output-path replacement, concurrent writes, helper startup, volume creation/removal, and interrupted export have failure-injection coverage (PR #73). Export staging and no-overwrite merging reduce accidental races with other host processes; they do not protect against a malicious process running as the same OS user. The manifest is a consistency record, not a digital signature or proof of a trusted evidence producer. The reviewed CLI approval workflow is implemented with fixed profiles. Live Docker daemon validation has passed against a synthetic clean Git fixture using a digest-pinned Python build image and the pinned BusyBox exporter helper (trusted-main workflow runs #5 and #6). This is a runtime smoke test, not a container-escape penetration test, a general security certification, or validation of every supported toolchain. Keep using synthetic fixtures only; customer repositories remain disabled pending a separate security review.

The runner is not a guarantee against container-runtime vulnerabilities or malicious build code. The snapshot fingerprint is a USC content digest, not itself a Git tree SHA or a signed provenance attestation; the detached manifest provides consistency checks but is not cryptographic proof of a trusted evidence producer. Use a patched Docker daemon and trusted, digest-pinned images. Never expose Docker socket or credentials inside the build container.
