# Isolated build execution model

## Purpose and boundary

USC build verification is a separate, explicit operation. Inspection, licence scanning, adapter detection, configuration validation, and dry-run planning must never execute project code. A build result applies only to the exact source tree, approved command, pinned image, and execution profile that produced it.

The first runner is deliberately Docker-only. If the Docker CLI or daemon is unavailable, USC blocks execution; it must not fall back to a host shell, subprocess execution, or another weaker environment.

## Required controls

The runner requires all of the following:

- Explicit approval of the command and image before execution.
- An image reference pinned by sha256 digest and already present locally (--pull=never); USC does not pull images during a build.
- Direct argv execution; shell interpreters and shell command strings are rejected.
- A disposable container with --network=none, read-only root filesystem, read-only source mount, and a dedicated writable output tmpfs capped at 256 MB. Successful or failed command output is copied from the stopped container into an initially empty host output directory before the container is removed.
- Non-root UID/GID, all Linux capabilities dropped, no-new-privileges, a PID limit, memory and CPU limits, and a small non-executable temporary filesystem.
- A sanitized environment containing only fixed HOME, TMPDIR, and PATH values. Host environment variables, credentials, sockets, and additional mounts are not forwarded.
- A hard timeout and bounded captured logs.
- A unique container label and a post-run cleanup check. If cleanup cannot be confirmed, the result is blocked_cleanup_failed.

When the source is a Git repository root, USC also attempts exact source identity inspection: it requires a clean index/worktree, rejects ignored or untracked files, submodules, symlinks, unsupported entries, and filter/smudge differences, then checks raw tracked file contents against the committed Git blob IDs. During staging, each included file is re-hashed as a Git blob and compared again, so a file changed between identity inspection and copying is rejected. The report records the full commit SHA, tree SHA, and whether this identity check succeeded. Non-Git or dirty fixture directories may still be used for isolated synthetic tests, but they receive no verified Git identity and cannot support a provenance claim.

The source snapshot rejects symlinks and non-regular files, fails on incomplete directory traversal, and is limited to 256 MB, 20,000 files, and 50 MB per file. A deterministic SHA-256 fingerprint covers each included relative path, file mode, size, and content. Known exclusions include .git/.usc, common cloud/CLI credential directories, .env files other than example templates, credential files, and private-key/certificate formats. In addition, USC scans included file content in bounded chunks for a small set of high-confidence credential formats (private-key PEM headers, AWS access-key IDs, GitHub/Slack tokens, Google API keys, and live Stripe secret keys). Findings block snapshot creation and report only the file path and rule identifier, never the matched value. This is defence in depth, not a complete secret scanner: it can miss unknown, encoded, split, or provider-specific credentials and can produce false positives. Human review remains required, and only synthetic fixtures are permitted at this stage.

The host output directory must exist, be empty, be writable by the non-root runner, and be separate from (not an ancestor or descendant of) the source directory. Build code writes only to the size-limited container tmpfs; USC copies the output back after execution. Exported symlinks are rejected. This avoids exposing an unbounded host directory as a writable container mount.

## Invocation contract

The Python API is customizer.build_runner.run_isolated_build. It accepts a source directory, an existing output directory, a digest-pinned image, an argv list, and approved=True. The caller must obtain that approval through a separate human-reviewed workflow; the boolean is not a substitute for a user-facing approval gate.

Example (illustrative only; replace the placeholder with a verified, locally provisioned 64-character digest):

~~~python
from customizer.build_runner import run_isolated_build

report = run_isolated_build(
    "./candidate",
    "./build-output",
    image="python:3.12-slim@sha256:<verified-64-character-digest>",
    command=["python", "-m", "pytest", "-q"],
    approved=True,
    timeout_seconds=300,
)
~~~

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

This remains an initial local Docker runner, not a complete CI orchestration or release system. It stages a bounded source snapshot with known-path exclusions plus content checks for selected high-confidence credential formats; neither control is a complete secret scanner. The USC SHA-256 snapshot fingerprint is bound to the inspected Git commit/tree identity when a clean Git source is available. Build evidence includes a bounded inventory of selected tools in the pinned image, artifact hashes, and a detached provenance manifest that cross-checks the source and exported artifacts. The manifest is a consistency record, not a digital signature or proof of a trusted evidence producer. A reviewed user-facing CLI approval workflow and live Docker daemon validation remain outstanding. Use synthetic fixtures only until those controls and failure tests are complete.

The runner is not a guarantee against container-runtime vulnerabilities or malicious build code. The snapshot fingerprint is a USC content digest, not yet a Git tree SHA or a provenance attestation; later Phase 6 work must bind it to repository revision and sync history. Use a patched Docker daemon and trusted, digest-pinned images. Never expose Docker socket or credentials inside the build container.
