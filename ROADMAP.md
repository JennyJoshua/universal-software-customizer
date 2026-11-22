# Roadmap

## Completed foundation and implementation batches

- [x] Repository purpose, scope, architecture, principles, and approval gates documented.
- [x] Python project skeleton, CLI, tests, and GitHub Actions CI established.
- [x] Static source inspector implemented and merged (PR #4).
- [x] Licence and third-party rights evidence scanner implemented and merged (PR #5).
- [x] Safe upstream synchronization requirements and architecture specified (PR #7).
- [x] Read-only, baseline-aware upstream sync planner implemented and merged (PR #8).
- [x] Isolated, uncommitted candidate integration implemented and merged (PR #9).
- [x] Authenticate public GitHub Actions run metadata, jobs, workflow identity, and exact candidate tree against pinned trust anchors.
- [x] Create an isolated one-parent verification snapshot commit/ref with an exact candidate tree, without changing product/candidate HEAD or baseline.
- [x] Verify a published snapshot end-to-end against a real GitHub Actions run and connect it to authenticated verification and acceptance (synthetic maintainer fixture).

## Phase 3 — Safe upstream synchronization

- [x] Require full base and target commit SHAs.
- [x] Reject shallow history, dirty working trees, and invalid/stale baselines.
- [x] Produce deterministic path-level upstream/local change classifications.
- [x] Run a non-mutating Git three-way merge preflight and block conflicts.
- [x] Flag common licence/notice file changes for human rights review.
- [x] Require explicit approval and rights-review acknowledgement when relevant.
- [x] Create candidate integration in a separate full clone without hardlinks or submodules.
- [x] Preserve original customized HEAD and working-tree state during candidate creation.
- [x] Validate external test evidence against the candidate branch, merge state, and exact Git tree SHA.
- [x] Require timezone-aware verification timestamps, reviewer identity, passing test entries, and evidence references.
- [x] Authenticate CI run metadata and pin the workflow file to a trusted blob SHA.
- [x] Create an exact-tree verification snapshot locally without changing the original product branch or candidate merge state.
- [x] Validate a published snapshot through authenticated verification and acceptance end-to-end using synthetic GitHub fixtures.
- [x] Remove both retained temporary verification/test refs through separate manual dispatches of the approval-gated cleanup workflow; both runs succeeded and both refs were independently verified absent (cleanup runs #2 and #3).
- [x] Resolve the stored upstream baseline by default after validating committed baseline/provenance identity and ancestry; retain explicit SHA overrides.
- [x] Add explicit candidate acceptance with original-HEAD/branch/clean-tree rechecks and fast-forward-only update.
- [x] Advance the stored upstream baseline only with the accepted branch update.
- [x] Record sync provenance, reviewer/test evidence, rights acknowledgement, and resulting merge commit.
- [x] Add explicit recovery for interruption after candidate provenance/baseline commit and before original fast-forward, with committed-record integrity checks.
- [x] Add deletion and rename-with-local-edit conflict tests.
- [x] Add guarded candidate discard for the uncommitted merge state and the exact pre-provenance merge commit; verify the original repository remains unchanged.
- [x] Expand failure-injection coverage for partial provenance writes and additional acceptance/recovery races (PRs #35 and #36 cover concurrent recovery fast-forward rejection and interruption after the baseline write; the earlier provenance-write interruption test remains covered).

## Phase 4 — Configuration and branding planning

- [x] Define versioned project and branding JSON schemas (PR #43); validate both Draft 2020-12 schema documents and example files, with negative-case coverage (PR #44).
- [x] Validate names, colors, URLs, assets, and safe paths through strict schema checks plus read-only runtime asset containment/symlink/protected-path validation (`usc config-check`, PR #46).
- [x] Create read-only adapter detection and deterministic dry-run plan interfaces (`usc adapter-detect` and `usc customize-plan`, PR #48). The Next.js candidate is now labelled `implemented`; other detected candidates remain `detected_not_implemented`. Adapter-specific checks and rights review still gate use.
- [x] Test invalid and unsafe configuration, including schema violations, traversal, symlink escapes, missing assets, reserved metadata, and protected notice paths (PRs #44 and #46).
- [ ] Complete the remaining cross-adapter write-policy specification; the first Next.js adapter now enforces fixed USC-marked files and USC-owned asset targets, with each future adapter requiring its own enforcement and tests.

## Phase 5 — First web adapter

- [x] Add a minimal MIT-licensed Next.js App Router fixture for adapter tests.
- [x] Support only explicitly detected, USC-marked Next.js App Router branding locations.
- [x] Implement product name, logo/favicon, and theme changes in the guarded Next.js adapter.
- [x] Keep licence/notice files outside the adapter write allowlist and test that they remain byte-for-byte unchanged.
- [x] Generate deterministic unified diffs for UTF-8 text changes and an explicit binary/size-limit marker; return a per-file application change report.
- [x] Test unrelated files, the MIT licence, NOTICE, and USC upstream-baseline metadata remain unchanged.
- [x] Test that non-overlapping upstream updates preserve applied branding in an isolated candidate, while edits to the same USC branding marker block without changing the customized repository.

## Phase 6 — Isolated build and provenance

- [x] Add the initial Docker-only isolated build runner API: explicit approval, digest-pinned pre-provisioned image, no network, non-root execution, read-only source, bounded tmpfs output, resource/time/log limits, and cleanup verification (PR #55). This is not yet a customer-ready workflow or CLI.
- [x] Stage a bounded immutable source snapshot, exclude VCS/USC metadata and known credential paths, reject symlinks/non-regular files, strip privileged mode bits, and compute a deterministic USC SHA-256 content fingerprint (PR #56).
- [x] Bind the source snapshot to the exact Git commit/tree identity and included committed blob IDs; reject dirty/index-mismatched, ignored/untracked, symlink, submodule, filter/smudge, and staging-race cases (PR #59).
- [x] Add bounded content scanning for selected high-confidence credential formats; block snapshot creation on findings and report only rule IDs/path, never matched values (PR #64; CI #252 passed). This is defence in depth, not comprehensive secret detection.
- [x] Capture approved command identity, command fingerprint, pinned image reference and local image ID, Docker engine version, timestamps, duration, exit outcome, bounded logs, and best-effort redaction; validate the report against a versioned evidence schema (PR #57).
- [x] Hash exported output files and create a deterministic artifact inventory digest; reject symlinks, special files, and oversized inventories (PR #57).
- [x] Bind build evidence and artifact inventory to the accepted upstream baseline and sync history through the validated detached manifest (PR #61).
- [x] Define a detached, versioned build provenance manifest contract and strict JSON Schema covering source, upstream, customization, build evidence, artifact hashes, and no-release state (PR #58).
- [x] Implement detached manifest construction, evidence/artifact digest verification, exact Git-tree-to-snapshot revalidation, and accepted-sync provenance cross-checks (PR #61).\n- [x] Record the exact pinned USC exporter image reference/ID and output-volume cleanup result in build provenance; reject passed build evidence without confirmed volume cleanup (Phase 6 evidence-hardening batch).
- [x] Capture a fixed in-image toolchain inventory with bounded version output, per-probe isolation, and deterministic digest in build evidence and provenance (PR #63; CI #246 passed).
- [x] Add a reviewed CLI approval workflow with short-lived HMAC-authenticated receipts, exact clean Git revision/image/profile binding, explicit review, fixed allowlisted argv, expiry, and one-time replay protection (PR #66; CI #256 passed). Initial profiles are `python-pytest` and synthetic-only `python-container-smoke`; local HMAC state is a guardrail, not external identity proof.
- [x] Validate the runner against a live Docker 29.4.2 daemon using a synthetic clean Git fixture, digest-pinned Python build image, and pinned BusyBox exporter helper; verify non-root identity, network-disabled execution, read-only root/source, bounded tmpfs output, artifact export, and container/volume cleanup (trusted-main workflow run #5). This is a runtime smoke test, not a container-escape penetration test.
- [ ] Complete failure-injection coverage for remaining output-path/export races, helper startup, volume creation/removal, and interrupted export.
- [ ] Keep artifacts detached from automatic public release; no automatic publishing or deployment is authorized.

## Phase 7 — Additional adapters

- [ ] Prioritize based on real project demand.
- [ ] Add one adapter at a time with fixtures and tests.
- [ ] Consider Android/Windows only after toolchains and rights requirements are validated.

A phase is complete only when its acceptance criteria are tested, documented, and reflected in GitHub Issues. Planned capabilities must not be described as implemented.


## Supplementary upstream-sync improvements — updated after live validation

The following status reflects the synthetic live remote test and current failure-injection coverage. It does not claim arbitrary customer applications are semantically protected.

1. [x] Run a real public-GitHub verification snapshot through completed CI, authenticated `sync-verify`, and `sync-accept` in an isolated local clone. The test confirmed the exact candidate tree, one-parent snapshot, preserved custom-only feature, upstream-only improvement, and baseline/provenance advancement.
2. [x] Add failure-injection coverage for candidate tampering after verification, baseline/provenance mismatch, rights-review acknowledgement tampering, failed verification, and interruption before provenance/baseline commit.
3. [x] Cover core deletion/rename cases: upstream deletion of a locally modified file blocks; deletion of an unmodified upstream-owned file integrates; unambiguous upstream rename preserves a local edit; rename/rename and delete/rename conflicts block.
4. [x] Clean up temporary live-test and verification refs through the approval-gated workflow. Each ref was deleted in its own manual dispatch with an exact expected SHA; both cleanup runs succeeded and both refs were verified absent.
5. [x] Implement v1 declarative customization registry schema, exact-path validation, protection-mode checks, and read-only `usc customization-check` CLI.
6. [x] Integrate registry entries into sync planning and acceptance; require evidence for every declared regression test ID against the exact candidate tree. USC validates evidence but does not execute project tests.
7. [ ] Add JSON three-way structured merge with schema validation and conservative conflict behaviour.
8. [ ] Consider a restricted YAML merge only after JSON fidelity and conflict tests pass.
9. [ ] Add optional scheduled upstream monitoring that creates review PRs only; never merge or advance product baselines automatically.
10. [ ] Consider AI-assisted conflict explanations as advisory output only. AI must not choose or apply a resolution, waive a protection rule, or approve a candidate.
11. [ ] Defer GitHub App fan-out/distribution until the local candidate lifecycle, permissions model, and recovery behaviour are proven.

### Live validation evidence

- Snapshot commit: `04f4f14b01be8be97bf361490c7167bc3ec0722c`
- Completed authenticated CI push run: https://github.com/JennyJoshua/universal-software-customizer/actions/runs/44633531926
- Follow-on live acceptance workflow: https://github.com/JennyJoshua/universal-software-customizer/actions/runs/44633580230
- Failure-matrix PR #21: https://github.com/JennyJoshua/universal-software-customizer/pull/21
- Rights/deletion PR #22: https://github.com/JennyJoshua/universal-software-customizer/pull/22

The live fixture uses synthetic files in this repository and accepts only inside a temporary local clone. No product remote branch was pushed. This proves the remote evidence-to-acceptance mechanics for the tested scenario, not semantic compatibility for arbitrary applications.

The reference-project review is recorded in `docs/reference-implementations.md`. Reuse concepts only; do not copy code until each source file's licence, attribution, dependencies, security implications, and compatibility have been reviewed.
