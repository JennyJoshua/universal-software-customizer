"""Command-line entry point for safe repository inspection and sync planning."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .inspector import InspectionError, inspect_github_repository, inspect_repository
from .licensing import LicenceScanError, scan_licence_evidence
from .customizations import inspect_customization_registry
from .configuration import validate_project_branding_configuration
from .planning import detect_adapters, create_customization_dry_run
from .web_nextjs import apply_nextjs_branding
from .sync import SyncPlanError, create_sync_candidate, create_sync_plan, resolve_sync_base
from .verification import create_sync_verification
from .verification_snapshot import create_sync_verification_snapshot
from .acceptance import accept_sync_candidate, recover_sync_acceptance
from .candidate_discard import discard_sync_candidate
from .build_approval import create_build_approval_request, approve_build_request, consume_build_approval, available_build_profiles
from .build_runner import run_isolated_build
from .source_inventory import create_source_review


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="usc",
        description="Inspect source repositories and plan safe upstream synchronization without executing source code.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Create a static repository inspection report.")
    source = inspect_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", help="Existing local source directory.")
    source.add_argument("--repo-url", help="Public HTTPS GitHub repository URL.")
    inspect_parser.add_argument("--revision", help="Required with --repo-url: branch, tag, or commit to inspect.")
    inspect_parser.add_argument("--output", help="Write JSON report to this path instead of stdout.")

    licence_parser = subparsers.add_parser(
        "licences", help="Collect project, dependency, asset, and attribution evidence for human review."
    )
    licence_parser.add_argument("--path", required=True, help="Existing local source directory.")
    licence_parser.add_argument("--output", help="Write JSON report to this path instead of stdout.")

    registry_parser = subparsers.add_parser(
        "customization-check", help="Validate the declarative custom-feature registry without changing project files."
    )
    registry_parser.add_argument("--path", required=True, help="Existing customized project directory.")
    registry_parser.add_argument("--output", help="Write JSON report outside the project directory.")

    config_parser = subparsers.add_parser(
        "config-check", help="Validate project and branding configuration without changing or executing project files."
    )
    config_parser.add_argument("--path", required=True, help="Existing customized project directory.")
    config_parser.add_argument("--project-config", required=True, help="Path to project.json configuration.")
    config_parser.add_argument("--branding-config", required=True, help="Path to branding.json configuration.")
    config_parser.add_argument("--output", help="Write JSON report outside the project directory.")

    detect_parser = subparsers.add_parser("adapter-detect", help="Detect technology and adapter candidates without executing project code.")
    detect_parser.add_argument("--path", required=True, help="Existing local source directory.")
    detect_parser.add_argument("--output", help="Write JSON report outside the source directory.")

    plan_parser = subparsers.add_parser("customize-plan", help="Create a read-only branding dry-run plan; no changes are applied.")
    plan_parser.add_argument("--path", required=True, help="Existing local source directory.")
    plan_parser.add_argument("--project-config", required=True, help="Path to project.json configuration.")
    plan_parser.add_argument("--branding-config", required=True, help="Path to branding.json configuration.")
    plan_parser.add_argument("--output", help="Write JSON report outside the source directory.")

    apply_parser = subparsers.add_parser("customize-apply", help="Apply the guarded Next.js branding plan after explicit approval.")
    apply_parser.add_argument("--path", required=True, help="Customized Next.js project directory.")
    apply_parser.add_argument("--project-config", required=True, help="Path to project.json configuration.")
    apply_parser.add_argument("--branding-config", required=True, help="Path to branding.json configuration.")
    apply_parser.add_argument("--plan-report", required=True, help="Reviewed JSON report emitted by customize-plan.")
    apply_parser.add_argument("--approve", action="store_true", help="Explicitly approve applying the reviewed plan.")
    apply_parser.add_argument("--output", help="Write JSON report outside the source directory.")

    sync_parser = subparsers.add_parser(
        "sync-plan", help="Create a read-only three-way upstream synchronization plan."
    )
    sync_parser.add_argument("--path", required=True, help="Customized Git working repository.")
    sync_parser.add_argument("--base-sha", help="Explicit full SHA override; otherwise load the validated stored baseline.")
    sync_parser.add_argument("--upstream-url", help="Expected HTTPS GitHub upstream URL when loading the stored baseline.")
    sync_parser.add_argument("--target-sha", required=True, help="Full SHA of the selected newer upstream commit.")
    sync_parser.add_argument("--output", help="Write JSON plan outside the repository.")

    candidate_parser = subparsers.add_parser(
        "sync-candidate", help="Create an isolated, uncommitted upstream integration candidate."
    )
    candidate_parser.add_argument("--path", required=True, help="Customized Git working repository.")
    candidate_parser.add_argument("--base-sha", help="Explicit full SHA override; otherwise load the validated stored baseline.")
    candidate_parser.add_argument("--upstream-url", help="Expected HTTPS GitHub upstream URL when loading the stored baseline.")
    candidate_parser.add_argument("--target-sha", required=True, help="Full SHA of the selected newer upstream commit.")
    candidate_parser.add_argument("--workspace", required=True, help="New candidate directory outside the source repository.")
    candidate_parser.add_argument("--approve", action="store_true", help="Confirm creation of the isolated candidate.")
    candidate_parser.add_argument(
        "--rights-reviewed", action="store_true",
        help="Confirm human review of changed upstream licence/notice files when the plan flags them."
    )
    candidate_parser.add_argument("--output", help="Write JSON candidate report outside both repositories.")

    snapshot_parser = subparsers.add_parser("sync-snapshot", help="Create an isolated verification-only commit for a candidate tree.")
    snapshot_parser.add_argument("--path", required=True, help="Original customized Git working repository.")
    snapshot_parser.add_argument("--candidate-report", required=True, help="JSON report emitted by sync-candidate.")
    snapshot_parser.add_argument("--push-url", required=True, help="HTTPS GitHub URL of the customized fork; the command will not push.")
    snapshot_parser.add_argument("--output", help="Write snapshot report outside both repositories.")

    verify_parser = subparsers.add_parser(
        "sync-verify", help="Validate external test evidence against an unchanged candidate tree."
    )
    verify_parser.add_argument("--candidate-report", required=True, help="JSON report emitted by sync-candidate.")
    verify_parser.add_argument("--evidence", required=True, help="Reviewer-supplied JSON test evidence.")
    verify_parser.add_argument("--snapshot-report", help="JSON report emitted by sync-snapshot; required for authenticated mode.")
    verify_parser.add_argument("--github-run-url", help="Canonical GitHub Actions run URL for a published candidate snapshot.")
    verify_parser.add_argument("--github-repo", help="Trusted GitHub OWNER/REPOSITORY for the Actions run.")
    verify_parser.add_argument("--workflow-id", type=int, help="Trusted numeric GitHub Actions workflow ID.")
    verify_parser.add_argument("--workflow-path", help="Trusted repository-relative workflow path.")
    verify_parser.add_argument("--workflow-blob-sha", help="Pinned Git blob SHA of the trusted workflow file.")
    verify_parser.add_argument("--output", help="Write verification report outside the candidate workspace.")

    accept_parser = subparsers.add_parser(
        "sync-accept", help="Accept a verified candidate and fast-forward the unchanged customized branch."
    )
    accept_parser.add_argument("--path", required=True, help="Original customized Git working repository.")
    accept_parser.add_argument("--candidate-report", required=True, help="JSON report emitted by sync-candidate.")
    accept_parser.add_argument("--verification-report", required=True, help="JSON report emitted by sync-verify.")
    accept_parser.add_argument("--upstream-url", required=True, help="Canonical HTTPS GitHub owner/repository URL.")
    accept_parser.add_argument("--approve", action="store_true", help="Explicitly approve updating the original branch.")
    accept_parser.add_argument(
        "--evidence-reviewed", action="store_true",
        help="Confirm that you personally reviewed the supplied CI/test evidence; it is not independently authenticated."
    )
    accept_parser.add_argument("--output", help="Write acceptance report outside both repositories.")

    recover_parser = subparsers.add_parser("sync-recover", help="Resume fast-forward after candidate provenance was committed.")
    recover_parser.add_argument("--path", required=True, help="Original customized Git repository.")
    recover_parser.add_argument("--candidate-report", required=True, help="Report emitted by sync-candidate.")
    recover_parser.add_argument("--approve", action="store_true", help="Explicitly approve recovery fast-forward.")
    recover_parser.add_argument("--output", help="Write recovery report outside both repositories.")

    discard_parser = subparsers.add_parser("sync-discard", help="Discard only a validated USC-created uncommitted candidate workspace.")
    discard_parser.add_argument("--path", required=True, help="Original customized Git working repository.")
    discard_parser.add_argument("--candidate-report", required=True, help="Report emitted by sync-candidate.")
    discard_parser.add_argument("--approve", action="store_true", help="Explicitly approve removal of the validated candidate workspace.")
    discard_parser.add_argument("--output", help="Write discard report outside both repositories.")

    source_review = subparsers.add_parser("source-review", help="Create a bounded, read-only source inventory for human review; never executes project code.")
    source_review.add_argument("--path", required=True, help="Existing source directory to inventory.")
    source_review.add_argument("--output", help="Write JSON report outside the source directory.")

    build_request = subparsers.add_parser("build-request", help="Create a short-lived request for one allowlisted isolated-build profile; does not execute code.")
    build_request.add_argument("--path", required=True, help="Clean Git source directory to bind to this request.")
    build_request.add_argument("--image", required=True, help="Pre-provisioned image pinned by a full sha256 digest.")
    build_request.add_argument("--profile", required=True, choices=sorted(available_build_profiles()), help="Fixed allowlisted command profile.")
    build_request.add_argument("--timeout", type=int, default=300, help="Maximum build duration in seconds (1-3600).")
    build_request.add_argument("--expires-in", type=int, default=900, help="Request lifetime in seconds (60-1800).")
    build_request.add_argument("--output", required=True, help="Write approval request JSON outside the source directory.")

    build_approve = subparsers.add_parser("build-approve", help="Approve the exact contents of a build request and create a local authenticated receipt.")
    build_approve.add_argument("--request", required=True, help="Request JSON emitted by build-request.")
    build_approve.add_argument("--output", required=True, help="Write receipt JSON outside the source directory.")
    build_approve.add_argument("--approve", action="store_true", help="Explicitly approve this exact source revision, image digest, profile, and time limit.")

    build_run = subparsers.add_parser("build-run", help="Consume a one-time approval receipt and run its fixed profile in Docker.")
    build_run.add_argument("--approval", required=True, help="Authenticated one-time approval receipt.")
    build_run.add_argument("--path", required=True, help="Source directory matching the approved Git revision.")
    build_run.add_argument("--output-dir", required=True, help="Existing empty artifact directory outside the source.")
    build_run.add_argument("--report", help="Write build evidence JSON outside source and artifact directories.")

    return parser


def _write_report(report: dict, output: str | None, source_root: Path | None = None) -> None:
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output:
        supplied_output = Path(output).expanduser()
        if supplied_output.is_symlink():
            raise ValueError("Report output must not be a symlink.")
        output_path = supplied_output.resolve()
        if source_root is not None and (output_path == source_root or source_root in output_path.parents):
            raise ValueError("Report output must be outside the inspected source directory.")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build-request":
            report = create_build_approval_request(
                args.path, image=args.image, profile=args.profile,
                timeout_seconds=args.timeout, expires_in_seconds=args.expires_in,
            )
            _write_report(report, args.output, Path(report["source_path"]))
        elif args.command == "build-approve":
            request_path = Path(args.request).expanduser()
            if request_path.is_symlink():
                raise ValueError("Build request file must not be a symlink.")
            request_data = json.loads(request_path.read_text(encoding="utf-8"))
            source_root = Path(request_data["source_path"]).expanduser().resolve(strict=True)
            print(
                "USC build approval review:\n"
                f"  Source: {source_root}\n"
                f"  Commit: {request_data.get('source_git_commit_sha')}\n"
                f"  Tree: {request_data.get('source_git_tree_sha')}\n"
                f"  Image: {request_data.get('image')}\n"
                f"  Profile: {request_data.get('profile')}\n"
                f"  Command: {request_data.get('command_argv')}\n"
                f"  Timeout: {request_data.get('timeout_seconds')} seconds\n"
                f"  Expires: {request_data.get('expires_at')}\n"
                "  Release/deployment: NOT authorized",
                file=sys.stderr,
            )
            receipt = approve_build_request(args.request, approved=args.approve)
            _write_report(receipt, args.output, source_root)
        elif args.command == "build-run":
            supplied_source = Path(args.path).expanduser()
            supplied_output = Path(args.output_dir).expanduser()
            if supplied_source.is_symlink() or supplied_output.is_symlink():
                raise ValueError("Build source and artifact directories must not be symlinks.")
            source_root = supplied_source.resolve(strict=True)
            output_dir = supplied_output.resolve(strict=True)
            if output_dir == source_root or source_root in output_dir.parents or output_dir in source_root.parents:
                raise ValueError("Build artifact directory must be separate from the source directory.")
            if args.report:
                supplied_report = Path(args.report).expanduser()
                if supplied_report.is_symlink():
                    raise ValueError("Build evidence report must not be a symlink.")
                report_path = supplied_report.resolve()
                if report_path == source_root or source_root in report_path.parents:
                    raise ValueError("Build evidence report must be outside the source directory.")
                if report_path == output_dir or output_dir in report_path.parents:
                    raise ValueError("Build evidence report must be outside the artifact directory.")
            approved = consume_build_approval(
                args.approval, source_path=supplied_source, output_path=supplied_output,
            )
            report = run_isolated_build(
                approved["source_path"], approved["output_path"],
                image=approved["image"], command=approved["command"],
                approved=True, timeout_seconds=approved["timeout_seconds"],
                max_log_bytes=approved["max_log_bytes"],
            )
            _write_report(report, args.report, source_root)
            if report.get("status") != "passed":
                return 2
        elif args.command == "inspect":
            if args.repo_url:
                if not args.revision:
                    parser.error("--revision is required when using --repo-url.")
                report = inspect_github_repository(args.repo_url, args.revision)
                _write_report(report, args.output)
            else:
                if args.revision:
                    parser.error("--revision can only be used with --repo-url.")
                source_root = Path(args.path).expanduser().resolve()
                report = inspect_repository(source_root)
                _write_report(report, args.output, source_root)
        elif args.command == "licences":
            source_root = Path(args.path).expanduser().resolve()
            report = scan_licence_evidence(source_root)
            _write_report(report, args.output, source_root)
        elif args.command == "customization-check":
            source_root = Path(args.path).expanduser().resolve()
            report = inspect_customization_registry(source_root)
            _write_report(report, args.output, source_root)
            if report.get("status") == "blocked":
                return 2
        elif args.command == "config-check":
            source_root_arg = Path(args.path).expanduser()
            report = validate_project_branding_configuration(
                source_root_arg, args.project_config, args.branding_config,
            )
            _write_report(report, args.output, source_root_arg.resolve())
            if report.get("status") == "blocked":
                return 2
        elif args.command == "adapter-detect":
            source_root = Path(args.path).expanduser().resolve()
            report = detect_adapters(source_root)
            _write_report(report, args.output, source_root)
        elif args.command == "customize-plan":
            source_root = Path(args.path).expanduser().resolve()
            report = create_customization_dry_run(
                source_root, args.project_config, args.branding_config,
            )
            _write_report(report, args.output, source_root)
            if report.get("status", "").startswith("blocked_"):
                return 2
        elif args.command == "customize-apply":
            source_root = Path(args.path).expanduser().resolve()
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                if output_path == source_root or source_root in output_path.parents:
                    raise ValueError("Apply report output must be outside the source directory.")
            plan_path = Path(args.plan_report).expanduser()
            if plan_path.is_symlink():
                raise ValueError("Reviewed plan report must not be a symlink.")
            plan_path = plan_path.resolve(strict=True)
            if not plan_path.is_file():
                raise ValueError("Reviewed plan report must be a regular file.")
            if plan_path == source_root or source_root in plan_path.parents:
                raise ValueError("Reviewed plan report must be outside the source directory.")
            expected_plan = json.loads(plan_path.read_text(encoding="utf-8"))
            if not isinstance(expected_plan, dict):
                raise ValueError("Reviewed plan report must contain a JSON object.")
            report = apply_nextjs_branding(
                source_root, args.project_config, args.branding_config,
                approved=args.approve, expected_plan=expected_plan,
            )
            _write_report(report, args.output, source_root)
            if report.get("status", "").startswith("blocked"):
                return 2
        elif args.command == "source-review":
            source_root = Path(args.path).expanduser().resolve(strict=True)
            report = create_source_review(source_root)
            _write_report(report, args.output, source_root)
        elif args.command == "sync-plan":
            source_root = Path(args.path).expanduser().resolve()
            base_sha = resolve_sync_base(source_root, base_sha=args.base_sha, upstream_url=args.upstream_url)
            report = create_sync_plan(source_root, base_sha, args.target_sha)
            _write_report(report, args.output, source_root)
        elif args.command == "sync-candidate":
            source_root = Path(args.path).expanduser().resolve()
            candidate_path = Path(args.workspace).expanduser().resolve()
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                if output_path == source_root or source_root in output_path.parents:
                    raise ValueError("Report output must be outside the inspected source directory.")
                if output_path == candidate_path or candidate_path in output_path.parents:
                    raise ValueError("Candidate report output must be outside the candidate workspace.")
            report = create_sync_candidate(
                source_root, resolve_sync_base(source_root, base_sha=args.base_sha, upstream_url=args.upstream_url), args.target_sha, args.workspace,
                approved=args.approve, rights_reviewed=args.rights_reviewed,
            )
            _write_report(report, args.output, source_root)
        elif args.command == "sync-snapshot":
            source_root = Path(args.path).expanduser().resolve()
            candidate_data = json.loads(Path(args.candidate_report).expanduser().read_text(encoding="utf-8"))
            candidate_path = Path(candidate_data["candidate_path"]).expanduser().resolve()
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                if output_path == source_root or source_root in output_path.parents:
                    raise ValueError("Snapshot report output must be outside the original repository.")
                if output_path == candidate_path or candidate_path in output_path.parents:
                    raise ValueError("Snapshot report output must be outside the candidate workspace.")
            report = create_sync_verification_snapshot(
                source_root, args.candidate_report, push_url=args.push_url,
            )
            _write_report(report, args.output, source_root)
        elif args.command == "sync-verify":
            report = create_sync_verification(
                args.candidate_report, args.evidence,
                github_run_url=args.github_run_url, github_repository=args.github_repo,
                workflow_id=args.workflow_id, workflow_path=args.workflow_path,
                workflow_blob_sha=args.workflow_blob_sha,
                snapshot_report_path=args.snapshot_report,
            )
            candidate_data = json.loads(Path(args.candidate_report).expanduser().read_text(encoding="utf-8"))
            candidate_path = Path(candidate_data["candidate_path"]).expanduser().resolve()
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                if output_path == candidate_path or candidate_path in output_path.parents:
                    raise ValueError("Verification report output must be outside the candidate workspace.")
            _write_report(report, args.output, candidate_path)
        elif args.command == "sync-accept":
            source_root = Path(args.path).expanduser().resolve()
            candidate_data = json.loads(Path(args.candidate_report).expanduser().read_text(encoding="utf-8"))
            candidate_path = Path(candidate_data["candidate_path"]).expanduser().resolve()
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                if output_path == source_root or source_root in output_path.parents:
                    raise ValueError("Acceptance report output must be outside the original repository.")
                if output_path == candidate_path or candidate_path in output_path.parents:
                    raise ValueError("Acceptance report output must be outside the candidate workspace.")
            report = accept_sync_candidate(
                source_root, args.candidate_report, args.verification_report,
                upstream_url=args.upstream_url, approved=args.approve,
                evidence_reviewed=args.evidence_reviewed,
            )
            _write_report(report, args.output, source_root)
        elif args.command == "sync-recover":
            source_root = Path(args.path).expanduser().resolve()
            candidate_data = json.loads(Path(args.candidate_report).expanduser().read_text(encoding="utf-8"))
            candidate_path = Path(candidate_data["candidate_path"]).expanduser().resolve()
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                if output_path == source_root or source_root in output_path.parents or output_path == candidate_path or candidate_path in output_path.parents:
                    raise ValueError("Recovery report output must be outside both repositories.")
            report = recover_sync_acceptance(source_root, args.candidate_report, approved=args.approve)
            _write_report(report, args.output, source_root)
        else:
            source_root = Path(args.path).expanduser().resolve()
            candidate_data = json.loads(Path(args.candidate_report).expanduser().read_text(encoding="utf-8"))
            candidate_path = Path(candidate_data["candidate_path"]).expanduser().resolve()
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                if output_path == source_root or source_root in output_path.parents or output_path == candidate_path or candidate_path in output_path.parents:
                    raise ValueError("Discard report output must be outside both repositories.")
            report = discard_sync_candidate(source_root, args.candidate_report, approved=args.approve)
            _write_report(report, args.output, source_root)
        return 0
    except (InspectionError, LicenceScanError, SyncPlanError, ValueError, OSError, KeyError) as exc:
        print(f"usc: operation blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
