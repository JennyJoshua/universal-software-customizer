from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from customizer.build_evidence import create_artifact_inventory, inspect_git_source
from customizer.build_provenance import (
    _upstream_context,
    create_build_provenance_manifest,
    validate_build_provenance,
)
from customizer.build_runner import _EXPORT_HELPER_IMAGE, _stage_source_snapshot


SCHEMA_PATH = (
    Path(__file__).parents[1]
    / "engine"
    / "customizer"
    / "schemas"
    / "build-provenance.schema.json"
)


def _schema():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def _manifest():
    digest = "a" * 64
    git_sha = "b" * 40
    return {
        "schema_version": "1.0",
        "operation": "usc_build_provenance",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "repository_url": "https://github.com/example/project",
            "commit_sha": git_sha,
            "tree_sha": "c" * 40,
            "snapshot_sha256": digest,
            "worktree_clean": True,
        },
        "upstream": None,
        "customization": {
            "project_id": "synthetic-fixture",
            "registry_sha256": None,
            "project_config_sha256": None,
            "branding_config_sha256": None,
        },
        "build": {
            "evidence_path": "evidence/build-report.json",
            "evidence_sha256": digest,
            "status": "passed",
            "command_sha256": digest,
            "image": "python:3.12-slim@sha256:" + digest,
            "docker_image_id": "sha256:" + digest,
            "export_helper_image": _EXPORT_HELPER_IMAGE,
            "export_helper_image_id": "sha256:" + "e" * 64,
            "output_volume_cleanup_confirmed": True,
            "source_snapshot_sha256": digest,
            "artifact_inventory_sha256": digest,
            "docker_engine_version": "27.0",
            "toolchain_inventory_sha256": hashlib.sha256(b"[]").hexdigest(),
        },
        "artifacts": [
            {"path": "artifacts/app.zip", "size_bytes": 123, "sha256": digest}
        ],
        "release_authorized": False,
    }


def test_build_provenance_schema_is_valid_and_accepts_synthetic_manifest():
    validator = Draft202012Validator(_schema(), format_checker=FormatChecker())
    errors = list(validator.iter_errors(_manifest()))
    assert errors == []


@pytest.mark.parametrize(
    ("mutate", "expected_fragment"),
    [
        (lambda item: item["source"].update(commit_sha="short"), "commit_sha"),
        (lambda item: item["source"].update(repository_url="https://user:pass@example.test/repo"), "repository_url"),
        (lambda item: item.update(release_authorized=True), "release_authorized"),
        (lambda item: item["artifacts"][0].update(path="../escape.zip"), None),
        (lambda item: item["build"].update(extra_field="unexpected"), "extra_field"),
    ],
)
def test_build_provenance_schema_rejects_invalid_manifest(mutate, expected_fragment):
    manifest = _manifest()
    mutate(manifest)
    validator = Draft202012Validator(_schema(), format_checker=FormatChecker())
    errors = list(validator.iter_errors(manifest))
    assert errors
    if expected_fragment:
        assert any(expected_fragment in str(error.message) or expected_fragment in ".".join(map(str, error.path)) for error in errors)



def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_repo(root: Path) -> None:
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "USC Provenance Fixture")
    _git(root, "config", "user.email", "usc-provenance@example.test")


def _make_source(root: Path, *, with_upstream: bool = False) -> dict:
    _init_repo(root)
    (root / "app.py").write_text("print('initial')\\n", encoding="utf-8")
    (root / ".gitignore").write_text("ignored.tmp\\n", encoding="utf-8")
    usc = root / ".usc"
    usc.mkdir()
    (usc / "customizations.json").write_text(
        json.dumps({"schema_version": "1.0", "project_id": "fixture-project", "entries": []}),
        encoding="utf-8",
    )
    _git(root, "add", "app.py", ".gitignore", ".usc/customizations.json")
    _git(root, "commit", "-qm", "initial fixture source")

    context = {}
    if with_upstream:
        upstream_repo = root.parent / "upstream"
        _init_repo(upstream_repo)
        (upstream_repo / "upstream.txt").write_text("base\\n", encoding="utf-8")
        _git(upstream_repo, "add", "upstream.txt")
        _git(upstream_repo, "commit", "-qm", "upstream base")
        base_sha = _git(upstream_repo, "rev-parse", "HEAD")
        (upstream_repo / "upstream.txt").write_text("target\\n", encoding="utf-8")
        _git(upstream_repo, "add", "upstream.txt")
        _git(upstream_repo, "commit", "-qm", "upstream target")
        target_sha = _git(upstream_repo, "rev-parse", "HEAD")

        (root / "app.py").write_text("print('accepted upstream merge')\\n", encoding="utf-8")
        _git(root, "add", "app.py")
        _git(root, "commit", "-qm", "fixture accepted upstream merge")
        merge_sha = _git(root, "rev-parse", "HEAD")

        provenance_dir = usc / "provenance"
        provenance_dir.mkdir()
        provenance_path = f".usc/provenance/sync-{target_sha}.json"
        provenance = {
            "schema_version": "1.0",
            "operation": "accepted_upstream_sync",
            "upstream_repository_url": "https://github.com/example/upstream",
            "base_sha": base_sha,
            "upstream_target_sha": target_sha,
            "merge_commit_sha": merge_sha,
        }
        provenance_bytes = json.dumps(provenance, sort_keys=True).encode("utf-8")
        (root / provenance_path).write_bytes(provenance_bytes)
        baseline = {
            "schema_version": "1.0",
            "upstream_repository_url": "https://github.com/example/upstream",
            "last_imported_upstream_sha": target_sha,
            "last_customized_merge_commit_sha": merge_sha,
            "provenance_path": provenance_path,
        }
        (usc / "upstream-baseline.json").write_text(
            json.dumps(baseline, sort_keys=True), encoding="utf-8"
        )
        _git(root, "add", ".usc")
        _git(root, "commit", "-qm", "record accepted sync provenance")
        context = {
            "base_sha": base_sha,
            "target_sha": target_sha,
            "merge_sha": merge_sha,
            "provenance_path": provenance_path,
        }
    return context


def _write_evidence(root: Path, evidence_root: Path, artifacts_root: Path) -> tuple[bytes, dict]:
    identity = inspect_git_source(root)
    assert identity["source_worktree_clean"] is True
    import tempfile
    with tempfile.TemporaryDirectory(prefix="test-provenance-stage-") as temp:
        snapshot_sha, excluded_count = _stage_source_snapshot(
            root,
            Path(temp) / "source",
            expected_git_blobs=identity["_tracked_blob_sha_by_path"],
        )
    inventory, inventory_sha = create_artifact_inventory(artifacts_root)
    report = {
        "schema_version": "1.0",
        "operation": "isolated_build",
        "status": "passed",
        "executed": True,
        "exit_code": 0,
        "image": "python:3.12-slim@sha256:" + "a" * 64,
        "docker_image_id": "sha256:" + "b" * 64,
        "export_helper_image": "busybox@sha256:" + "d" * 64,
        "export_helper_image_id": "sha256:" + "e" * 64,
        "output_volume_cleanup_confirmed": True,
        "docker_engine_version": "27.0",
        "command_argv": ["python", "-m", "pytest"],
        "command_sha256": "c" * 64,
        "timeout_seconds": 300,
        "log_bytes": 0,
        "log_truncated": False,
        "logs": "",
        "logs_sha256": hashlib.sha256(b"").hexdigest(),
        "source_read_only": True,
        "network_disabled": True,
        "source_snapshot_sha256": snapshot_sha,
        "source_git_commit_sha": identity["source_git_commit_sha"],
        "source_git_tree_sha": identity["source_git_tree_sha"],
        "source_worktree_clean": True,
        "source_git_identity_error": None,
        "excluded_source_path_count": excluded_count,
        "artifact_exported": True,
        "artifact_inventory": inventory,
        "artifact_inventory_sha256": inventory_sha,
        "toolchain_inventory": [],
        "toolchain_inventory_sha256": hashlib.sha256(b"[]").hexdigest(),
        "container_cleanup_confirmed": True,
    }
    raw = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "build-report.json").write_bytes(raw)
    return raw, report


def test_create_manifest_reverifies_evidence_source_and_artifacts(tmp_path):
    source = tmp_path / "source"
    _make_source(source)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "app.zip").write_bytes(b"synthetic build artifact")
    project_config = tmp_path / "project.json"
    branding_config = tmp_path / "branding.json"
    project_config.write_text('{"schema_version":1}', encoding="utf-8")
    branding_config.write_text('{"schema_version":1}', encoding="utf-8")
    raw_evidence, report = _write_evidence(source, evidence_root, artifacts)

    manifest = create_build_provenance_manifest(
        source,
        evidence_root,
        "build-report.json",
        artifacts,
        project_config_path=project_config,
        branding_config_path=branding_config,
    )

    assert manifest["source"]["commit_sha"] == report["source_git_commit_sha"]
    assert manifest["source"]["tree_sha"] == report["source_git_tree_sha"]
    assert manifest["build"]["evidence_sha256"] == hashlib.sha256(raw_evidence).hexdigest()
    assert manifest["build"]["source_snapshot_sha256"] == report["source_snapshot_sha256"]
    assert manifest["build"]["export_helper_image"] == report["export_helper_image"]
    assert manifest["build"]["export_helper_image_id"] == report["export_helper_image_id"]
    assert manifest["build"]["output_volume_cleanup_confirmed"] is True
    assert manifest["artifacts"][0]["path"] == "artifacts/app.zip"
    assert manifest["customization"]["project_id"] == "fixture-project"
    assert manifest["customization"]["registry_sha256"]
    assert manifest["customization"]["project_config_sha256"] == hashlib.sha256(project_config.read_bytes()).hexdigest()
    assert manifest["customization"]["branding_config_sha256"] == hashlib.sha256(branding_config.read_bytes()).hexdigest()
    assert manifest["upstream"] is None
    assert manifest["release_authorized"] is False
    validate_build_provenance(manifest)


def test_create_manifest_cross_checks_accepted_upstream_baseline_and_provenance(tmp_path):
    source = tmp_path / "source"
    context = _make_source(source, with_upstream=True)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "app.zip").write_bytes(b"synthetic artifact")
    _write_evidence(source, evidence_root, artifacts)

    manifest = create_build_provenance_manifest(
        source, evidence_root, "build-report.json", artifacts
    )

    assert manifest["upstream"]["baseline_sha"] == context["target_sha"]
    assert manifest["upstream"]["target_sha"] == context["target_sha"]
    assert manifest["upstream"]["accepted_merge_commit_sha"] == context["merge_sha"]
    assert manifest["upstream"]["provenance_path"] == context["provenance_path"]
    assert len(manifest["upstream"]["provenance_sha256"]) == 64


def test_manifest_rejects_changed_source_after_build_evidence(tmp_path):
    source = tmp_path / "source"
    _make_source(source)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write_evidence(source, evidence_root, artifacts)
    (source / "app.py").write_text("tampered after build\\n", encoding="utf-8")

    with pytest.raises(ValueError, match="clean, exact Git source identity"):
        create_build_provenance_manifest(
            source, evidence_root, "build-report.json", artifacts
        )


def test_manifest_rejects_artifact_changes_after_build(tmp_path):
    source = tmp_path / "source"
    _make_source(source)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    artifact = artifacts / "app.zip"
    artifact.write_bytes(b"original artifact")
    _write_evidence(source, evidence_root, artifacts)
    artifact.write_bytes(b"modified artifact")

    with pytest.raises(ValueError, match="Actual artifact files do not match"):
        create_build_provenance_manifest(
            source, evidence_root, "build-report.json", artifacts
        )


def test_manifest_rejects_unsafe_evidence_paths(tmp_path):
    source = tmp_path / "source"
    _make_source(source)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write_evidence(source, evidence_root, artifacts)

    with pytest.raises(ValueError, match="normalized relative path"):
        create_build_provenance_manifest(
            source, evidence_root, "../build-report.json", artifacts
        )


def test_upstream_context_rejects_mismatched_baseline_and_provenance(tmp_path):
    source = tmp_path / "source"
    _make_source(source, with_upstream=True)
    baseline_path = source / ".usc" / "upstream-baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["last_imported_upstream_sha"] = "f" * 40
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    _git(source, "add", ".usc/upstream-baseline.json")
    _git(source, "commit", "-qm", "fixture deliberately mismatched baseline")
    identity = inspect_git_source(source)

    with pytest.raises(ValueError, match="target SHA does not match"):
        _upstream_context(source, identity["_tracked_blob_sha_by_path"])



def test_create_manifest_rejects_passed_evidence_without_exporter_identity(tmp_path):
    source = tmp_path / "source"
    _make_source(source)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "app.zip").write_bytes(b"synthetic build artifact")
    _write_evidence(source, evidence_root, artifacts)
    report_path = evidence_root / "build-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report.pop("export_helper_image")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="missing provenance fields"):
        create_build_provenance_manifest(source, evidence_root, "build-report.json", artifacts)


def test_create_manifest_rejects_passed_evidence_without_volume_cleanup(tmp_path):
    source = tmp_path / "source"
    _make_source(source)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "app.zip").write_bytes(b"synthetic build artifact")
    _write_evidence(source, evidence_root, artifacts)
    report_path = evidence_root / "build-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["output_volume_cleanup_confirmed"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="must confirm cleanup"):
        create_build_provenance_manifest(source, evidence_root, "build-report.json", artifacts)



def test_create_manifest_rejects_unapproved_export_helper_image(tmp_path):
    source = tmp_path / "source"
    _make_source(source)
    evidence_root = tmp_path / "evidence"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "app.zip").write_bytes(b"synthetic build artifact")
    _write_evidence(source, evidence_root, artifacts)
    report_path = evidence_root / "build-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["export_helper_image"] = "busybox@sha256:" + "f" * 64
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="pinned USC export-helper image"):
        create_build_provenance_manifest(source, evidence_root, "build-report.json", artifacts)
