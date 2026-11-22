"""Detached build provenance construction and verification helpers."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker

from .build_evidence import (
    create_artifact_inventory,
    inspect_git_source,
    validate_build_evidence,
)
from .build_runner import _EXPORT_HELPER_IMAGE, _stage_source_snapshot

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_MAX_METADATA_BYTES = 2 * 1024 * 1024


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _safe_relative_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be a non-empty, trimmed relative path.")
    if "\\" in value or "\x00" in value:
        raise ValueError(f"{label} must not contain backslashes or NUL bytes.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError(f"{label} must be a normalized relative path without traversal.")
    return path.as_posix()


def _resolve_directory(path_value: str | Path, label: str) -> Path:
    supplied = Path(path_value).expanduser()
    absolute = supplied.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path traverses a symlink.")
    resolved = supplied.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{label} must be an existing directory.")
    return resolved


def _read_repository_file(
    root: Path, relative: str, label: str, *, max_bytes: int = _MAX_METADATA_BYTES,
) -> bytes:
    safe = _safe_relative_path(relative, label)
    path = root
    for part in PurePosixPath(safe).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"{label} traverses a symlink: {safe}")
    if not path.is_file():
        raise ValueError(f"{label} is missing or is not a regular file: {safe}")
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_size > max_bytes:
        raise ValueError(f"{label} exceeds its configured size limit: {safe}")
    return path.read_bytes()


def _read_external_config(path_value: str | Path | None, label: str) -> str | None:
    if path_value is None:
        return None
    path = Path(path_value).expanduser()
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path traverses a symlink.")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular file.")
    if resolved.stat().st_size > _MAX_METADATA_BYTES:
        raise ValueError(f"{label} exceeds the 2 MB metadata limit.")
    return hashlib.sha256(resolved.read_bytes()).hexdigest()


def _canonical_github_url(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical HTTPS GitHub repository URL.")
    parsed = urlparse(value)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or len(parts) != 2
    ):
        raise ValueError(f"{label} must be a credential-free HTTPS GitHub OWNER/REPOSITORY URL.")
    owner, repository = parts
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repository.removesuffix(".git")):
        raise ValueError(f"{label} contains an invalid GitHub owner or repository.")
    return f"https://github.com/{owner}/{repository.removesuffix('.git')}"


def _source_repository_url(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-c", f"core.hooksPath={os.devnull}", "-C", str(root), "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10, check=False,
            env={
                **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        return _canonical_github_url(result.stdout.strip(), "Source repository URL")
    except ValueError:
        return None


def _verify_git_blob(relative_path: str, raw: bytes, expected_git_blobs: dict[str, str]) -> None:
    expected = expected_git_blobs.get(relative_path)
    if expected is None:
        raise ValueError(f"Provenance metadata is not tracked in the verified Git tree: {relative_path}")
    algorithm = "sha1" if len(expected) == 40 else "sha256"
    digest = hashlib.new(algorithm)
    digest.update(f"blob {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    if digest.hexdigest() != expected:
        raise ValueError(f"Provenance metadata changed after Git identity inspection: {relative_path}")


def _upstream_context(root: Path, expected_git_blobs: dict[str, str]) -> dict | None:
    usc_dir = root / ".usc"
    if usc_dir.is_symlink():
        raise ValueError(".usc metadata directory must not be a symlink.")
    if not usc_dir.exists():
        return None
    if not usc_dir.is_dir():
        raise ValueError(".usc metadata path is not a directory.")

    baseline_path = usc_dir / "upstream-baseline.json"
    if baseline_path.is_symlink():
        raise ValueError("Upstream baseline must not be a symlink.")
    if not baseline_path.exists():
        return None
    if not baseline_path.is_file():
        raise ValueError("Upstream baseline must be a regular file.")
    baseline_bytes = _read_repository_file(root, ".usc/upstream-baseline.json", "Upstream baseline")
    _verify_git_blob(".usc/upstream-baseline.json", baseline_bytes, expected_git_blobs)
    try:
        baseline = json.loads(baseline_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Upstream baseline is invalid JSON: {exc}") from exc
    if not isinstance(baseline, dict) or baseline.get("schema_version") != "1.0":
        raise ValueError("Upstream baseline has an unsupported or invalid schema.")

    repository_url = _canonical_github_url(baseline.get("upstream_repository_url"), "Upstream repository URL")
    baseline_sha = str(baseline.get("last_imported_upstream_sha", "")).lower()
    merge_sha = str(baseline.get("last_customized_merge_commit_sha", "")).lower()
    if not _SHA_RE.fullmatch(baseline_sha) or not _SHA_RE.fullmatch(merge_sha):
        raise ValueError("Upstream baseline contains an invalid commit SHA.")

    provenance_value = baseline.get("provenance_path")
    provenance_path = _safe_relative_path(provenance_value, "Upstream provenance path")
    provenance_relative = PurePosixPath(provenance_path)
    if provenance_relative.parent != PurePosixPath(".usc/provenance"):
        raise ValueError("Upstream provenance must be a direct child of .usc/provenance.")
    provenance_bytes = _read_repository_file(root, provenance_path, "Accepted upstream provenance")
    _verify_git_blob(provenance_path, provenance_bytes, expected_git_blobs)
    try:
        provenance = json.loads(provenance_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Accepted upstream provenance is invalid JSON: {exc}") from exc
    if not isinstance(provenance, dict) or provenance.get("operation") != "accepted_upstream_sync":
        raise ValueError("Referenced upstream provenance is not an accepted sync record.")
    if _canonical_github_url(provenance.get("upstream_repository_url"), "Provenance upstream URL") != repository_url:
        raise ValueError("Upstream baseline and provenance repository identities do not match.")
    provenance_base_sha = str(provenance.get("base_sha", "")).lower()
    provenance_target_sha = str(provenance.get("upstream_target_sha", "")).lower()
    if not _SHA_RE.fullmatch(provenance_base_sha) or not _SHA_RE.fullmatch(provenance_target_sha):
        raise ValueError("Accepted upstream provenance contains an invalid base/target SHA.")
    if provenance_target_sha != baseline_sha:
        raise ValueError("Upstream baseline target SHA does not match accepted provenance.")
    if str(provenance.get("merge_commit_sha", "")).lower() != merge_sha:
        raise ValueError("Upstream baseline merge SHA does not match accepted provenance.")

    ancestor = subprocess.run(
        ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "protocol.file.allow=never",
         "-C", str(root), "merge-base", "--is-ancestor", merge_sha, "HEAD"],
        capture_output=True, text=True, timeout=20, check=False,
        env={
            **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if ancestor.returncode != 0:
        raise ValueError("Accepted upstream merge commit is not an ancestor of the source HEAD.")

    return {
        "repository_url": repository_url,
        "baseline_sha": baseline_sha,
        "target_sha": str(provenance["upstream_target_sha"]).lower(),
        "accepted_merge_commit_sha": merge_sha,
        "provenance_path": provenance_path,
        "provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
    }


def _registry_context(root: Path, expected_git_blobs: dict[str, str]) -> tuple[str | None, str | None]:
    registry_path = root / ".usc" / "customizations.json"
    if registry_path.is_symlink():
        raise ValueError("Customization registry must not be a symlink.")
    if not registry_path.exists():
        return None, None
    if not registry_path.is_file():
        raise ValueError("Customization registry must be a regular file.")
    if registry_path.stat().st_size > _MAX_METADATA_BYTES:
        raise ValueError("Customization registry exceeds the 2 MB metadata limit.")
    raw = registry_path.read_bytes()
    _verify_git_blob(".usc/customizations.json", raw, expected_git_blobs)
    try:
        registry = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Customization registry is invalid JSON: {exc}") from exc
    if not isinstance(registry, dict):
        raise ValueError("Customization registry root must be a JSON object.")
    project_id = registry.get("project_id")
    if project_id is not None and (not isinstance(project_id, str) or not project_id.strip()):
        raise ValueError("Customization registry project_id must be a non-empty string.")
    return project_id, hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=1)
def _provenance_validator() -> Draft202012Validator:
    schema_path = Path(__file__).with_name("schemas") / "build-provenance.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_build_provenance(manifest: dict) -> None:
    """Raise ValueError unless a detached build provenance manifest matches its schema."""
    errors = sorted(
        _provenance_validator().iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.path) or "manifest"
        raise ValueError(f"Invalid build provenance at {location}: {first.message}")


def create_build_provenance_manifest(
    source_path: str | Path,
    evidence_root: str | Path,
    evidence_path: str,
    artifact_path: str | Path,
    *,
    project_config_path: str | Path | None = None,
    branding_config_path: str | Path | None = None,
) -> dict:
    """Create a detached manifest only after re-verifying source, evidence, upstream, and artifacts.

    The evidence document is read from evidence_root/evidence_path. This function
    returns data only; it does not write into the source repository, mutate Git
    refs, or publish/release artifacts.
    """
    root = _resolve_directory(source_path, "Source")
    evidence_dir = _resolve_directory(evidence_root, "Evidence")
    evidence_relative = _safe_relative_path(evidence_path, "Build evidence path")
    artifacts_root = _resolve_directory(artifact_path, "Artifact")
    directory_roots = [("Source", root), ("Evidence", evidence_dir), ("Artifact", artifacts_root)]
    for index, (left_label, left) in enumerate(directory_roots):
        for right_label, right in directory_roots[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError(f"{left_label} and {right_label} directories must be separate.")

    raw_evidence = _read_repository_file(
        evidence_dir, evidence_relative, "Build evidence", max_bytes=_MAX_EVIDENCE_BYTES,
    )
    if len(raw_evidence) > _MAX_EVIDENCE_BYTES:
        raise ValueError("Build evidence document exceeds the 8 MB limit.")
    try:
        report = json.loads(raw_evidence.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Build evidence document is invalid JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise ValueError("Build evidence document root must be a JSON object.")
    validate_build_evidence(report)
    required_evidence_fields = (
        "command_sha256", "image", "docker_image_id",
        "source_snapshot_sha256", "source_git_commit_sha",
        "source_git_tree_sha", "source_worktree_clean",
        "source_git_identity_error", "excluded_source_path_count",
        "export_helper_image", "export_helper_image_id", "output_volume_cleanup_confirmed",
        "artifact_inventory", "artifact_inventory_sha256",
        "toolchain_inventory", "toolchain_inventory_sha256",
    )
    missing_fields = [key for key in required_evidence_fields if key not in report]
    if missing_fields:
        raise ValueError("Build evidence is missing provenance fields: " + ", ".join(missing_fields))
    if report["source_git_identity_error"] is not None:
        raise ValueError("Build evidence reports a source Git identity error.")
    if report["export_helper_image"] != _EXPORT_HELPER_IMAGE:
        raise ValueError("Build evidence does not identify the pinned USC export-helper image.")
    if not isinstance(report["export_helper_image_id"], str) or not report["export_helper_image_id"]:
        raise ValueError("Build evidence does not identify the local USC export-helper image ID.")
    if report["status"] == "passed" and report["output_volume_cleanup_confirmed"] is not True:
        raise ValueError("A passed build must confirm cleanup of its temporary output volume.")
    toolchain_digest = hashlib.sha256(
        json.dumps(report["toolchain_inventory"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if toolchain_digest != report["toolchain_inventory_sha256"]:
        raise ValueError("Toolchain inventory digest does not match build evidence.")

    identity = inspect_git_source(root)
    if identity["source_worktree_clean"] is not True:
        raise ValueError("Build provenance requires a clean, exact Git source identity: " + str(identity["source_git_identity_error"]))
    if (
        report.get("source_git_commit_sha") != identity["source_git_commit_sha"]
        or report.get("source_git_tree_sha") != identity["source_git_tree_sha"]
        or report.get("source_worktree_clean") is not True
    ):
        raise ValueError("Build evidence source commit/tree identity does not match the current clean source repository.")

    with tempfile.TemporaryDirectory(prefix="usc-provenance-check-") as temporary_root:
        staged = Path(temporary_root) / "source"
        snapshot_sha256, excluded_count = _stage_source_snapshot(
            root,
            staged,
            expected_git_blobs=identity["_tracked_blob_sha_by_path"],
        )
    if snapshot_sha256 != report.get("source_snapshot_sha256"):
        raise ValueError("Reconstructed source snapshot digest does not match the build evidence.")
    if excluded_count != report.get("excluded_source_path_count"):
        raise ValueError("Source exclusion count does not match the build evidence.")

    artifact_inventory, artifact_inventory_sha256 = create_artifact_inventory(artifacts_root)
    if artifact_inventory != report.get("artifact_inventory"):
        raise ValueError("Actual artifact files do not match the build evidence inventory.")
    if artifact_inventory_sha256 != report.get("artifact_inventory_sha256"):
        raise ValueError("Actual artifact inventory digest does not match the build evidence.")

    expected_git_blobs = identity["_tracked_blob_sha_by_path"]
    upstream = _upstream_context(root, expected_git_blobs)
    project_id, registry_sha256 = _registry_context(root, expected_git_blobs)
    project_config_sha256 = _read_external_config(project_config_path, "Project configuration")
    branding_config_sha256 = _read_external_config(branding_config_path, "Branding configuration")

    manifest = {
        "schema_version": "1.0",
        "operation": "usc_build_provenance",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "repository_url": _source_repository_url(root),
            "commit_sha": identity["source_git_commit_sha"],
            "tree_sha": identity["source_git_tree_sha"],
            "snapshot_sha256": snapshot_sha256,
            "worktree_clean": True,
        },
        "upstream": upstream,
        "customization": {
            "project_id": project_id,
            "registry_sha256": registry_sha256,
            "project_config_sha256": project_config_sha256,
            "branding_config_sha256": branding_config_sha256,
        },
        "build": {
            "evidence_path": evidence_relative,
            "evidence_sha256": hashlib.sha256(raw_evidence).hexdigest(),
            "status": report["status"],
            "command_sha256": report["command_sha256"],
            "image": report["image"],
            "docker_image_id": report["docker_image_id"],
            "export_helper_image": report["export_helper_image"],
            "export_helper_image_id": report["export_helper_image_id"],
            "output_volume_cleanup_confirmed": report["output_volume_cleanup_confirmed"],
            "source_snapshot_sha256": snapshot_sha256,
            "artifact_inventory_sha256": artifact_inventory_sha256,
            "docker_engine_version": report.get("docker_engine_version"),
            "toolchain_inventory_sha256": toolchain_digest,
        },
        "artifacts": [
            {
                "path": f"artifacts/{item['path']}",
                "size_bytes": item["size_bytes"],
                "sha256": item["sha256"],
            }
            for item in artifact_inventory
        ],
        "release_authorized": False,
    }
    validate_build_provenance(manifest)
    return manifest
