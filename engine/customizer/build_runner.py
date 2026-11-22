"""Fail-closed disposable build execution using a pre-provisioned Docker image."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import selectors
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .build_evidence import create_artifact_inventory, inspect_git_source, redact_build_logs, validate_build_evidence
from .source_secret_scan import SourceSecretScanner

_PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_EXPORT_HELPER_IMAGE = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
_SHELLS = {"sh", "bash", "dash", "zsh", "fish", "cmd", "powershell", "pwsh"}
_MAX_TIMEOUT = 3600
_MAX_LOG_BYTES = 1_048_576
_SECRET_ARG_PATTERN = re.compile(r"(?i)(?:password|token|secret|api[_-]?key|credential|authorization)[\w-]*\s*[:=]")
_SECRET_FLAGS = {
    "--password", "--token", "--secret", "--api-key", "--apikey",
    "--credential", "--authorization", "--auth-token",
}
_TOOLCHAIN_PROBES = (
    ("python", ("--version",)),
    ("python3", ("--version",)),
    ("node", ("--version",)),
    ("npm", ("--version",)),
    ("git", ("--version",)),
    ("go", ("version",)),
    ("rustc", ("--version",)),
    ("cargo", ("--version",)),
    ("java", ("-version",)),
    ("php", ("--version",)),
    ("ruby", ("--version",)),
    ("dotnet", ("--version",)),
    ("gcc", ("--version",)),
    ("cmake", ("--version",)),
    ("make", ("--version",)),
    ("deno", ("--version",)),
    ("bun", ("--version",)),
    ("uv", ("--version",)),
    ("pytest", ("--version",)),
)
_MAX_TOOLCHAIN_OUTPUT_BYTES = 4096


def _toolchain_inventory_digest(inventory: list[dict]) -> str:
    canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _probe_toolchain(
    docker: str,
    image: str,
    run_label: str,
    *,
    timeout_seconds: float = 3.0,
    max_output_bytes: int = _MAX_TOOLCHAIN_OUTPUT_BYTES,
    probes: Sequence[tuple[str, tuple[str, ...]]] = _TOOLCHAIN_PROBES,
) -> list[dict]:
    """Probe a fixed tool list in disposable, network-disabled containers with bounded output."""
    inventory = []
    for executable, version_args in probes:
        argv = [
            docker, "run", "--pull=never", "--network=none", "--read-only",
            f"--user={os.getuid()}:{os.getgid()}",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--pids-limit=16", "--memory=128m", "--cpus=0.25",
            f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=8m,uid={os.getuid()},gid={os.getgid()},mode=0700",
            f"--label={run_label}", "--rm", "--entrypoint", executable, image, *version_args,
        ]
        process = None
        selector = None
        output = bytearray()
        exit_code = None
        status = "probe_failed"
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout_seconds
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timed_out"
                    process.kill()
                    break
                for key, _ in selector.select(timeout=min(0.1, remaining)):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = max_output_bytes - len(output)
                    if len(chunk) > available:
                        output.extend(chunk[:available])
                        status = "output_limit_exceeded"
                        process.kill()
                        break
                    output.extend(chunk)
                if status in {"timed_out", "output_limit_exceeded"}:
                    break
            try:
                exit_code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                status = "timed_out"
                try:
                    exit_code = process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    exit_code = None
            if status not in {"timed_out", "output_limit_exceeded"}:
                status = "available" if exit_code == 0 else "missing" if exit_code == 127 else "probe_failed"
        except KeyboardInterrupt:
            if process is not None and process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            # A killed Docker CLI can leave its labelled container running.
            _cleanup_labelled_containers(docker, run_label)
            raise
        except (OSError, subprocess.TimeoutExpired):
            status = "probe_failed"
        finally:
            if selector is not None:
                selector.close()
            if process is not None and process.stdout is not None:
                process.stdout.close()

        redacted = redact_build_logs(output.decode("utf-8", errors="replace"))
        first_line = next((line.strip() for line in redacted.splitlines() if line.strip()), "")
        inventory.append({
            "name": executable,
            "status": status,
            "exit_code": exit_code,
            "version": first_line[:256] or None,
            "output_sha256": hashlib.sha256(bytes(output)).hexdigest(),
        })
    return inventory


def _validated_result(report: dict) -> dict:
    report.setdefault("schema_version", "1.0")
    validate_build_evidence(report)
    return report


def _directory(path: str | Path, label: str) -> Path:
    supplied = Path(path).expanduser()
    absolute = supplied.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path must not traverse a symlink.")
    resolved = supplied.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{label} must be an existing directory.")
    return resolved


def _directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        if path.is_symlink():
            return None
        info = path.stat(follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _output_directory_matches(
    output: Path,
    expected_identity: tuple[int, int],
    *,
    require_empty: bool,
) -> bool:
    if _directory_identity(output) != expected_identity:
        return False
    try:
        return not require_empty or not any(output.iterdir())
    except OSError:
        return False


def _validate_request(
    source_path: str | Path,
    output_path: str | Path,
    image: str,
    command: Sequence[str],
    timeout_seconds: int,
    max_log_bytes: int,
) -> tuple[Path, Path, list[str]]:
    if not isinstance(image, str) or not _PINNED_IMAGE.fullmatch(image):
        raise ValueError("Build image must be pinned by an immutable sha256 digest.")
    if not isinstance(command, (list, tuple)) or not 1 <= len(command) <= 32:
        raise ValueError("Command must be a list of 1 to 32 arguments.")
    args = list(command)
    if any(not isinstance(arg, str) or not arg or "\x00" in arg or len(arg) > 4096 for arg in args):
        raise ValueError("Command arguments must be non-empty strings without NUL bytes and at most 4096 characters.")
    executable = Path(args[0]).name.lower()
    if executable in _SHELLS:
        raise ValueError("Shell interpreters are not accepted; provide an executable and arguments directly.")
    for argument in args:
        lowered = argument.lower()
        if lowered in _SECRET_FLAGS or _SECRET_ARG_PATTERN.search(argument) or re.search(r"(?i)://[^/@:\s]+:[^/@\s]+@", argument):
            raise ValueError("Build command arguments must not contain passwords, tokens, credentials, or authenticated URLs.")
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= _MAX_TIMEOUT:
        raise ValueError(f"timeout_seconds must be between 1 and {_MAX_TIMEOUT}.")
    if not isinstance(max_log_bytes, int) or isinstance(max_log_bytes, bool) or not 1024 <= max_log_bytes <= _MAX_LOG_BYTES:
        raise ValueError(f"max_log_bytes must be between 1024 and {_MAX_LOG_BYTES}.")

    source = _directory(source_path, "Source")
    output = _directory(output_path, "Output")
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("Output directory must be separate from, and not an ancestor or descendant of, the source directory.")
    if "," in str(source) or "," in str(output):
        raise ValueError("Source and output paths must not contain commas.")
    if not hasattr(os, "getuid") or not hasattr(os, "getgid") or os.getuid() == 0:
        raise ValueError("The host runner must execute as a non-root user.")
    if not os.access(output, os.W_OK | os.X_OK):
        raise ValueError("Output directory must be writable by the non-root host runner.")
    if any(output.iterdir()):
        raise ValueError("Output directory must be empty before execution.")
    return source, output, args

_EXCLUDED_DIRS = {
    ".git", ".usc", ".ssh", ".aws", ".azure", ".gcloud", ".terraform",
    ".docker", ".kube", ".config", ".firebase",
}
_EXCLUDED_FILE_NAMES = {
    ".git", ".gitconfig", ".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    ".vault-token", ".pgpass", ".my.cnf", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", "credentials", "credentials.json", "secrets.json", "secret.json",
}
_SAFE_ENV_EXAMPLES = {".env.example", ".env.sample", ".env.template"}
_SENSITIVE_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".p8", ".jks", ".keystore",
    ".tfstate", ".secret", ".token", ".mobileprovision",
}
_MAX_SOURCE_BYTES = 256 * 1024 * 1024
_MAX_SOURCE_FILES = 20_000
_MAX_SINGLE_SOURCE_FILE = 50 * 1024 * 1024


def _is_sensitive_file(relative: Path) -> bool:
    name = relative.name.lower()
    suffix = relative.suffix.lower()
    if name in _EXCLUDED_FILE_NAMES:
        return True
    if name.startswith(".env") and name not in _SAFE_ENV_EXAMPLES:
        return True
    if suffix in _SENSITIVE_SUFFIXES:
        return True
    if (name.startswith("service-account") or name.startswith("firebase-adminsdk")) and suffix == ".json":
        return True
    if "credential" in name and suffix in {".json", ".yaml", ".yml", ".toml"}:
        return True
    return False


def _stage_source_snapshot(
    source: Path,
    destination: Path,
    *,
    expected_git_blobs: dict[str, str] | None = None,
) -> tuple[str, int]:
    """Copy a bounded source snapshot and optionally prove each included file matches HEAD."""
    destination.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256()
    total_bytes = 0
    file_count = 0
    excluded_count = 0
    expected_included: dict[str, str] | None = None
    seen_git_paths: set[str] = set()
    if expected_git_blobs is not None:
        expected_included = {}
        for relative_text, blob_sha in expected_git_blobs.items():
            relative_path = Path(relative_text)
            if any(part.lower() in _EXCLUDED_DIRS for part in relative_path.parts[:-1]):
                continue
            if _is_sensitive_file(relative_path):
                continue
            expected_included[relative_path.as_posix()] = blob_sha

    def raise_walk_error(error: OSError) -> None:
        raise error

    for current_text, directories, filenames in os.walk(
        source, topdown=True, followlinks=False, onerror=raise_walk_error,
    ):
        current = Path(current_text)
        kept_directories = []
        for directory in sorted(directories):
            path = current / directory
            if path.is_symlink():
                raise ValueError(f"Source snapshot contains a symlinked directory: {path.relative_to(source)}")
            if directory.lower() in _EXCLUDED_DIRS:
                excluded_count += 1
                continue
            kept_directories.append(directory)
        directories[:] = kept_directories

        for filename in sorted(filenames):
            path = current / filename
            relative = path.relative_to(source)
            relative_text = relative.as_posix()
            if path.is_symlink():
                raise ValueError(f"Source snapshot contains a symlinked file: {relative_text}")
            if _is_sensitive_file(relative):
                excluded_count += 1
                continue
            expected_blob = None
            if expected_included is not None:
                expected_blob = expected_included.get(relative_text)
                if expected_blob is None:
                    raise ValueError(f"Source contains a file outside the inspected Git tree: {relative_text}")
                seen_git_paths.add(relative_text)

            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"Source snapshot contains a non-regular file: {relative_text}")
            if metadata.st_size > _MAX_SINGLE_SOURCE_FILE:
                raise ValueError(f"Source file exceeds the 50 MB per-file limit: {relative_text}")
            total_bytes += metadata.st_size
            file_count += 1
            if total_bytes > _MAX_SOURCE_BYTES:
                raise ValueError("Source snapshot exceeds the 256 MB total size limit.")
            if file_count > _MAX_SOURCE_FILES:
                raise ValueError("Source snapshot exceeds the 20,000-file limit.")

            relative_bytes = os.fsencode(relative_text)
            mode = 0o755 if metadata.st_mode & 0o111 else 0o644
            digest.update(len(relative_bytes).to_bytes(4, "big"))
            digest.update(relative_bytes)
            digest.update(mode.to_bytes(4, "big"))
            digest.update(metadata.st_size.to_bytes(8, "big"))

            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            copied_bytes = 0
            git_blob_digest = None
            if expected_blob is not None:
                algorithm = "sha1" if len(expected_blob) == 40 else "sha256"
                git_blob_digest = hashlib.new(algorithm)
                git_blob_digest.update(f"blob {metadata.st_size}\0".encode("ascii"))
            secret_scanner = SourceSecretScanner()
            with path.open("rb") as source_file, target.open("xb") as target_file:
                while True:
                    chunk = source_file.read(1024 * 1024)
                    if not chunk:
                        break
                    copied_bytes += len(chunk)
                    if copied_bytes > _MAX_SINGLE_SOURCE_FILE:
                        raise ValueError(f"Source file grew beyond the per-file limit during snapshot: {relative_text}")
                    secret_scanner.feed(chunk)
                    if secret_scanner.findings:
                        rules = ", ".join(sorted(secret_scanner.findings))
                        raise ValueError(
                            f"Potential credential material detected in source file {relative_text!r} "
                            f"(rules: {rules}); remove it or place it in a supported excluded secret path."
                        )
                    digest.update(chunk)
                    if git_blob_digest is not None:
                        git_blob_digest.update(chunk)
                    target_file.write(chunk)
            after = path.stat(follow_symlinks=False)
            if (
                copied_bytes != metadata.st_size
                or after.st_size != metadata.st_size
                or after.st_mtime_ns != metadata.st_mtime_ns
                or after.st_ino != metadata.st_ino
            ):
                raise ValueError(f"Source file changed while the snapshot was being staged: {relative_text}")
            if git_blob_digest is not None and git_blob_digest.hexdigest() != expected_blob:
                raise ValueError(f"Staged source file does not match its exact Git tree blob: {relative_text}")
            os.chmod(target, mode)

    if expected_included is not None and seen_git_paths != set(expected_included):
        missing = sorted(set(expected_included) - seen_git_paths)
        raise ValueError("Source snapshot is missing tracked Git files: " + ", ".join(missing[:10]))
    return digest.hexdigest(), excluded_count

def _labelled_container_ids(docker: str, label: str) -> list[str] | None:
    try:
        listing = subprocess.run(
            [docker, "ps", "-aq", "--filter", f"label={label}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if listing.returncode != 0:
            return None
        return listing.stdout.split()
    except (OSError, subprocess.TimeoutExpired):
        return None


def _create_output_volume(docker: str, volume_name: str, run_id: str) -> bool:
    """Create a bounded Docker-managed tmpfs volume for build artifacts."""
    try:
        created = subprocess.run(
            [
                docker, "volume", "create", "--driver", "local",
                "--opt", "type=tmpfs", "--opt", "device=tmpfs",
                "--opt", f"o=size=256m,uid={os.getuid()},gid={os.getgid()},mode=0700",
                "--label", f"com.usc.build-volume={run_id}", volume_name,
            ],
            capture_output=True, text=True, timeout=15, check=False,
        )
        return created.returncode == 0 and created.stdout.strip() == volume_name
    except (OSError, subprocess.TimeoutExpired):
        return False


def _start_export_helper(docker: str, volume_name: str, run_label: str) -> str | None:
    """Keep the output tmpfs mounted read-only until the host has copied its contents."""
    argv = [
        docker, "run", "-d", "--pull=never", "--network=none", "--read-only",
        f"--user={os.getuid()}:{os.getgid()}", "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=16", "--memory=64m", "--cpus=0.25",
        f"--mount=type=volume,src={volume_name},dst=/out,readonly",
        f"--label={run_label}", "--entrypoint=/bin/sleep",
        _EXPORT_HELPER_IMAGE, "7200",
    ]
    try:
        started = subprocess.run(
            argv, capture_output=True, text=True, timeout=15, check=False,
        )
        if started.returncode != 0:
            return None
        container_id = started.stdout.strip()
        return container_id or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _merge_staged_export(
    staged: Path,
    output: Path,
    expected_identity: tuple[int, int],
    staged_inventory: list[dict],
) -> bool:
    """Merge staged artifacts without overwriting files created concurrently."""
    created_files: list[Path] = []
    created_directories: list[Path] = []
    try:
        for root, directories, files in os.walk(staged, followlinks=False):
            directories.sort()
            files.sort()
            relative_root = Path(root).relative_to(staged)
            for name in directories:
                source_directory = Path(root) / name
                if source_directory.is_symlink():
                    raise ValueError("Export staging contains a symlinked directory.")
                target_directory = output / relative_root / name
                if not _output_directory_matches(output, expected_identity, require_empty=False):
                    raise ValueError("Output directory changed during artifact export.")
                if target_directory.exists() or target_directory.is_symlink():
                    raise FileExistsError("Output directory changed during artifact export.")
                target_directory.mkdir(mode=0o700)
                created_directories.append(target_directory)
            for name in files:
                source_file = Path(root) / name
                metadata = source_file.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or source_file.is_symlink():
                    raise ValueError("Export staging contains a symlink or non-regular file.")
                target_file = output / relative_root / name
                if not _output_directory_matches(output, expected_identity, require_empty=False):
                    raise ValueError("Output directory changed during artifact export.")
                if target_file.exists() or target_file.is_symlink():
                    raise FileExistsError("Output file already exists; USC will not overwrite concurrent data.")
                os.link(source_file, target_file, follow_symlinks=False)
                created_files.append(target_file)

        actual_inventory, _ = create_artifact_inventory(output)
        if actual_inventory != staged_inventory:
            raise ValueError("Exported artifact inventory changed during the output merge.")
        return _output_directory_matches(output, expected_identity, require_empty=False)
    except (OSError, ValueError):
        if _directory_identity(output) == expected_identity:
            for path in reversed(created_files):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            for path in reversed(created_directories):
                try:
                    path.rmdir()
                except OSError:
                    pass
        return False


def _export_container_output(
    docker: str,
    exporter_container_id: str,
    output: Path,
    expected_output_identity: tuple[int, int],
) -> bool:
    """Copy to a private staging directory, then merge without overwriting concurrent files."""
    if not _output_directory_matches(output, expected_output_identity, require_empty=True):
        return False
    try:
        running = subprocess.run(
            [docker, "inspect", "--format", "{{.State.Running}}", exporter_container_id],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if running.returncode != 0 or running.stdout.strip().lower() != "true":
            return False
        with tempfile.TemporaryDirectory(prefix=".usc-export-", dir=output.parent) as temporary_root:
            staged = Path(temporary_root)
            copied = subprocess.run(
                [docker, "cp", f"{exporter_container_id}:/out/.", str(staged)],
                capture_output=True, text=True, timeout=60, check=False,
            )
            if copied.returncode != 0:
                return False
            staged_inventory, _ = create_artifact_inventory(staged)
            if not _output_directory_matches(output, expected_output_identity, require_empty=True):
                return False
            return _merge_staged_export(staged, output, expected_output_identity, staged_inventory)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def _cleanup_output_volume(docker: str, volume_name: str) -> bool:
    try:
        removed = subprocess.run(
            [docker, "volume", "rm", "-f", volume_name],
            capture_output=True, text=True, timeout=15, check=False,
        )
        return removed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _cleanup_labelled_containers(docker: str, label: str) -> bool:
    container_ids = _labelled_container_ids(docker, label)
    if container_ids is None:
        return False
    for container_id in container_ids:
        try:
            removed = subprocess.run(
                [docker, "rm", "-f", container_id],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if removed.returncode != 0:
                return False
        except (OSError, subprocess.TimeoutExpired):
            return False
    remaining = _labelled_container_ids(docker, label)
    return remaining == []


def run_isolated_build(
    source_path: str | Path,
    output_path: str | Path,
    *,
    image: str,
    command: Sequence[str],
    approved: bool = False,
    timeout_seconds: int = 300,
    max_log_bytes: int = 262_144,
) -> dict:
    """Run an explicitly approved argv command in a network-disabled, read-only container.

    The image must already exist locally and be pinned by digest. No host environment
    variables, credentials, sockets, or additional mounts are passed to the container.
    """
    if approved is not True:
        return _validated_result({
            "operation": "isolated_build",
            "status": "blocked_approval_required",
            "executed": False,
            "note": "Execution requires explicit approval of this exact command and image.",
        })
    try:
        source, output, args = _validate_request(
            source_path, output_path, image, command, timeout_seconds, max_log_bytes,
        )
    except (OSError, ValueError) as exc:
        return _validated_result({
            "operation": "isolated_build",
            "status": "blocked_invalid_request",
            "executed": False,
            "errors": [str(exc)],
        })

    docker = shutil.which("docker")
    if not docker:
        return _validated_result({
            "operation": "isolated_build",
            "status": "blocked_isolation_unavailable",
            "executed": False,
            "errors": ["Docker CLI is unavailable; no fallback execution is permitted."],
        })
    try:
        probe = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        probe = None
    if probe is None or probe.returncode != 0:
        return _validated_result({
            "operation": "isolated_build",
            "status": "blocked_isolation_unavailable",
            "executed": False,
            "errors": ["Docker daemon is unavailable; no fallback execution is permitted."],
        })
    docker_engine_version = (probe.stdout or "").strip() or None
    try:
        image_probe = subprocess.run(
            [docker, "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        image_probe = None
    if image_probe is None or image_probe.returncode != 0 or not (image_probe.stdout or "").strip():
        return _validated_result({
            "operation": "isolated_build",
            "status": "blocked_isolation_unavailable",
            "executed": False,
            "image": image,
            "command_argv": args,
            "errors": ["The digest-pinned image is not available locally; image pulling is disabled."],
        })
    docker_image_id = image_probe.stdout.strip()
    try:
        exporter_image_probe = subprocess.run(
            [docker, "image", "inspect", "--format", "{{.Id}}", _EXPORT_HELPER_IMAGE],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        exporter_image_probe = None
    if exporter_image_probe is None or exporter_image_probe.returncode != 0 or not (exporter_image_probe.stdout or "").strip():
        return _validated_result({
            "operation": "isolated_build",
            "status": "blocked_isolation_unavailable",
            "executed": False,
            "image": image,
            "docker_image_id": docker_image_id,
            "export_helper_image": _EXPORT_HELPER_IMAGE,
            "errors": ["The pinned USC export-helper image is not available locally; image pulling is disabled."],
        })
    export_helper_image_id = exporter_image_probe.stdout.strip()
    run_id = uuid.uuid4().hex
    run_label = f"com.usc.build-run={run_id}"
    output_volume_name = f"usc-output-{run_id}"
    output_volume_created = False
    output_volume_cleanup_ok = True
    export_helper_container_id = None
    toolchain_inventory = _probe_toolchain(docker, image, run_label)
    toolchain_inventory_sha256 = _toolchain_inventory_digest(toolchain_inventory)

    logs = bytearray()
    log_truncated = False
    status = "failed"
    exit_code = None
    cleanup_ok = True
    artifact_exported = False
    execution_started = False
    process = None
    selector = None
    source_snapshot_sha256 = None
    excluded_source_path_count = 0
    source_git_identity = {
        "source_git_commit_sha": None,
        "source_git_tree_sha": None,
        "source_worktree_clean": False,
        "source_git_identity_error": "Source Git identity has not been inspected.",
    }
    artifact_inventory = []
    artifact_inventory_sha256 = hashlib.sha256(b"[]").hexdigest()
    started_at = None
    started_monotonic = None
    errors = []
    command_sha256 = hashlib.sha256(
        json.dumps(args, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix="usc-build-") as temporary_root:
            staged_source = Path(temporary_root) / "source"
            source_git_identity = inspect_git_source(source)
            expected_git_blobs = (
                source_git_identity.get("_tracked_blob_sha_by_path")
                if source_git_identity["source_worktree_clean"] else None
            )
            source_snapshot_sha256, excluded_source_path_count = _stage_source_snapshot(
                source, staged_source, expected_git_blobs=expected_git_blobs,
            )
            if "," in str(staged_source):
                raise ValueError("Temporary snapshot path must not contain commas.")
            output_volume_created = _create_output_volume(docker, output_volume_name, run_id)
            if not output_volume_created:
                raise OSError("USC could not create the bounded 256 MB tmpfs output volume.")
            export_helper_container_id = _start_export_helper(docker, output_volume_name, run_label)
            if not export_helper_container_id:
                raise OSError("USC could not start the restricted output-export helper container.")
            docker_argv = [
                docker, "run", "--pull=never",
                "--network=none", "--read-only",
                f"--user={os.getuid()}:{os.getgid()}", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--pids-limit=64", "--memory=512m", "--cpus=1.0",
                f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid={os.getuid()},gid={os.getgid()},mode=0700",
                f"--mount=type=volume,src={output_volume_name},dst=/out",
                f"--label={run_label}",
                f"--mount=type=bind,src={staged_source},dst=/src,readonly",
                "--workdir=/src",
                "--env=HOME=/tmp", "--env=TMPDIR=/tmp",
                "--env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                image, *args,
            ]
            started_at = datetime.now(timezone.utc).isoformat()
            started_monotonic = time.monotonic()
            process = subprocess.Popen(
                docker_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            execution_started = True
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = started_monotonic + timeout_seconds
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        status = "timed_out"
                        process.kill()
                        break
                    for key, _ in selector.select(timeout=min(0.1, remaining)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        available = max_log_bytes - len(logs)
                        if len(chunk) > available:
                            logs.extend(chunk[:available])
                            log_truncated = True
                            status = "output_limit_exceeded"
                            process.kill()
                            break
                        logs.extend(chunk)
                    if status in {"timed_out", "output_limit_exceeded"}:
                        break
                exit_code = process.wait(timeout=5)
                if status not in {"timed_out", "output_limit_exceeded"}:
                    if exit_code == 125:
                        status = "blocked_isolation_unavailable"
                        execution_started = False
                    else:
                        status = "passed" if exit_code == 0 else "failed"
                        artifact_exported = _export_container_output(docker, export_helper_container_id, output)
                        if artifact_exported:
                            try:
                                artifact_inventory, artifact_inventory_sha256 = create_artifact_inventory(output)
                            except (OSError, ValueError) as exc:
                                artifact_exported = False
                                errors.append(str(exc))
                        if not artifact_exported:
                            status = "artifact_export_failed"
                            if not errors:
                                errors.append("Build artifacts could not be exported and inventoried safely.")
            finally:
                selector.close()
                selector = None
                process.stdout.close()
    except ValueError as exc:
        status = "blocked_invalid_request"
        execution_started = False
        errors.append(str(exc))
        logs.extend(str(exc).encode("utf-8", errors="replace")[:max_log_bytes])
    except (OSError, subprocess.TimeoutExpired) as exc:
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        status = "blocked_invalid_request" if source_snapshot_sha256 is None else "blocked_isolation_unavailable"
        if process is None:
            execution_started = False
        errors.append(str(exc))
        logs.extend(str(exc).encode("utf-8", errors="replace")[:max_log_bytes])
    except KeyboardInterrupt:
        if process is not None:
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    errors.append("Docker runner did not exit after interruption; labelled-container cleanup will still be attempted.")
            if process.stdout is not None:
                process.stdout.close()
        if selector is not None:
            selector.close()
        errors.append("Build execution was interrupted; USC attempted to stop the runner and clean up its container.")
        raise
    finally:
        cleanup_ok = _cleanup_labelled_containers(docker, run_label)
        if output_volume_created:
            output_volume_cleanup_ok = _cleanup_output_volume(docker, output_volume_name)

    if not cleanup_ok or not output_volume_cleanup_ok:
        status = "blocked_cleanup_failed"
        errors.append("USC could not confirm cleanup of every build/export container and temporary output volume.")
    finished_at = datetime.now(timezone.utc).isoformat() if started_at else None
    duration_seconds = round(max(0.0, time.monotonic() - started_monotonic), 3) if started_monotonic is not None else None
    redacted_logs = redact_build_logs(logs.decode("utf-8", errors="replace"))
    redacted_bytes = redacted_logs.encode("utf-8")
    if len(redacted_bytes) > max_log_bytes:
        redacted_logs = redacted_bytes[:max_log_bytes].decode("utf-8", errors="replace")
        log_truncated = True
    logs_sha256 = hashlib.sha256(redacted_logs.encode("utf-8")).hexdigest()
    return _validated_result({
        "schema_version": "1.0",
        "operation": "isolated_build",
        "status": status,
        "executed": execution_started,
        "exit_code": exit_code,
        "image": image,
        "docker_image_id": docker_image_id,
        "export_helper_image": _EXPORT_HELPER_IMAGE,
        "export_helper_image_id": export_helper_image_id,
        "docker_engine_version": docker_engine_version,
        "toolchain_inventory": toolchain_inventory,
        "toolchain_inventory_sha256": toolchain_inventory_sha256,
        "command_argv": args,
        "command_sha256": command_sha256,
        "command_executable": args[0],
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration_seconds,
        "timeout_seconds": timeout_seconds,
        "log_bytes": len(logs),
        "log_truncated": log_truncated,
        "logs": redacted_logs,
        "logs_sha256": logs_sha256,
        "source_read_only": True,
        "output_path": str(output),
        "artifact_exported": artifact_exported,
        "artifact_inventory": artifact_inventory,
        "artifact_inventory_sha256": artifact_inventory_sha256,
        "source_snapshot_sha256": source_snapshot_sha256,
        "source_git_commit_sha": source_git_identity["source_git_commit_sha"],
        "source_git_tree_sha": source_git_identity["source_git_tree_sha"],
        "source_worktree_clean": source_git_identity["source_worktree_clean"],
        "source_git_identity_error": source_git_identity["source_git_identity_error"],
        "excluded_source_path_count": excluded_source_path_count,
        "network_disabled": True,
        "container_cleanup_confirmed": cleanup_ok,
        "output_volume_cleanup_confirmed": output_volume_cleanup_ok,
        "errors": errors,
        "note": "No host environment variables or credentials were forwarded. The build and pinned USC export-helper images had to be pre-provisioned locally. The helper is non-root, network-disabled, read-only, and only holds the bounded output tmpfs volume read-only during export. Log redaction is best-effort.",
    })
