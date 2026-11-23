"""Read-only, bounded source inventory for human review before isolated builds."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from .source_secret_scan import SourceSecretScanner

_EXCLUDED_DIRS = {".git", ".usc", ".ssh", ".aws", ".azure", ".gcloud", ".terraform", ".docker", ".kube", ".config", ".firebase"}
_EXCLUDED_FILE_NAMES = {".git", ".gitconfig", ".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".vault-token", ".pgpass", ".my.cnf", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", "credentials.json", "secrets.json", "secret.json"}
_SAFE_ENV_EXAMPLES = {".env.example", ".env.sample", ".env.template"}
_SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".p8", ".jks", ".keystore", ".tfstate", ".secret", ".token", ".mobileprovision"}
_MAX_SOURCE_BYTES = 256 * 1024 * 1024
_MAX_SOURCE_FILES = 20_000
_MAX_SINGLE_SOURCE_FILE = 50 * 1024 * 1024
_MAX_REPORTED_ENTRIES = 500
_MAX_REPORTED_PATH_LENGTH = 1024


def _is_sensitive_file(relative: Path) -> bool:
    name, suffix = relative.name.lower(), relative.suffix.lower()
    if name in _EXCLUDED_FILE_NAMES or (name.startswith(".env") and name not in _SAFE_ENV_EXAMPLES):
        return True
    if suffix in _SENSITIVE_SUFFIXES:
        return True
    if (name.startswith("service-account") or name.startswith("firebase-adminsdk")) and suffix == ".json":
        return True
    return "credential" in name and suffix in {".json", ".yaml", ".yml", ".toml"}


def create_source_review(source_path: str | Path) -> dict:
    """Inventory paths and scan included file contents without executing project code."""
    supplied = Path(source_path).expanduser()
    absolute, current = supplied.absolute(), Path(supplied.absolute().anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("Source review path must not traverse a symlink.")
    source = supplied.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("Source review path must be an existing directory.")

    entries: list[dict] = []
    total_entries = excluded_count = total_bytes = file_count = finding_count = 0

    def record(path: str, status: str, **extra: object) -> None:
        nonlocal total_entries, excluded_count, finding_count
        total_entries += 1
        excluded_count += status == "excluded"
        finding_count += status == "review_required"
        if len(entries) < _MAX_REPORTED_ENTRIES:
            item = {"path": path[:_MAX_REPORTED_PATH_LENGTH], "status": status}
            item.update(extra)
            entries.append(item)

    def raise_walk_error(error: OSError) -> None:
        raise error

    for root_text, directories, filenames in os.walk(source, topdown=True, followlinks=False, onerror=raise_walk_error):
        root = Path(root_text)
        kept = []
        for name in sorted(directories):
            path = root / name
            relative = path.relative_to(source).as_posix()
            if path.is_symlink():
                raise ValueError(f"Source inventory contains a symlinked directory: {relative}")
            if name.lower() in _EXCLUDED_DIRS:
                record(relative, "excluded", reason="sensitive_directory")
            else:
                kept.append(name)
        directories[:] = kept

        for name in sorted(filenames):
            path = root / name
            relative = path.relative_to(source)
            relative_text = relative.as_posix()
            if path.is_symlink():
                raise ValueError(f"Source inventory contains a symlinked file: {relative_text}")
            if _is_sensitive_file(relative):
                record(relative_text, "excluded", reason="sensitive_file")
                continue
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"Source inventory contains a non-regular file: {relative_text}")
            if metadata.st_size > _MAX_SINGLE_SOURCE_FILE:
                raise ValueError(f"Source file exceeds the 50 MB per-file limit: {relative_text}")
            total_bytes += metadata.st_size
            file_count += 1
            if total_bytes > _MAX_SOURCE_BYTES:
                raise ValueError("Source inventory exceeds the 256 MB total size limit.")
            if file_count > _MAX_SOURCE_FILES:
                raise ValueError("Source inventory exceeds the 20,000-file limit.")
            scanner = SourceSecretScanner()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    scanner.feed(chunk)
            if scanner.findings:
                record(relative_text, "review_required", reason="potential_secret_pattern", rules=sorted(scanner.findings))
            else:
                record(relative_text, "included", size_bytes=metadata.st_size)

    return {
        "schema_version": "1.0",
        "operation": "source_review",
        "execution_performed": False,
        "human_review_required": True,
        "source_path": str(source),
        "included_file_count": file_count,
        "included_bytes": total_bytes,
        "excluded_path_count": excluded_count,
        "potential_secret_finding_count": finding_count,
        "entries": entries,
        "entries_truncated": total_entries > len(entries),
        "review_note": "Review every listed path before requesting a build. Excluded paths are not tested. Potential secret patterns block later snapshot staging; this finite scanner cannot prove that a source tree is secret-free. This report does not approve or execute a build.",
    }
