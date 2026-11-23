"""Reviewed, short-lived approval receipts for named isolated-build profiles.

Receipts are HMAC-authenticated with a per-user local key and consumed once. This
protects against accidental edits and other local accounts, not the same OS user
who controls the key and state directory; it is not proof of external human consent.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .build_evidence import inspect_git_source

_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_MAX_TTL_SECONDS = 1800
_MIN_TTL_SECONDS = 60
_MAX_LOG_BYTES = 1_048_576
_PROFILES = {
    "python-pytest": {
        "command": ["python", "-m", "pytest", "-q"],
        "description": "Run the Python test suite with pytest in quiet mode.",
    },
    "python-container-smoke": {
        "command": [
            "python", "-c",
            "from pathlib import Path; import os,socket; "
            "m=[x.split() for x in Path('/proc/mounts').read_text().splitlines() if len(x.split())>=4]; "
            "assert os.geteuid()!=0; "
            "assert any(x[1]=='/' and 'ro' in x[3].split(',') for x in m); "
            "assert any(x[1]=='/src' and 'ro' in x[3].split(',') for x in m); "
            "assert any(x[1]=='/out' and 'rw' in x[3].split(',') for x in m); "
            "assert Path('/src/fixture.txt').read_text()=='USC docker smoke fixture\\n'; "
            "s=socket.socket(); s.settimeout(2); assert s.connect_ex(('1.1.1.1',443)) != 0; "
            "Path('/out/smoke-result.txt').write_text('isolated runner passed\\n'); "
            "print('USC isolated Docker smoke test passed')",
        ],
        "description": "Verify a synthetic fixture, non-root identity, read-only root/source mounts, writable output tmpfs, and disabled networking.",
    },
}


def available_build_profiles() -> dict[str, dict[str, Any]]:
    """Return a defensive copy of the fixed, allowlisted build profiles."""
    return {
        name: {"command": list(profile["command"]), "description": profile["description"]}
        for name, profile in _PROFILES.items()
    }


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _read_json(path: str | Path) -> dict:
    supplied = Path(path).expanduser()
    if supplied.is_symlink():
        raise ValueError("Approval files must not be symlinks.")
    resolved = supplied.resolve(strict=True)
    info = resolved.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
        raise ValueError("Approval file must be a regular file no larger than 64 KiB.")
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Approval JSON contains duplicate keys.")
            result[key] = value
        return result
    data = json.loads(resolved.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(data, dict):
        raise ValueError("Approval file must contain a JSON object.")
    return data


def _state_root(state_dir: str | Path | None = None) -> Path:
    root = Path(state_dir).expanduser() if state_dir is not None else Path.home() / ".usc"
    if root.is_symlink():
        raise ValueError("USC approval state directory must not be a symlink.")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    info = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("USC approval state directory must be owned by the current user.")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("USC approval state directory permissions must be 0700.")
    return root


def _key(root: Path, *, create: bool) -> bytes:
    path = root / "approval-hmac.key"
    if path.is_symlink():
        raise ValueError("USC approval key must not be a symlink.")
    if not path.exists():
        if not create:
            raise ValueError("No USC approval key exists; create and approve a build request first.")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            key = secrets.token_bytes(32)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(key)
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("USC approval key must be a current-user-owned regular file with private permissions.")
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("USC approval key has an invalid length.")
    return key


def _source_identity(source_path: str | Path) -> tuple[Path, dict]:
    supplied = Path(source_path).expanduser()
    if supplied.is_symlink():
        raise ValueError("Build source path must not be a symlink.")
    source = supplied.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("Build source path must be an existing directory.")
    identity = inspect_git_source(source)
    if (
        not identity.get("source_worktree_clean")
        or not identity.get("source_git_commit_sha")
        or not identity.get("source_git_tree_sha")
    ):
        raise ValueError(
            "Reviewed build approval requires a clean Git source with verified commit and tree identity; "
            "non-Git or dirty sources are not eligible."
        )
    return source, identity


def create_build_approval_request(
    source_path: str | Path,
    *,
    image: str,
    profile: str,
    timeout_seconds: int = 300,
    expires_in_seconds: int = 900,
    now: datetime | None = None,
) -> dict:
    """Create a request bound to exact source identity, image digest, profile and limits."""
    if not isinstance(image, str) or not _IMAGE.fullmatch(image):
        raise ValueError("Build image must be pinned by a full sha256 digest.")
    if profile not in _PROFILES:
        raise ValueError(f"Unknown build profile {profile!r}; allowed profiles: {', '.join(sorted(_PROFILES))}.")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 3600:
        raise ValueError("Build timeout must be an integer from 1 to 3600 seconds.")
    if isinstance(expires_in_seconds, bool) or not isinstance(expires_in_seconds, int) or not _MIN_TTL_SECONDS <= expires_in_seconds <= _MAX_TTL_SECONDS:
        raise ValueError("Approval expiry must be between 60 and 1800 seconds.")
    source, identity = _source_identity(source_path)
    created = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = created + timedelta(seconds=expires_in_seconds)
    return {
        "schema_version": "1.0",
        "operation": "usc_build_approval_request",
        "approval_id": str(uuid.uuid4()),
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "source_path": str(source),
        "source_git_commit_sha": identity["source_git_commit_sha"],
        "source_git_tree_sha": identity["source_git_tree_sha"],
        "image": image,
        "profile": profile,
        "command_argv": list(_PROFILES[profile]["command"]),
        "timeout_seconds": timeout_seconds,
        "max_log_bytes": _MAX_LOG_BYTES,
        "release_authorized": False,
    }


def approve_build_request(
    request_path: str | Path,
    *,
    approved: bool,
    state_dir: str | Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Create an HMAC-authenticated approval receipt after explicit CLI approval."""
    if approved is not True:
        raise ValueError("Approval requires the explicit --approve flag.")
    request = _read_json(request_path)
    required = {
        "schema_version", "operation", "approval_id", "created_at", "expires_at",
        "source_path", "source_git_commit_sha", "source_git_tree_sha", "image",
        "profile", "command_argv", "timeout_seconds", "max_log_bytes", "release_authorized",
    }
    if set(request) != required or request.get("schema_version") != "1.0" or request.get("operation") != "usc_build_approval_request":
        raise ValueError("Build approval request has an invalid structure.")
    if request.get("release_authorized") is not False:
        raise ValueError("Build approval cannot authorize release or deployment.")
    profile = _PROFILES.get(request.get("profile"))
    if profile is None or request.get("command_argv") != profile["command"]:
        raise ValueError("Build request command does not match a fixed allowlisted profile.")
    if not _IMAGE.fullmatch(str(request.get("image", ""))):
        raise ValueError("Build request image is not digest-pinned.")
    if isinstance(request.get("timeout_seconds"), bool) or not isinstance(request.get("timeout_seconds"), int) or not 1 <= request["timeout_seconds"] <= 3600:
        raise ValueError("Build request timeout is invalid.")
    if request.get("max_log_bytes") != _MAX_LOG_BYTES:
        raise ValueError("Build request log limit is invalid.")
    if not isinstance(request.get("approval_id"), str) or not re.fullmatch(r"[0-9a-f-]{36}", request["approval_id"]):
        raise ValueError("Build request approval ID is invalid.")
    source, identity = _source_identity(request["source_path"])
    if (
        str(source) != request["source_path"]
        or identity["source_git_commit_sha"] != request["source_git_commit_sha"]
        or identity["source_git_tree_sha"] != request["source_git_tree_sha"]
    ):
        raise ValueError("Build source changed after the approval request was created.")
    expires = datetime.fromisoformat(request["expires_at"])
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires.tzinfo is None or current >= expires:
        raise ValueError("Build approval request has expired.")
    created = datetime.fromisoformat(request["created_at"])
    if created.tzinfo is None or created > current or (expires - created).total_seconds() > _MAX_TTL_SECONDS:
        raise ValueError("Build approval request timestamps are invalid.")
    root = _state_root(state_dir)
    key = _key(root, create=True)
    payload = {
        "schema_version": "1.0",
        "operation": "usc_build_approval_receipt",
        "request": request,
        "approved_at": current.isoformat(),
    }
    signature = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return {**payload, "hmac_sha256": signature}


def consume_build_approval(
    receipt_path: str | Path,
    *,
    source_path: str | Path,
    output_path: str | Path,
    state_dir: str | Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Verify and atomically consume a receipt; return the exact approved runner inputs."""
    receipt = _read_json(receipt_path)
    if set(receipt) != {"schema_version", "operation", "request", "approved_at", "hmac_sha256"}:
        raise ValueError("Build approval receipt has an invalid structure.")
    if receipt.get("schema_version") != "1.0" or receipt.get("operation") != "usc_build_approval_receipt":
        raise ValueError("Unsupported build approval receipt.")
    request = receipt.get("request")
    if not isinstance(request, dict):
        raise ValueError("Build approval receipt request is invalid.")
    root = _state_root(state_dir)
    key = _key(root, create=False)
    payload = {key: value for key, value in receipt.items() if key != "hmac_sha256"}
    expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(receipt.get("hmac_sha256", "")), expected):
        raise ValueError("Build approval receipt authentication failed.")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = datetime.fromisoformat(request["expires_at"])
    if expires.tzinfo is None or current >= expires:
        raise ValueError("Build approval receipt has expired.")
    source, identity = _source_identity(source_path)
    if (
        str(source) != request.get("source_path")
        or identity["source_git_commit_sha"] != request.get("source_git_commit_sha")
        or identity["source_git_tree_sha"] != request.get("source_git_tree_sha")
    ):
        raise ValueError("Build source does not match the approved revision.")
    profile = _PROFILES.get(request.get("profile"))
    if profile is None or request.get("command_argv") != profile["command"]:
        raise ValueError("Approved command profile is invalid or has changed.")
    if not _IMAGE.fullmatch(str(request.get("image", ""))):
        raise ValueError("Approved image is not digest-pinned.")
    if request.get("release_authorized") is not False:
        raise ValueError("Build approval cannot authorize release or deployment.")
    if isinstance(request.get("timeout_seconds"), bool) or not isinstance(request.get("timeout_seconds"), int) or not 1 <= request["timeout_seconds"] <= 3600:
        raise ValueError("Approved timeout is invalid.")
    if request.get("max_log_bytes") != _MAX_LOG_BYTES:
        raise ValueError("Approved log limit is invalid.")
    approval_id = request.get("approval_id")
    if not isinstance(approval_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", approval_id):
        raise ValueError("Approval ID is invalid.")
    consumed = root / "consumed"
    consumed.mkdir(mode=0o700, exist_ok=True)
    if consumed.is_symlink() or consumed.stat().st_uid != os.getuid() or stat.S_IMODE(consumed.stat().st_mode) & 0o077:
        raise ValueError("Approval replay ledger must have private permissions.")
    output = Path(output_path).expanduser()
    if output.is_symlink():
        raise ValueError("Build output directory must not be a symlink.")
    output = output.resolve(strict=True)
    if not output.is_dir():
        raise ValueError("Build output path must be an existing directory.")
    if any(output.iterdir()):
        raise ValueError("Build output directory must be empty before approval is consumed.")
    marker = consumed / approval_id
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("Build approval has already been used; replay is blocked.") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(current.isoformat())
    return {
        "source_path": str(source),
        "output_path": str(output),
        "image": request["image"],
        "command": list(profile["command"]),
        "timeout_seconds": request["timeout_seconds"],
        "max_log_bytes": request["max_log_bytes"],
        "approval_id": approval_id,
    }


def execute_approved_build(
    receipt_path: str | Path,
    *,
    source_path: str | Path,
    output_path: str | Path,
    state_dir: str | Path | None = None,
    now: datetime | None = None,
) -> dict:
    """Consume a valid one-time receipt and execute only its fixed approved profile.

    This is the supported build execution API. The low-level Docker runner is kept
    private to the implementation module and is not imported by the CLI.
    """
    approved = consume_build_approval(
        receipt_path,
        source_path=source_path,
        output_path=output_path,
        state_dir=state_dir,
        now=now,
    )
    # Local import avoids a module cycle: the runner's execution primitive is internal.
    from .build_runner import _run_isolated_build

    return _run_isolated_build(
        approved["source_path"],
        approved["output_path"],
        image=approved["image"],
        command=approved["command"],
        approved=True,
        timeout_seconds=approved["timeout_seconds"],
        max_log_bytes=approved["max_log_bytes"],
    )
