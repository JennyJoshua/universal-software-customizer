"""Strict, bounded local IPC contract for the Stage 1 runner prototype.

This module validates message shape and operation-level OS-identity authorization.
It does not create a socket, authenticate a peer, approve a build, or execute code.
The caller must obtain peer_uid from trusted transport credentials (e.g. SO_PEERCRED).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import AbstractSet
from uuid import UUID

PROTOCOL_VERSION = "1"
POLICY_VERSION = "usc-runner-policy-v1"
MAX_MESSAGE_BYTES = 16 * 1024
MAX_TTL_SECONDS = 30 * 60
ALLOWED_PROFILES = frozenset({"python-pytest", "python-container-smoke"})
_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVELOPE = {"protocol_version", "request_id", "operation"}
_SUBMIT_FIELDS = {
    "approval_id", "source_snapshot_sha256", "profile_id",
    "build_image_digest", "exporter_image_digest", "policy_version",
    "expires_at", "release_authorized",
}
_JOB_OPERATIONS = frozenset({"status", "cancel", "result"})


class ProtocolError(ValueError):
    """A malformed, unsupported, or unauthorized local protocol message."""


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError("Duplicate JSON object key.")
        value[key] = item
    return value


def _uuid(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{field} must be a UUID string.")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProtocolError(f"{field} must be a UUID string.") from exc
    if str(parsed) != value:
        raise ProtocolError(f"{field} must use canonical lowercase UUID form.")
    return value


def _future_expiry(value: object, *, now: datetime | None = None) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise ProtocolError("expires_at must be a bounded ISO-8601 timestamp.")
    try:
        expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("expires_at must be a valid ISO-8601 timestamp.") from exc
    if expiry.tzinfo is None:
        raise ProtocolError("expires_at must include a timezone.")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    seconds = (expiry.astimezone(timezone.utc) - current).total_seconds()
    if seconds <= 0 or seconds > MAX_TTL_SECONDS:
        raise ProtocolError("Request expiry is outside the permitted future window.")
    return value


def decode_message(raw: bytes | str, *, now: datetime | None = None) -> dict:
    """Decode and validate one complete protocol message; reject unknown fields."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ProtocolError("Protocol message exceeds the byte limit.")
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ProtocolError("Protocol message must be valid UTF-8.") from exc
    elif isinstance(raw, str):
        try:
            if len(raw.encode("utf-8", errors="strict")) > MAX_MESSAGE_BYTES:
                raise ProtocolError("Protocol message exceeds the byte limit.")
        except UnicodeEncodeError as exc:
            raise ProtocolError("Protocol message must be valid UTF-8 text.") from exc
    else:
        raise ProtocolError("Protocol message must be bytes or text.")

    try:
        message = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ProtocolError("Non-standard JSON constants are not allowed.")),
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("Protocol message is not valid JSON.") from exc

    if not isinstance(message, dict):
        raise ProtocolError("Protocol message must be a JSON object.")
    if not _ENVELOPE.issubset(message):
        raise ProtocolError("Protocol envelope is incomplete.")
    if not isinstance(message["protocol_version"], str) or message["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("Unsupported protocol version.")
    _uuid(message["request_id"], "request_id")
    operation = message["operation"]
    if not isinstance(operation, str) or operation not in {"submit", *_JOB_OPERATIONS}:
        raise ProtocolError("Unsupported operation.")

    if operation == "submit":
        if set(message) != _ENVELOPE | {"job"}:
            raise ProtocolError("Submit message contains missing or unknown fields.")
        job = message["job"]
        if not isinstance(job, dict) or set(job) != _SUBMIT_FIELDS:
            raise ProtocolError("Submit job contains missing or unknown fields.")
        _uuid(job["approval_id"], "approval_id")
        if not isinstance(job["source_snapshot_sha256"], str) or not _SHA256.fullmatch(job["source_snapshot_sha256"]):
            raise ProtocolError("source_snapshot_sha256 must be a lowercase SHA-256 digest.")
        if not isinstance(job["profile_id"], str) or job["profile_id"] not in ALLOWED_PROFILES:
            raise ProtocolError("Unsupported build profile.")
        for field in ("build_image_digest", "exporter_image_digest"):
            if not isinstance(job[field], str) or not _IMAGE.fullmatch(job[field]):
                raise ProtocolError(f"{field} must be pinned by a full SHA-256 digest.")
        if not isinstance(job["policy_version"], str) or job["policy_version"] != POLICY_VERSION:
            raise ProtocolError("Unsupported runner policy version.")
        _future_expiry(job["expires_at"], now=now)
        if job["release_authorized"] is not False:
            raise ProtocolError("Runner requests cannot authorize release or deployment.")
        return message

    if set(message) != _ENVELOPE | {"job_id"}:
        raise ProtocolError("Job operation contains missing or unknown fields.")
    _uuid(message["job_id"], "job_id")
    return message


def authorize_peer(
    peer_uid: int,
    *,
    operation: str,
    job_owner_uid: int | None = None,
    operator_uids: AbstractSet[int] = frozenset(),
) -> None:
    """Authorize a peer UID obtained from the transport for this one operation.

    Job IDs are identifiers, not bearer credentials. The broker must load the
    authoritative owner UID for the job before authorizing status/cancel/result.
    """
    if isinstance(peer_uid, bool) or not isinstance(peer_uid, int) or peer_uid <= 0:
        raise ProtocolError("Peer identity is invalid or privileged.")
    if operation == "submit":
        if peer_uid in operator_uids:
            return
        raise ProtocolError("Peer is not authorized to submit runner jobs.")
    if not isinstance(operation, str) or operation not in _JOB_OPERATIONS:
        raise ProtocolError("Operation authorization context is incomplete.")
    if isinstance(job_owner_uid, bool) or not isinstance(job_owner_uid, int) or job_owner_uid <= 0:
        raise ProtocolError("Operation authorization context is incomplete.")
    if peer_uid == job_owner_uid or peer_uid in operator_uids:
        return
    raise ProtocolError("Peer is not authorized for this job operation.")
