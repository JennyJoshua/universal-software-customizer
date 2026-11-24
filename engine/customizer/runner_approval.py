"""Strict protocol-v2 signed-approval envelope validation and canonicalization.

This module does not verify signatures or authenticate the submitting peer.
The broker must compare requester_uid with kernel SO_PEERCRED and verify the
signature using its separately configured trusted public key before acceptance.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from uuid import UUID

from .runner_protocol import (
    ALLOWED_PROFILES,
    MAX_MESSAGE_BYTES,
    POLICY_VERSION,
    ProtocolError,
)

PROTOCOL_VERSION_V2 = "2"
MAX_SIGNATURE_BYTES = 64
MAX_APPROVAL_TTL_SECONDS = 30 * 60
MAX_FUTURE_ISSUE_SECONDS = 60
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[^\\s@]+@sha256:[0-9a-f]{64}$")
_ENVELOPE = {"protocol_version", "request_id", "operation"}
_JOB_FIELDS = {
    "source_snapshot_sha256",
    "profile_id",
    "build_image_digest",
    "exporter_image_digest",
    "policy_version",
    "release_authorized",
    "approval",
}
_APPROVAL_FIELDS = {
    "approval_id",
    "issued_at",
    "expires_at",
    "nonce",
    "requester_uid",
    "key_id",
    "signature",
}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ProtocolError("Non-standard JSON constants are not allowed.")


def _uuid(value, field):
    if not isinstance(value, str):
        raise ProtocolError(f"{field} must be a UUID string.")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProtocolError(f"{field} must be a UUID string.") from exc
    if str(parsed) != value:
        raise ProtocolError(f"{field} must use canonical lowercase UUID form.")
    return value


def _timestamp(value, field):
    if not isinstance(value, str) or not 20 <= len(value) <= 40:
        raise ProtocolError(f"{field} must be a bounded UTC ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError(f"{field} must be a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ProtocolError(f"{field} must use UTC.")
    return parsed.astimezone(timezone.utc)


def decode_approval_message(raw: bytes | str, *, now: datetime | None = None) -> dict:
    """Decode and strictly validate one complete v2 signed submit message."""
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
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("Protocol message is not valid JSON.") from exc

    if not isinstance(message, dict) or set(message) != _ENVELOPE | {"job"}:
        raise ProtocolError("Protocol-v2 submit envelope contains missing or unknown fields.")
    if message["protocol_version"] != PROTOCOL_VERSION_V2:
        raise ProtocolError("Unsupported signed-approval protocol version.")
    _uuid(message["request_id"], "request_id")
    if message["operation"] != "submit":
        raise ProtocolError("Protocol-v2 currently supports signed submit only.")

    job = message["job"]
    if not isinstance(job, dict) or set(job) != _JOB_FIELDS:
        raise ProtocolError("Protocol-v2 job contains missing or unknown fields.")
    if not isinstance(job["source_snapshot_sha256"], str) or not _SHA256.fullmatch(job["source_snapshot_sha256"]):
        raise ProtocolError("source_snapshot_sha256 must be a lowercase SHA-256 digest.")
    if not isinstance(job["profile_id"], str) or job["profile_id"] not in ALLOWED_PROFILES:
        raise ProtocolError("Unsupported build profile.")
    for field in ("build_image_digest", "exporter_image_digest"):
        if not isinstance(job[field], str) or not _IMAGE.fullmatch(job[field]):
            raise ProtocolError(f"{field} must be pinned by a full SHA-256 digest.")
    if job["policy_version"] != POLICY_VERSION:
        raise ProtocolError("Unsupported runner policy version.")
    if job["release_authorized"] is not False:
        raise ProtocolError("Runner requests cannot authorize release or deployment.")

    approval = job["approval"]
    if not isinstance(approval, dict) or set(approval) != _APPROVAL_FIELDS:
        raise ProtocolError("Signed approval contains missing or unknown fields.")
    _uuid(approval["approval_id"], "approval_id")
    _uuid(approval["nonce"], "nonce")
    uid = approval["requester_uid"]
    if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
        raise ProtocolError("requester_uid must be a positive non-root integer.")
    if not isinstance(approval["key_id"], str) or not _SHA256.fullmatch(approval["key_id"]):
        raise ProtocolError("key_id must be a lowercase SHA-256 fingerprint.")
    signature_text = approval["signature"]
    if not isinstance(signature_text, str) or len(signature_text) > 128:
        raise ProtocolError("signature must be bounded base64 text.")
    try:
        signature = base64.b64decode(signature_text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("signature must be valid base64.") from exc
    if len(signature) != MAX_SIGNATURE_BYTES or base64.b64encode(signature).decode("ascii") != signature_text:
        raise ProtocolError("signature must be canonical base64 for a 64-byte Ed25519 signature.")

    issued_at = _timestamp(approval["issued_at"], "issued_at")
    expires_at = _timestamp(approval["expires_at"], "expires_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (issued_at - current).total_seconds() > MAX_FUTURE_ISSUE_SECONDS:
        raise ProtocolError("Approval issue time is too far in the future.")
    if expires_at <= current or expires_at <= issued_at:
        raise ProtocolError("Approval is expired or has an invalid time window.")
    if (expires_at - issued_at).total_seconds() > MAX_APPROVAL_TTL_SECONDS:
        raise ProtocolError("Approval validity exceeds the permitted 30-minute window.")
    return message


def canonical_approval_payload(message: dict) -> bytes:
    """Rebuild the exact signed payload from a validated protocol-v2 message."""
    if not isinstance(message, dict) or message.get("protocol_version") != PROTOCOL_VERSION_V2:
        raise ProtocolError("A validated protocol-v2 message is required.")
    try:
        job = message["job"]
        approval = job["approval"]
        payload = {
            "protocol_version": PROTOCOL_VERSION_V2,
            "approval_id": approval["approval_id"],
            "issued_at": approval["issued_at"],
            "expires_at": approval["expires_at"],
            "nonce": approval["nonce"],
            "requester_uid": approval["requester_uid"],
            "key_id": approval["key_id"],
            "source_snapshot_sha256": job["source_snapshot_sha256"],
            "profile_id": job["profile_id"],
            "build_image_digest": job["build_image_digest"],
            "exporter_image_digest": job["exporter_image_digest"],
            "policy_version": job["policy_version"],
            "release_authorized": False,
        }
    except (KeyError, TypeError) as exc:
        raise ProtocolError("A validated protocol-v2 message is required.") from exc
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("Approval payload cannot be canonicalized.") from exc


def public_key_id(pem_bytes: bytes) -> str:
    """Return the configured public-key identifier from exact PEM file bytes."""
    if not isinstance(pem_bytes, bytes) or not pem_bytes or len(pem_bytes) > 4096:
        raise ProtocolError("Trusted public key must be non-empty PEM bytes no larger than 4 KiB.")
    return hashlib.sha256(pem_bytes).hexdigest()
