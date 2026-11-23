from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest

from customizer.runner_protocol import (
    MAX_MESSAGE_BYTES,
    POLICY_VERSION,
    ProtocolError,
    authorize_peer,
    decode_message,
)


NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
IMAGE = "python:3.12-slim@sha256:" + "a" * 64
EXPORTER = "busybox@sha256:" + "b" * 64


def submit_message(**overrides):
    job = {
        "approval_id": str(uuid4()),
        "source_snapshot_sha256": "c" * 64,
        "profile_id": "python-pytest",
        "build_image_digest": IMAGE,
        "exporter_image_digest": EXPORTER,
        "policy_version": POLICY_VERSION,
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "release_authorized": False,
    }
    job.update(overrides)
    return {
        "protocol_version": "1",
        "request_id": str(uuid4()),
        "operation": "submit",
        "job": job,
    }


def test_accepts_minimal_fixed_profile_submit_without_paths_or_commands():
    message = decode_message(json.dumps(submit_message()).encode(), now=NOW)
    assert message["operation"] == "submit"
    assert "command" not in message
    assert "source_path" not in message


@pytest.mark.parametrize("mutation", [
    lambda m: m.update(extra="unexpected"),
    lambda m: m.update(protocol_version="2"),
    lambda m: m.update(operation="shell"),
    lambda m: m["job"].update(command=["sh", "-c", "id"]),
    lambda m: m["job"].update(source_path="/home/user"),
    lambda m: m["job"].update(profile_id="arbitrary"),
    lambda m: m["job"].update(build_image_digest="python:latest"),
    lambda m: m["job"].update(release_authorized=True),
    lambda m: m["job"].update(policy_version="other"),
    lambda m: m["job"].update(source_snapshot_sha256="../etc/passwd"),
])
def test_rejects_unknown_or_unsafe_submit_fields(mutation):
    message = submit_message()
    mutation(message)
    with pytest.raises(ProtocolError):
        decode_message(json.dumps(message), now=NOW)


def test_rejects_expired_or_excessively_long_request():
    expired = submit_message(expires_at=(NOW - timedelta(seconds=1)).isoformat())
    long_lived = submit_message(expires_at=(NOW + timedelta(hours=1)).isoformat())
    for message in (expired, long_lived):
        with pytest.raises(ProtocolError, match="expiry"):
            decode_message(json.dumps(message), now=NOW)


def test_rejects_duplicate_keys_unknown_version_invalid_utf8_and_oversize():
    with pytest.raises(ProtocolError, match="Duplicate"):
        decode_message(b'{"protocol_version":"1","protocol_version":"1"}')
    with pytest.raises(ProtocolError, match="UTF-8"):
        decode_message(b"\xff")
    with pytest.raises(ProtocolError, match="byte limit"):
        decode_message(b" " * (MAX_MESSAGE_BYTES + 1))


@pytest.mark.parametrize("operation", ["status", "cancel", "result"])
def test_job_operations_have_exact_shape_and_require_job_id(operation):
    message = {
        "protocol_version": "1",
        "request_id": str(uuid4()),
        "operation": operation,
        "job_id": str(uuid4()),
    }
    assert decode_message(json.dumps(message))["operation"] == operation
    message["path"] = "/tmp/arbitrary"
    with pytest.raises(ProtocolError, match="unknown fields"):
        decode_message(json.dumps(message))


def test_job_id_is_not_authorization_and_each_operation_checks_peer_uid():
    with pytest.raises(ProtocolError, match="not authorized"):
        authorize_peer(2001, operation="submit")
    with pytest.raises(ProtocolError, match="not authorized"):
        authorize_peer(2001, operation="result", job_owner_uid=2002)
    authorize_peer(2001, operation="status", job_owner_uid=2001)
    authorize_peer(3000, operation="cancel", job_owner_uid=2001, operator_uids={3000})


def test_privileged_or_invalid_peer_identity_is_rejected():
    for uid in (0, -1, True, "1000"):
        with pytest.raises(ProtocolError):
            authorize_peer(uid, operation="submit", operator_uids={1000})
