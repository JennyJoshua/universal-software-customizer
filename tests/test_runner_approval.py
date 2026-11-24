from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from customizer.runner_approval import (
    ProtocolError,
    canonical_approval_payload,
    decode_approval_message,
    public_key_id,
)

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
IMAGE = "python:3.12-slim@sha256:" + "a" * 64
EXPORTER = "busybox@sha256:" + "b" * 64
SIGNATURE = base64.b64encode(b"s" * 64).decode("ascii")
KEY_ID = "d" * 64


def approval_message(**approval_overrides):
    approval = {
        "approval_id": str(uuid4()),
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "nonce": str(uuid4()),
        "requester_uid": 1200,
        "key_id": KEY_ID,
        "signature": SIGNATURE,
    }
    approval.update(approval_overrides)
    return {
        "protocol_version": "2",
        "request_id": str(uuid4()),
        "operation": "submit",
        "job": {
            "source_snapshot_sha256": "c" * 64,
            "profile_id": "python-pytest",
            "build_image_digest": IMAGE,
            "exporter_image_digest": EXPORTER,
            "policy_version": "usc-runner-policy-v1",
            "release_authorized": False,
            "approval": approval,
        },
    }


def test_accepts_v2_signed_submit_and_builds_canonical_payload():
    message = approval_message()
    validated = decode_approval_message(json.dumps(message), now=NOW)
    payload = json.loads(canonical_approval_payload(validated))
    assert payload["protocol_version"] == "2"
    assert payload["approval_id"] == message["job"]["approval"]["approval_id"]
    assert payload["requester_uid"] == 1200
    assert payload["release_authorized"] is False
    assert "signature" not in payload
    assert "request_id" not in payload


def test_canonical_payload_is_stable_and_independent_of_transport_request_id():
    message = approval_message()
    first = decode_approval_message(json.dumps(message), now=NOW)
    altered_transport = copy.deepcopy(message)
    altered_transport["request_id"] = str(uuid4())
    second = decode_approval_message(json.dumps(altered_transport), now=NOW)
    assert canonical_approval_payload(first) == canonical_approval_payload(second)


@pytest.mark.parametrize("mutation", [
    lambda m: m.update(protocol_version="1"),
    lambda m: m.update(extra="unexpected"),
    lambda m: m.update(operation="status"),
    lambda m: m["job"].update(source_path="/etc/passwd"),
    lambda m: m["job"].update(release_authorized=True),
    lambda m: m["job"].update(profile_id="arbitrary"),
    lambda m: m["job"]["approval"].update(extra="unexpected"),
    lambda m: m["job"]["approval"].update(requester_uid=0),
    lambda m: m["job"]["approval"].update(requester_uid=True),
    lambda m: m["job"]["approval"].update(key_id="A" * 64),
    lambda m: m["job"]["approval"].update(signature="not-base64"),
    lambda m: m["job"]["approval"].update(signature=base64.b64encode(b"short").decode("ascii")),
    lambda m: m["job"]["approval"].update(nonce="NOT-A-UUID"),
])
def test_rejects_unsafe_v2_fields(mutation):
    message = approval_message()
    mutation(message)
    with pytest.raises(ProtocolError):
        decode_approval_message(json.dumps(message), now=NOW)


def test_rejects_duplicate_keys_invalid_utf8_and_oversized_payload():
    with pytest.raises(ProtocolError, match="Duplicate"):
        decode_approval_message(b'{"protocol_version":"2","protocol_version":"2"}', now=NOW)
    with pytest.raises(ProtocolError, match="UTF-8"):
        decode_approval_message(b"\\xff", now=NOW)
    with pytest.raises(ProtocolError, match="byte limit"):
        decode_approval_message(b" " * (16 * 1024 + 1), now=NOW)


@pytest.mark.parametrize("overrides, message", [
    ({"issued_at": (NOW + timedelta(seconds=61)).isoformat()}, "future"),
    ({"expires_at": (NOW - timedelta(seconds=1)).isoformat()}, "expired"),
    ({"expires_at": (NOW + timedelta(minutes=31)).isoformat()}, "30-minute"),
    ({"issued_at": NOW.isoformat().replace("+00:00", "")}, "UTC"),
])
def test_rejects_invalid_approval_time_windows(overrides, message):
    with pytest.raises(ProtocolError, match=message):
        decode_approval_message(json.dumps(approval_message(**overrides)), now=NOW)


def test_rejects_non_utc_time_and_expiry_before_issue():
    message = approval_message(expires_at=(NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"))
    with pytest.raises(ProtocolError):
        decode_approval_message(json.dumps(message), now=NOW)


def test_public_key_id_hashes_exact_pem_bytes():
    pem = b"-----BEGIN PUBLIC KEY-----\\nsynthetic\\n-----END PUBLIC KEY-----\\n"
    assert public_key_id(pem) == public_key_id(pem)
    assert public_key_id(pem) != public_key_id(pem + b" ")
    with pytest.raises(ProtocolError):
        public_key_id(b"")
    with pytest.raises(ProtocolError):
        public_key_id(b"x" * 4097)


def test_canonical_payload_rejects_unvalidated_shape():
    with pytest.raises(ProtocolError):
        canonical_approval_payload({"protocol_version": "1"})
