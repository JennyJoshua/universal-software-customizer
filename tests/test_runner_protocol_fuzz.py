from __future__ import annotations

import base64
import copy
import json
import random
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from customizer.local_runner_broker import _decode_broker_message
from customizer.runner_approval import (
    ProtocolError,
    canonical_approval_payload,
    decode_approval_message,
    verify_ed25519_approval,
)

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
IMAGE = "python:3.12-slim@sha256:" + "a" * 64
EXPORTER = "busybox@sha256:" + "b" * 64


def valid_v2_message():
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
            "approval": {
                "approval_id": str(uuid4()),
                "issued_at": NOW.isoformat().replace("+00:00", "Z"),
                "expires_at": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "nonce": str(uuid4()),
                "requester_uid": 1200,
                "key_id": "d" * 64,
                "signature": base64.b64encode(b"x" * 64).decode("ascii"),
            },
        },
    }


def test_random_bounded_byte_inputs_only_return_validated_messages_or_protocol_errors():
    rng = random.Random(0x555343)
    for _ in range(750):
        raw = rng.randbytes(rng.randrange(0, 384))
        try:
            message = _decode_broker_message(raw)
        except ProtocolError:
            continue
        assert isinstance(message, dict)
        assert (
            (message.get("protocol_version") == "2" and message.get("operation") == "submit")
            or
            (message.get("protocol_version") == "1" and message.get("operation") in {"status", "cancel", "result"})
        )


def test_random_json_shapes_do_not_escape_protocol_error():
    rng = random.Random(0xA771)
    values = [None, True, False, 0, -1, 1.5, "", "x" * 200, [], {}, [1, 2], {"nested": []}]
    for _ in range(500):
        message = {
            "protocol_version": rng.choice(["1", "2", None, [], {}]),
            "request_id": rng.choice(values),
            "operation": rng.choice(["submit", "status", "cancel", "result", "shell", None, []]),
            "job": rng.choice(values),
            "job_id": rng.choice(values),
            "extra": rng.choice(values),
        }
        raw = json.dumps(message, separators=(",", ":"))
        try:
            result = _decode_broker_message(raw)
        except ProtocolError:
            continue
        assert result["operation"] in {"status", "cancel", "result"}


@pytest.mark.parametrize("path", [
    ("protocol_version",),
    ("request_id",),
    ("operation",),
    ("job", "source_snapshot_sha256"),
    ("job", "profile_id"),
    ("job", "build_image_digest"),
    ("job", "exporter_image_digest"),
    ("job", "policy_version"),
    ("job", "release_authorized"),
    ("job", "approval", "approval_id"),
    ("job", "approval", "issued_at"),
    ("job", "approval", "expires_at"),
    ("job", "approval", "nonce"),
    ("job", "approval", "requester_uid"),
    ("job", "approval", "key_id"),
    ("job", "approval", "signature"),
])
@pytest.mark.parametrize("bad_value", [None, True, 0, [], {}, ""])
def test_protocol_v2_rejects_mutated_required_fields(path, bad_value):
    message = valid_v2_message()
    target = message
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = bad_value
    with pytest.raises(ProtocolError):
        decode_approval_message(json.dumps(message), now=NOW)


def test_protocol_v2_rejects_random_unknown_fields_at_both_levels():
    rng = random.Random(0xB0A7)
    for _ in range(100):
        message = valid_v2_message()
        message["extra_" + str(rng.randrange(1_000_000))] = rng.choice([None, True, 1, "x", []])
        with pytest.raises(ProtocolError):
            decode_approval_message(json.dumps(message), now=NOW)

        message = valid_v2_message()
        message["job"]["approval"]["extra_" + str(rng.randrange(1_000_000))] = "unexpected"
        with pytest.raises(ProtocolError):
            decode_approval_message(json.dumps(message), now=NOW)


def test_deeply_nested_json_is_rejected_without_recursion_error():
    raw = b'{"protocol_version":"2","nested":' + (b"[" * 2500) + b"0" + (b"]" * 2500) + b"}"
    with pytest.raises(ProtocolError):
        _decode_broker_message(raw)


def test_unsigned_v1_submit_is_rejected_but_v1_status_shape_remains_supported():
    legacy_submit = {
        "protocol_version": "1",
        "request_id": str(uuid4()),
        "operation": "submit",
        "job": {},
    }
    with pytest.raises(ProtocolError, match="Unsigned"):
        _decode_broker_message(json.dumps(legacy_submit))
    status = {
        "protocol_version": "1",
        "request_id": str(uuid4()),
        "operation": "status",
        "job_id": str(uuid4()),
    }
    assert _decode_broker_message(json.dumps(status)) == status


def test_canonical_payload_rejects_mutated_message_and_verifier_fails_before_key_access(monkeypatch):
    message = valid_v2_message()
    message["job"]["release_authorized"] = True
    with pytest.raises(ProtocolError):
        canonical_approval_payload(message)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("OpenSSL must not run for an invalid approval envelope.")

    monkeypatch.setattr("customizer.runner_approval.subprocess.run", forbidden)
    with pytest.raises(ProtocolError):
        verify_ed25519_approval(
            message,
            public_key_path="/not/read/for/invalid/envelope.pem",
            state_directory="/not/read/for/invalid/state",
            peer_uid=1200,
            now=NOW,
        )
