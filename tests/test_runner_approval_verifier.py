from __future__ import annotations

import base64
import os
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from customizer import runner_approval as approval
from customizer.runner_approval import (
    ProtocolError,
    canonical_approval_payload,
    public_key_id,
    verify_ed25519_approval,
)

NOW = datetime.now(timezone.utc).replace(microsecond=0)
IMAGE = "python:3.12-slim@sha256:" + "a" * 64
EXPORTER = "busybox@sha256:" + "b" * 64


def make_keypair(directory: Path, prefix: str = "test"):
    private = directory / f"{prefix}-private.pem"
    public = directory / f"{prefix}-public.pem"
    subprocess.run(
        [approval.OPENSSL_BINARY, "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [approval.OPENSSL_BINARY, "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    private.chmod(0o600)
    public.chmod(0o600)
    return private, public


def signed_message(private: Path, public: Path):
    message = {
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
                "requester_uid": os.getuid(),
                "key_id": public_key_id(public.read_bytes()),
                "signature": base64.b64encode(b"0" * 64).decode("ascii"),
            },
        },
    }
    payload = canonical_approval_payload(message)
    payload_path = private.parent / "approval-payload.bin"
    payload_path.write_bytes(payload)
    payload_path.chmod(0o600)
    try:
        result = subprocess.run(
            [approval.OPENSSL_BINARY, "pkeyutl", "-sign", "-inkey", str(private),
             "-in", str(payload_path), "-rawin"],
            capture_output=True, check=True,
        )
    finally:
        payload_path.unlink(missing_ok=True)
    message["job"]["approval"]["signature"] = base64.b64encode(result.stdout).decode("ascii")
    return message


@pytest.fixture
def signed_fixture(tmp_path):
    private, public = make_keypair(tmp_path)
    state_dir = tmp_path / "runner-state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    return signed_message(private, public), public, state_dir


def verify(message, public, state_dir, *, peer_uid=None):
    return verify_ed25519_approval(
        message,
        public_key_path=public,
        state_directory=state_dir,
        peer_uid=os.getuid() if peer_uid is None else peer_uid,
        now=NOW,
    )


def test_verifies_real_ed25519_signature_and_cleans_temporary_signature(signed_fixture):
    message, public, state_dir = signed_fixture
    assert verify(message, public, state_dir) is True
    assert list(state_dir.iterdir()) == []


def test_rejects_tampering_after_signature(signed_fixture):
    message, public, state_dir = signed_fixture
    message["job"]["source_snapshot_sha256"] = "e" * 64
    with pytest.raises(ProtocolError, match="invalid"):
        verify(message, public, state_dir)


def test_rejects_wrong_trusted_key(signed_fixture, tmp_path):
    message, _public, state_dir = signed_fixture
    _private2, wrong_public = make_keypair(tmp_path, "wrong")
    with pytest.raises(ProtocolError, match="key ID"):
        verify(message, wrong_public, state_dir)


def test_rejects_authenticated_peer_uid_mismatch(signed_fixture):
    message, public, state_dir = signed_fixture
    with pytest.raises(ProtocolError, match="does not match"):
        verify(message, public, state_dir, peer_uid=os.getuid() + 1000)


def test_rejects_group_or_world_writable_public_key(signed_fixture):
    message, public, state_dir = signed_fixture
    public.chmod(0o666)
    with pytest.raises(ProtocolError, match="non-writable"):
        verify(message, public, state_dir)


def test_rejects_symlinked_public_key(signed_fixture, tmp_path):
    message, public, state_dir = signed_fixture
    alias = tmp_path / "public-key-link.pem"
    alias.symlink_to(public)
    with pytest.raises(ProtocolError, match="safely open"):
        verify(message, alias, state_dir)


def test_rejects_non_private_state_directory(signed_fixture):
    message, public, state_dir = signed_fixture
    state_dir.chmod(0o755)
    with pytest.raises(ProtocolError, match="private"):
        verify(message, public, state_dir)


def test_fails_closed_when_openssl_is_unavailable(signed_fixture, monkeypatch):
    message, public, state_dir = signed_fixture
    monkeypatch.setattr(approval, "OPENSSL_BINARY", "/missing/usc-openssl")
    with pytest.raises(ProtocolError, match="unavailable"):
        verify(message, public, state_dir)


def test_rejects_invalid_signature_bytes_and_cleans_temp_file(signed_fixture):
    message, public, state_dir = signed_fixture
    message["job"]["approval"]["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
    with pytest.raises(ProtocolError, match="invalid"):
        verify(message, public, state_dir)
    assert list(state_dir.iterdir()) == []


def test_rejects_non_absolute_public_key_path(signed_fixture):
    message, public, state_dir = signed_fixture
    with pytest.raises(ProtocolError, match="absolute"):
        verify_ed25519_approval(
            message, public_key_path=Path(public.name),
            state_directory=state_dir, peer_uid=os.getuid(), now=NOW,
        )
