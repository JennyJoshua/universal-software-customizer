from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from customizer.runner_approval import canonical_approval_payload, public_key_id


pytestmark = pytest.mark.skipif(
    os.environ.get("USC_RUNNER_IDENTITY_INTEGRATION") != "1",
    reason="Requires the explicit ephemeral GitHub Actions service-identity test gate.",
)


def _sudo(*args, check=True, **kwargs):
    return subprocess.run(
        ["sudo", "-n", *args],
        check=check,
        text=True,
        capture_output=True,
        **kwargs,
    )


def _uid(username):
    return int(_sudo("id", "-u", username).stdout.strip())


def _submit_message(private_key, public_key, approver, requester_uid, public_dir, *, request_id=None, approval_id=None, nonce=None):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    message = {
        "protocol_version": "2",
        "request_id": request_id or str(uuid4()),
        "operation": "submit",
        "job": {
            "source_snapshot_sha256": "c" * 64,
            "profile_id": "python-pytest",
            "build_image_digest": "python:3.12-slim@sha256:" + "a" * 64,
            "exporter_image_digest": "busybox@sha256:" + "b" * 64,
            "policy_version": "usc-runner-policy-v1",
            "release_authorized": False,
            "approval": {
                "approval_id": approval_id or str(uuid4()),
                "issued_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
                "nonce": nonce or str(uuid4()),
                "requester_uid": requester_uid,
                "key_id": public_key_id(Path(public_key).read_bytes()),
                "signature": base64.b64encode(b"0" * 64).decode("ascii"),
            },
        },
    }
    payload_path = Path(public_dir) / f"payload-{uuid4()}.bin"
    signature_path = Path(public_dir) / f"signature-{uuid4()}.bin"
    payload_path.write_bytes(canonical_approval_payload(message))
    payload_path.chmod(0o644)
    try:
        _sudo(
            "-u", approver, "--", "openssl", "pkeyutl", "-sign",
            "-inkey", private_key, "-in", str(payload_path), "-rawin",
            "-out", str(signature_path),
        )
        _sudo("chmod", "0644", str(signature_path))
        message["job"]["approval"]["signature"] = base64.b64encode(signature_path.read_bytes()).decode("ascii")
    finally:
        payload_path.unlink(missing_ok=True)
        _sudo("rm", "-f", str(signature_path), check=False)
    return message


def test_runner_service_identity_is_separated_from_control_plane():
    if sys.platform != "linux":
        pytest.fail("The service-identity integration test requires Linux SO_PEERCRED.")
    if shutil.which("sudo") is None:
        pytest.fail("The service-identity integration test requires sudo.")

    suffix = uuid4().hex[:8]
    group = "uscg" + suffix
    approval_group = "usca" + suffix
    runner = "uscr" + suffix
    client = "uscc" + suffix
    outsider = "usco" + suffix
    approver = "uscp" + suffix
    base = tempfile.mkdtemp(prefix="usc-identity-")
    broker_process = None
    created_users = []
    created_groups = []

    try:
        for group_name in (group, approval_group):
            _sudo("groupadd", group_name)
            created_groups.append(group_name)
        for username, primary_group in (
            (runner, group), (client, group), (outsider, group), (approver, approval_group)
        ):
            _sudo("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", primary_group, username)
            created_users.append(username)

        runner_uid = _uid(runner)
        client_uid = _uid(client)
        outsider_uid = _uid(outsider)
        approver_uid = _uid(approver)
        group_gid = int(_sudo("getent", "group", group).stdout.strip().split(":")[2])

        _sudo("chmod", "0755", base)
        socket_dir = os.path.join(base, "socket")
        state_dir = os.path.join(base, "state")
        key_path = os.path.join(state_dir, "approval-public.pem")
        approval_private_dir = os.path.join(base, "approval-private")
        approval_public_dir = os.path.join(base, "approval-public")
        private_key = os.path.join(approval_private_dir, "approval-private.pem")
        public_key = os.path.join(approval_public_dir, "approval-public.pem")
        _sudo("install", "-d", "-o", runner, "-g", group, "-m", "2710", socket_dir)
        _sudo("install", "-d", "-o", runner, "-g", group, "-m", "0700", state_dir)
        _sudo("install", "-d", "-o", approver, "-g", approval_group, "-m", "0700", approval_private_dir)
        _sudo("install", "-d", "-o", approver, "-g", approval_group, "-m", "1777", approval_public_dir)
        _sudo("-u", approver, "--", "openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key)
        _sudo("-u", approver, "--", "openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key)
        _sudo("install", "-o", runner, "-g", group, "-m", "0644", public_key, key_path)

        # The control-plane UID can traverse/connect through the group socket,
        # but cannot list the socket directory or read runner-private state.
        assert _sudo("-u", client, "--", "ls", socket_dir, check=False).returncode != 0
        assert _sudo("-u", runner, "--", "cat", key_path, check=False).returncode == 0
        assert _sudo("-u", runner, "--", "cat", private_key, check=False).returncode != 0
        assert _sudo("-u", client, "--", "cat", private_key, check=False).returncode != 0
        assert _sudo("-u", outsider, "--", "cat", private_key, check=False).returncode != 0
        assert _sudo("-u", approver, "--", "test", "-r", private_key, check=False).returncode == 0

        # The runner service identity is deliberately not a Docker administrator.
        runner_groups = _sudo("id", "-nG", runner).stdout.split()
        client_groups = _sudo("id", "-nG", client).stdout.split()
        assert "docker" not in runner_groups
        assert "docker" not in client_groups
        assert "docker" not in _sudo("id", "-nG", approver).stdout.split()
        docker_socket = "/var/run/docker.sock"
        if _sudo("test", "-S", docker_socket, check=False).returncode == 0:
            assert _sudo("-u", runner, "--", "test", "-r", docker_socket, check=False).returncode != 0
            assert _sudo("-u", client, "--", "test", "-r", docker_socket, check=False).returncode != 0

        socket_path = os.path.join(socket_dir, "runner.sock")
        source_package = Path(__file__).resolve().parents[2] / "engine" / "customizer"
        python_root = os.path.join(base, "python")
        os.makedirs(python_root, mode=0o755)
        shutil.copytree(source_package, os.path.join(python_root, "customizer"))
        _sudo("chown", "-R", f"{runner}:{group}", python_root)
        _sudo("chmod", "-R", "a+rX", python_root)
        repo_engine = python_root
        state_db_path = os.path.join(state_dir, "broker.sqlite3")
        client_code = (
            "import json,sys; from customizer.local_runner_broker import send_local_request; "
            "print(json.dumps(send_local_request(sys.argv[1], json.loads(sys.argv[2]))))"
        )

        def start_broker():
            return subprocess.Popen(
                ["sudo", "-n", "-u", runner, "--", "env", f"PYTHONPATH={repo_engine}",
                 "python3", "-m", "customizer.local_runner_broker",
                 "--socket", socket_path, "--socket-gid", str(group_gid),
                 "--state-db", state_db_path, "--approval-public-key", key_path,
                 "--submitter-uid", str(client_uid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

        def wait_for_broker_response(process):
            deadline = time.monotonic() + 10
            probe_message = {
                "protocol_version": "1",
                "request_id": str(uuid4()),
                "operation": "status",
                "job_id": str(uuid4()),
            }
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    error = process.stderr.read() if process.stderr else ""
                    pytest.fail(f"Runner broker exited during startup: {error}")
                probe = _sudo(
                    "-u", client, "--", "env", f"PYTHONPATH={repo_engine}",
                    "python3", "-c", client_code, socket_path, json.dumps(probe_message),
                    check=False,
                )
                if probe.returncode == 0:
                    response = json.loads(probe.stdout.strip())
                    if response.get("error") == "Unknown job or unauthorized operation.":
                        return
                time.sleep(0.05)
            pytest.fail("Runner broker did not answer a protocol request.")

        broker_process = start_broker()
        wait_for_broker_response(broker_process)

        # Verify owner/group/mode on the service socket.
        socket_stat = _sudo("stat", "-c", "%u:%g:%a", socket_path).stdout.strip()
        assert socket_stat == f"{runner_uid}:{group_gid}:660"
        state_stat = _sudo("stat", "-c", "%u:%a", state_db_path).stdout.strip()
        assert state_stat == f"{runner_uid}:600"
        assert _sudo("-u", client, "--", "cat", state_db_path, check=False).returncode != 0

        original_submission = _submit_message(
            private_key, public_key, approver, client_uid, approval_public_dir,
        )
        submitted = _sudo(
            "-u", client, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(original_submission),
        )
        accepted = json.loads(submitted.stdout.strip())
        assert accepted["ok"] is True
        assert accepted["state"] == "queued"

        # A different UID in the socket group can connect, but peer-UID policy denies it.
        denied = _sudo(
            "-u", outsider, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(_submit_message(
                private_key, public_key, approver, outsider_uid, approval_public_dir,
            )),
        )
        rejected = json.loads(denied.stdout.strip())
        assert rejected["ok"] is False
        assert "not authorized" in rejected["error"].lower()

        # Kill the broker without graceful cleanup, then verify stale-socket
        # recovery and durable job/replay state after a fresh process starts.
        _sudo("pkill", "-KILL", "-u", runner, check=False)
        broker_process.wait(timeout=5)
        assert _sudo("pgrep", "-u", runner, check=False).returncode != 0
        broker_process = None

        broker_process = start_broker()
        wait_for_broker_response(broker_process)

        status_message = {
            "protocol_version": "1",
            "request_id": str(uuid4()),
            "operation": "status",
            "job_id": accepted["job_id"],
        }
        status_result = _sudo(
            "-u", client, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(status_message), check=False,
        )
        assert status_result.returncode == 0, status_result.stderr
        persisted_status = json.loads(status_result.stdout.strip())
        assert persisted_status["ok"] is True
        assert persisted_status["state"] == "queued"

        replayed_request = _sudo(
            "-u", client, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(original_submission),
        )
        assert json.loads(replayed_request.stdout.strip())["error"] == "Duplicate request ID."

        replayed_approval = _submit_message(
            private_key, public_key, approver, client_uid, approval_public_dir,
            approval_id=original_submission["job"]["approval"]["approval_id"],
        )
        replayed_approval_result = _sudo(
            "-u", client, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(replayed_approval),
        )
        assert "already been submitted" in json.loads(replayed_approval_result.stdout.strip())["error"]

        replayed_nonce = _submit_message(
            private_key, public_key, approver, client_uid, approval_public_dir,
            nonce=original_submission["job"]["approval"]["nonce"],
        )
        replayed_nonce_result = _sudo(
            "-u", client, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(replayed_nonce),
        )
        assert "nonce has already been used" in json.loads(replayed_nonce_result.stdout.strip())["error"]

        # Exercise the real CLI's graceful SIGTERM path: it stops accepting,
        # closes SQLite, and removes the socket after the active request ends.
        _sudo("pkill", "-TERM", "-u", runner, check=False)
        broker_process.wait(timeout=5)
        broker_process = None
        assert _sudo("test", "-S", socket_path, check=False).returncode != 0

    finally:
        if broker_process is not None and broker_process.poll() is None:
            _sudo("pkill", "-KILL", "-u", runner, check=False)
            try:
                broker_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker_process.kill()
                broker_process.wait(timeout=5)
        _sudo("rm", "-rf", base, check=False)
        for username in reversed(created_users):
            _sudo("userdel", username, check=False)
        for group_name in reversed(created_groups):
            _sudo("groupdel", group_name, check=False)
