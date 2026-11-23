from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest


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


def _submit_message():
    return {
        "protocol_version": "1",
        "request_id": str(uuid4()),
        "operation": "submit",
        "job": {
            "approval_id": str(uuid4()),
            "source_snapshot_sha256": "c" * 64,
            "profile_id": "python-pytest",
            "build_image_digest": "python:3.12-slim@sha256:" + "a" * 64,
            "exporter_image_digest": "busybox@sha256:" + "b" * 64,
            "policy_version": "usc-runner-policy-v1",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "release_authorized": False,
        },
    }


def test_runner_service_identity_is_separated_from_control_plane():
    if sys.platform != "linux":
        pytest.fail("The service-identity integration test requires Linux SO_PEERCRED.")
    if shutil.which("sudo") is None:
        pytest.fail("The service-identity integration test requires sudo.")

    suffix = uuid4().hex[:8]
    group = "uscg" + suffix
    runner = "uscr" + suffix
    client = "uscc" + suffix
    outsider = "usco" + suffix
    base = tempfile.mkdtemp(prefix="usc-identity-")
    broker_process = None
    created_users = []
    created_group = False

    try:
        _sudo("groupadd", group)
        created_group = True
        for username in (runner, client, outsider):
            _sudo("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", group, username)
            created_users.append(username)

        runner_uid = _uid(runner)
        client_uid = _uid(client)
        group_gid = int(_sudo("getent", "group", group).stdout.strip().split(":")[2])

        _sudo("chmod", "0755", base)
        socket_dir = os.path.join(base, "socket")
        state_dir = os.path.join(base, "state")
        key_path = os.path.join(state_dir, "approval.key")
        _sudo("install", "-d", "-o", runner, "-g", group, "-m", "2710", socket_dir)
        _sudo("install", "-d", "-o", runner, "-g", group, "-m", "0700", state_dir)
        _sudo(
            "-u", runner, "--", "python3", "-c",
            "import os,sys; fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600); os.write(fd,b'synthetic-fixture-only'); os.close(fd)",
            key_path,
        )

        # The control-plane UID can traverse/connect through the group socket,
        # but cannot list the socket directory or read runner-private state.
        assert _sudo("-u", client, "--", "ls", socket_dir, check=False).returncode != 0
        assert _sudo("-u", client, "--", "cat", key_path, check=False).returncode != 0

        # The runner service identity is deliberately not a Docker administrator.
        runner_groups = _sudo("id", "-nG", runner).stdout.split()
        client_groups = _sudo("id", "-nG", client).stdout.split()
        assert "docker" not in runner_groups
        assert "docker" not in client_groups
        docker_socket = "/var/run/docker.sock"
        if _sudo("test", "-S", docker_socket, check=False).returncode == 0:
            assert _sudo("-u", runner, "--", "test", "-r", docker_socket, check=False).returncode != 0
            assert _sudo("-u", client, "--", "test", "-r", docker_socket, check=False).returncode != 0

        socket_path = os.path.join(socket_dir, "runner.sock")
        repo_engine = str(Path(__file__).resolve().parents[2] / "engine")
        server_code = (
            "import sys; from customizer.local_runner_broker import LocalRunnerBroker; "
            "b=LocalRunnerBroker(sys.argv[1], submitter_uids={int(sys.argv[2])}, socket_gid=int(sys.argv[3])); "
            "b.start(); print('READY', flush=True); b.serve_forever()"
        )
        broker_process = subprocess.Popen(
            ["sudo", "-n", "-u", runner, "--", "env", f"PYTHONPATH={repo_engine}",
             "python3", "-c", server_code, socket_path, str(client_uid), str(group_gid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if _sudo("test", "-S", socket_path, check=False).returncode == 0:
                break
            if broker_process.poll() is not None:
                error = broker_process.stderr.read() if broker_process.stderr else ""
                pytest.fail(f"Runner broker exited during startup: {error}")
            time.sleep(0.05)
        else:
            pytest.fail("Runner broker did not create its socket.")

        # Verify owner/group/mode on the service socket.
        socket_stat = _sudo("stat", "-c", "%u:%g:%a", socket_path).stdout.strip()
        assert socket_stat == f"{runner_uid}:{group_gid}:660"

        client_code = (
            "import json,sys; from customizer.local_runner_broker import send_local_request; "
            "print(json.dumps(send_local_request(sys.argv[1], json.loads(sys.argv[2]))))"
        )
        submitted = _sudo(
            "-u", client, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(_submit_message()),
        )
        accepted = json.loads(submitted.stdout.strip())
        assert accepted["ok"] is True
        assert accepted["state"] == "queued"

        # A different UID in the socket group can connect, but peer-UID policy denies it.
        denied = _sudo(
            "-u", outsider, "--", "env", f"PYTHONPATH={repo_engine}", "python3", "-c", client_code,
            socket_path, json.dumps(_submit_message()),
        )
        rejected = json.loads(denied.stdout.strip())
        assert rejected["ok"] is False
        assert "not authorized" in rejected["error"].lower()

    finally:
        if broker_process is not None and broker_process.poll() is None:
            try:
                os.killpg(broker_process.pid, signal.SIGTERM)
                broker_process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(broker_process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        _sudo("rm", "-rf", base, check=False)
        for username in reversed(created_users):
            _sudo("userdel", username, check=False)
        if created_group:
            _sudo("groupdel", group, check=False)
