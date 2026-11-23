from __future__ import annotations
import os
import socket
import stat
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from customizer.local_runner_broker import LocalRunnerBroker, send_local_request
from customizer.runner_protocol import POLICY_VERSION

IMAGE = "python:3.12-slim@sha256:" + "a" * 64
EXPORTER = "busybox@sha256:" + "b" * 64


def submit_message(*, request_id=None, approval_id=None):
    return {
        "protocol_version": "1", "request_id": request_id or str(uuid4()),
        "operation": "submit",
        "job": {
            "approval_id": approval_id or str(uuid4()),
            "source_snapshot_sha256": "c" * 64,
            "profile_id": "python-pytest",
            "build_image_digest": IMAGE,
            "exporter_image_digest": EXPORTER,
            "policy_version": POLICY_VERSION,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "release_authorized": False,
        },
    }


@pytest.fixture
def running_broker(tmp_path):
    socket_dir = tmp_path / "private"
    broker = LocalRunnerBroker(socket_dir / "runner.sock", submitter_uids={os.getuid()})
    broker.start()
    thread = threading.Thread(target=broker.serve_forever, daemon=True)
    thread.start()
    try:
        yield broker
    finally:
        broker.close()
        thread.join(timeout=2)


def test_broker_socket_directory_and_socket_are_private(running_broker):
    directory = running_broker.socket_path.parent.stat()
    endpoint = running_broker.socket_path.stat(follow_symlinks=False)
    assert stat.S_IMODE(directory.st_mode) == 0o700
    assert directory.st_uid == os.getuid()
    assert stat.S_IMODE(endpoint.st_mode) == 0o600
    assert stat.S_ISSOCK(endpoint.st_mode)
    assert endpoint.st_uid == os.getuid()


def test_broker_accepts_synthetic_submit_and_supports_status_cancel_result(running_broker):
    submitted = send_local_request(running_broker.socket_path, submit_message())
    assert submitted["ok"] is True
    job_id = submitted["job_id"]
    assert submitted["state"] == "queued"
    status = send_local_request(running_broker.socket_path, {
        "protocol_version": "1", "request_id": str(uuid4()),
        "operation": "status", "job_id": job_id,
    })
    assert status["ok"] is True and status["state"] == "queued"
    result = send_local_request(running_broker.socket_path, {
        "protocol_version": "1", "request_id": str(uuid4()),
        "operation": "result", "job_id": job_id,
    })
    assert result["ok"] is True and result["result_available"] is False
    cancelled = send_local_request(running_broker.socket_path, {
        "protocol_version": "1", "request_id": str(uuid4()),
        "operation": "cancel", "job_id": job_id,
    })
    assert cancelled["ok"] is True and cancelled["state"] == "cancelled"


def test_broker_rejects_unknown_fields_and_unknown_jobs(running_broker):
    malformed = submit_message()
    malformed["job"]["source_path"] = "/etc"
    response = send_local_request(running_broker.socket_path, malformed)
    assert response["ok"] is False and "unknown fields" in response["error"]
    unknown = send_local_request(running_broker.socket_path, {
        "protocol_version": "1", "request_id": str(uuid4()),
        "operation": "status", "job_id": str(uuid4()),
    })
    assert unknown["ok"] is False and unknown["error"] == "Unknown job or unauthorized operation."


def test_broker_blocks_duplicate_request_and_approval_replay(running_broker):
    request_id, approval_id = str(uuid4()), str(uuid4())
    first = send_local_request(running_broker.socket_path,
                               submit_message(request_id=request_id, approval_id=approval_id))
    assert first["ok"] is True
    replay_request = send_local_request(running_broker.socket_path,
                                        submit_message(request_id=request_id))
    assert replay_request["ok"] is False and "Duplicate request ID" in replay_request["error"]
    replay_approval = send_local_request(running_broker.socket_path,
                                         submit_message(approval_id=approval_id))
    assert replay_approval["ok"] is False and "already been submitted" in replay_approval["error"]


def test_broker_uses_kernel_peer_uid_not_caller_supplied_field(running_broker, monkeypatch):
    import customizer.local_runner_broker as broker_module
    submitted = send_local_request(running_broker.socket_path, submit_message())
    assert submitted["ok"] is True
    monkeypatch.setattr(broker_module, "_peer_uid", lambda _connection: os.getuid() + 10000)
    response = send_local_request(running_broker.socket_path, {
        "protocol_version": "1", "request_id": str(uuid4()),
        "operation": "status", "job_id": submitted["job_id"],
    })
    assert response["ok"] is False
    assert response["error"] == "Unknown job or unauthorized operation."


def test_broker_refuses_to_replace_regular_file_or_symlink_socket_path(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    regular = private / "runner.sock"
    regular.write_text("keep", encoding="utf-8")
    broker = LocalRunnerBroker(regular, submitter_uids={os.getuid()})
    with pytest.raises(ValueError, match="non-owned or non-socket"):
        broker.start()
    assert regular.read_text(encoding="utf-8") == "keep"
    linked = private / "linked.sock"
    linked.symlink_to(regular)
    linked_broker = LocalRunnerBroker(linked, submitter_uids={os.getuid()})
    with pytest.raises(ValueError, match="symlink"):
        linked_broker.start()
    assert linked.is_symlink()


def test_broker_fails_closed_when_private_directory_permissions_are_open(tmp_path):
    socket_dir = tmp_path / "open"
    socket_dir.mkdir(mode=0o755)
    socket_dir.chmod(0o755)
    broker = LocalRunnerBroker(socket_dir / "runner.sock", submitter_uids={os.getuid()})
    with pytest.raises(ValueError, match="private"):
        broker.start()


def test_broker_returns_no_artifacts_and_never_claims_execution(running_broker):
    submitted = send_local_request(running_broker.socket_path, submit_message())
    result = send_local_request(running_broker.socket_path, {
        "protocol_version": "1", "request_id": str(uuid4()),
        "operation": "result", "job_id": submitted["job_id"],
    })
    assert result == {"ok": True, "job_id": submitted["job_id"],
                      "state": "queued", "result_available": False}


def test_broker_restart_loses_in_memory_jobs_by_design(tmp_path):
    socket_path = tmp_path / "private" / "runner.sock"
    first = LocalRunnerBroker(socket_path, submitter_uids={os.getuid()})
    first.start()
    thread1 = threading.Thread(target=first.serve_forever, daemon=True)
    thread1.start()
    submitted = send_local_request(socket_path, submit_message())
    first.close()
    thread1.join(timeout=2)
    second = LocalRunnerBroker(socket_path, submitter_uids={os.getuid()})
    second.start()
    thread2 = threading.Thread(target=second.serve_forever, daemon=True)
    thread2.start()
    try:
        status = send_local_request(socket_path, {
            "protocol_version": "1", "request_id": str(uuid4()),
            "operation": "status", "job_id": submitted["job_id"],
        })
        assert status["ok"] is False and status["error"] == "Unknown job or unauthorized operation."
    finally:
        second.close()
        thread2.join(timeout=2)



def test_broker_rejects_replayed_status_request_id(running_broker):
    submitted = send_local_request(running_broker.socket_path, submit_message())
    request_id = str(uuid4())
    status_message = {
        "protocol_version": "1", "request_id": request_id,
        "operation": "status", "job_id": submitted["job_id"],
    }
    assert send_local_request(running_broker.socket_path, status_message)["ok"] is True
    replay = send_local_request(running_broker.socket_path, status_message)
    assert replay["ok"] is False
    assert replay["error"] == "Duplicate request ID."


def test_broker_enforces_in_memory_capacity_limit(running_broker, monkeypatch):
    import customizer.local_runner_broker as broker_module
    monkeypatch.setattr(broker_module, "MAX_JOBS", 0)
    response = send_local_request(running_broker.socket_path, submit_message())
    assert response["ok"] is False
    assert response["error"] == "Broker job capacity has been reached."



def test_broker_does_not_unlink_an_active_socket(tmp_path):
    socket_path = tmp_path / "private" / "runner.sock"
    first = LocalRunnerBroker(socket_path, submitter_uids={os.getuid()})
    first.start()
    second = LocalRunnerBroker(socket_path, submitter_uids={os.getuid()})
    try:
        with pytest.raises(ValueError, match="already listening"):
            second.start()
        assert stat.S_ISSOCK(socket_path.stat(follow_symlinks=False).st_mode)
    finally:
        first.close()


def test_broker_removes_only_a_stale_owned_socket(tmp_path):
    socket_dir = tmp_path / "private"
    socket_dir.mkdir(mode=0o700)
    socket_path = socket_dir / "runner.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(socket_path))
    stale.close()
    broker = LocalRunnerBroker(socket_path, submitter_uids={os.getuid()})
    broker.start()
    try:
        assert stat.S_ISSOCK(socket_path.stat(follow_symlinks=False).st_mode)
    finally:
        broker.close()



def test_broker_supports_preprovisioned_group_socket_mode(tmp_path):
    socket_dir = tmp_path / "group-socket"
    socket_dir.mkdir(mode=0o700)
    socket_dir.chmod(0o2710)
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    broker = LocalRunnerBroker(
        socket_dir / "runner.sock",
        submitter_uids={os.getuid()},
        socket_gid=os.getgid(),
        state_db_path=state_dir / "broker.sqlite3",
    )
    broker.start()
    try:
        directory = socket_dir.stat()
        endpoint = broker.socket_path.stat(follow_symlinks=False)
        assert stat.S_IMODE(directory.st_mode) == 0o2710
        assert directory.st_gid == os.getgid()
        assert stat.S_IMODE(endpoint.st_mode) == 0o660
        assert endpoint.st_gid == os.getgid()
    finally:
        broker.close()


def test_broker_group_socket_mode_requires_preprovisioned_private_directory(tmp_path):
    missing = tmp_path / "not-created"
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    with pytest.raises(ValueError, match="pre-provisioned"):
        LocalRunnerBroker(
            missing / "runner.sock", socket_gid=os.getgid(),
            state_db_path=state_dir / "broker.sqlite3",
        ).start()

    open_dir = tmp_path / "open-group"
    open_dir.mkdir(mode=0o700)
    open_dir.chmod(0o750)
    with pytest.raises(ValueError, match="2710"):
        LocalRunnerBroker(
            open_dir / "runner.sock", socket_gid=os.getgid(),
            state_db_path=state_dir / "broker.sqlite3",
        ).start()



def test_group_socket_mode_requires_durable_state_database(tmp_path):
    socket_dir = tmp_path / "group-socket"
    socket_dir.mkdir(mode=0o700)
    socket_dir.chmod(0o2710)
    with pytest.raises(ValueError, match="durable runner state database"):
        LocalRunnerBroker(socket_dir / "runner.sock", socket_gid=os.getgid()).start()



def test_broker_submit_transaction_rolls_back_job_if_replay_record_fails(tmp_path, monkeypatch):
    socket_dir = tmp_path / "socket"
    socket_dir.mkdir(mode=0o700)
    socket_dir.chmod(0o700)
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    broker = LocalRunnerBroker(
        socket_dir / "runner.sock",
        submitter_uids={os.getuid()},
        state_db_path=state_dir / "broker.sqlite3",
    )
    broker.start()
    message = submit_message()

    def fail_record(_request_id):
        raise RuntimeError("injected replay-ledger write failure")

    monkeypatch.setattr(broker._state, "record_request", fail_record)
    try:
        with pytest.raises(RuntimeError, match="injected"):
            broker._dispatch(os.getuid(), message)
        assert broker._state.job_count() == 0
        assert not broker._state.approval_seen(message["job"]["approval_id"])
        assert not broker._state.request_seen(message["request_id"])
    finally:
        broker.close()



def test_request_stop_finishes_accept_loop_before_close_removes_socket(tmp_path):
    socket_dir = tmp_path / "socket"
    socket_dir.mkdir(mode=0o700)
    socket_dir.chmod(0o700)
    broker = LocalRunnerBroker(socket_dir / "runner.sock", submitter_uids={os.getuid()})
    broker.start()
    thread = threading.Thread(target=broker.serve_forever, daemon=True)
    thread.start()
    broker.request_stop()
    thread.join(timeout=2)
    try:
        assert not thread.is_alive()
        assert broker.socket_path.exists()
    finally:
        broker.close()
    assert not broker.socket_path.exists()
