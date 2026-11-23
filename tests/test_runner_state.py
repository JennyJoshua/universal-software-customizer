from __future__ import annotations

import os
import stat
import sqlite3

import pytest

from customizer.runner_protocol import ProtocolError
from customizer.runner_state import RunnerStateStore


def _private_state_dir(tmp_path):
    path = tmp_path / "runner-state"
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def test_state_database_is_created_with_private_owner_permissions(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    path = state_dir / "broker.sqlite3"
    store = RunnerStateStore(path)
    store.start()
    try:
        info = path.stat(follow_symlinks=False)
        assert stat.S_ISREG(info.st_mode)
        assert info.st_uid == os.getuid()
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_nlink == 1
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == 1
    finally:
        store.close()


def test_state_database_rejects_non_private_or_unowned_parent(tmp_path):
    state_dir = tmp_path / "open-state"
    state_dir.mkdir(mode=0o750)
    state_dir.chmod(0o750)
    with pytest.raises(ProtocolError, match="private"):
        RunnerStateStore(state_dir / "broker.sqlite3").start()


def test_state_database_rejects_symlink_and_unsafe_existing_file(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    target = state_dir / "target.db"
    target.write_bytes(b"synthetic")
    target.chmod(0o600)
    linked = state_dir / "linked.db"
    linked.symlink_to(target)
    with pytest.raises(ProtocolError, match="symlink"):
        RunnerStateStore(linked).start()

    unsafe = state_dir / "unsafe.db"
    unsafe.write_bytes(b"synthetic")
    unsafe.chmod(0o644)
    with pytest.raises(ProtocolError, match="regular file"):
        RunnerStateStore(unsafe).start()


def test_state_database_rejects_hardlinked_existing_file(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    original = state_dir / "original.db"
    original.write_bytes(b"synthetic")
    original.chmod(0o600)
    linked = state_dir / "linked.db"
    os.link(original, linked)
    with pytest.raises(ProtocolError, match="single-link"):
        RunnerStateStore(original).start()


def test_state_database_persists_jobs_and_replay_ids_across_store_restart(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    path = state_dir / "broker.sqlite3"
    job = {
        "owner_uid": os.getuid(),
        "state": "queued",
        "profile_id": "python-pytest",
        "source_snapshot_sha256": "a" * 64,
        "approval_id": "approval-fixture-1",
        "release_authorized": False,
    }
    first = RunnerStateStore(path)
    first.start()
    with first.transaction():
        first.create_job("job-fixture-1", job)
        first.record_request("request-fixture-1")
    first.close()

    second = RunnerStateStore(path)
    second.start()
    try:
        assert second.job_count() == 1
        assert second.request_count() == 1
        assert second.request_seen("request-fixture-1")
        assert second.approval_seen("approval-fixture-1")
        assert second.get_job("job-fixture-1") == job
    finally:
        second.close()


def test_state_database_transaction_rolls_back_partial_changes(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    store = RunnerStateStore(state_dir / "broker.sqlite3")
    store.start()
    try:
        with pytest.raises(RuntimeError, match="rollback"):
            with store.transaction():
                store.record_request("request-rollback")
                raise RuntimeError("rollback")
        assert not store.request_seen("request-rollback")
        assert store.request_count() == 0
    finally:
        store.close()


def test_state_database_rejects_unknown_schema_version(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    path = state_dir / "broker.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version=99")
    connection.close()
    path.chmod(0o600)
    with pytest.raises(ProtocolError, match="Unsupported"):
        RunnerStateStore(path).start()
