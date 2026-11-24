from __future__ import annotations

import os
import stat
import sqlite3
import subprocess
import sys
from uuid import uuid4

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
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == 2
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
        first.record_nonce("nonce-fixture-1")
    first.close()

    second = RunnerStateStore(path)
    second.start()
    try:
        assert second.job_count() == 1
        assert second.request_count() == 1
        assert second.request_seen("request-fixture-1")
        assert second.nonce_seen("nonce-fixture-1")
        assert second.approval_seen("approval-fixture-1")
        with pytest.raises(ProtocolError):
            with second.transaction():
                second.record_nonce("nonce-fixture-1")
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



def test_state_database_rejects_corrupt_existing_database(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    path = state_dir / "broker.sqlite3"
    path.write_bytes(b"not-a-sqlite-database")
    path.chmod(0o600)
    with pytest.raises(ProtocolError, match="database"):
        RunnerStateStore(path).start()



def test_state_database_rejects_legacy_schema_v1_without_implicit_migration(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    path = state_dir / "broker.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version=1")
    connection.close()
    path.chmod(0o600)
    with pytest.raises(ProtocolError, match="explicit state reset"):
        RunnerStateStore(path).start()



def _fixture_job(approval_id):
    return {
        "owner_uid": os.getuid(),
        "state": "queued",
        "profile_id": "python-pytest",
        "source_snapshot_sha256": "a" * 64,
        "approval_id": approval_id,
        "release_authorized": False,
    }


def test_state_database_recovers_cleanly_after_process_dies_mid_transaction(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    path = state_dir / "broker.sqlite3"
    script = """
import os, sys
from customizer.runner_state import RunnerStateStore
store = RunnerStateStore(sys.argv[1])
store.start()
store._db.execute("PRAGMA cache_size=1")
with store.transaction():
    store.create_job("crash-job", {
        "owner_uid": os.getuid(),
        "state": "queued",
        "profile_id": "python-pytest",
        "source_snapshot_sha256": "a" * 64,
        "approval_id": "crash-approval",
        "release_authorized": False,
    })
    for index in range(1500):
        store.record_request(f"crash-request-{index:05d}")
    store.record_nonce("crash-nonce")
    os._exit(23)
"""
    child = subprocess.run([sys.executable, "-c", script, str(path)], check=False)
    assert child.returncode == 23

    recovered = RunnerStateStore(path)
    recovered.start()
    try:
        assert recovered.job_count() == 0
        assert recovered.request_count() == 0
        assert not recovered.approval_seen("crash-approval")
        assert not recovered.nonce_seen("crash-nonce")
        assert recovered._db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        recovered.close()


def test_state_database_disk_full_rolls_back_all_replay_writes(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    store = RunnerStateStore(state_dir / "broker.sqlite3")
    store.start()
    try:
        current_pages = store._db.execute("PRAGMA page_count").fetchone()[0]
        effective_limit = store._db.execute(
            f"PRAGMA max_page_count={current_pages}"
        ).fetchone()[0]
        assert effective_limit >= current_pages
        with pytest.raises(sqlite3.DatabaseError):
            with store.transaction():
                store.create_job("full-job", _fixture_job("full-approval"))
                store.record_request("full-request")
                store.record_nonce("full-nonce")
                for index in range(10000):
                    store.record_request(f"fill-request-{index:05d}")
        assert store.job_count() == 0
        assert store.request_count() == 0
        assert not store.approval_seen("full-approval")
        assert not store.nonce_seen("full-nonce")
        assert store._db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        store.close()


def test_state_database_backup_and_restore_preserve_job_and_replay_ledgers(tmp_path):
    state_dir = _private_state_dir(tmp_path)
    source_path = state_dir / "source.sqlite3"
    backup_path = state_dir / "backup.sqlite3"
    source = RunnerStateStore(source_path)
    source.start()
    try:
        with source.transaction():
            source.create_job("backup-job", _fixture_job("backup-approval"))
            source.record_request("backup-request")
            source.record_nonce("backup-nonce")
        backup_connection = sqlite3.connect(backup_path)
        try:
            source._db.backup(backup_connection)
        finally:
            backup_connection.close()
        backup_path.chmod(0o600)
    finally:
        source.close()

    restored = RunnerStateStore(backup_path)
    restored.start()
    try:
        assert restored.get_job("backup-job") == _fixture_job("backup-approval")
        assert restored.request_seen("backup-request")
        assert restored.approval_seen("backup-approval")
        assert restored.nonce_seen("backup-nonce")
        assert restored._db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        restored.close()
