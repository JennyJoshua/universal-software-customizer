"""Broker-owned durable state for the synthetic USC runner prototype.

SQLite is used only for job metadata and replay identifiers. The database must
live in a runner-owned 0700 directory and is never exposed through the socket.
"""
from __future__ import annotations

import os
import sqlite3
import stat
import threading
from contextlib import contextmanager
from pathlib import Path

from .runner_protocol import ProtocolError


class RunnerStateStore:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path).expanduser() if db_path is not None else None
        self._db = None
        self._lock = threading.RLock()
        self._jobs = {}
        self._request_ids = set()
        self._approval_ids = set()

    def start(self):
        if self.db_path is None:
            return
        if self._db is not None:
            raise RuntimeError("Runner state store is already started.")
        if not self.db_path.is_absolute():
            raise ProtocolError("Runner state database path must be absolute.")
        parent = self.db_path.parent
        if parent.is_symlink():
            raise ProtocolError("Runner state directory must not be a symlink.")
        parent = parent.resolve(strict=True)
        self.db_path = parent / self.db_path.name
        if self.db_path.is_symlink():
            raise ProtocolError("Runner state database must not be a symlink.")
        parent_info = parent.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700):
            raise ProtocolError("Runner state directory must be service-owned and private (0700).")

        existed = self.db_path.exists()
        if existed:
            info = self.db_path.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ProtocolError("Existing runner state database must be a single-link service-owned regular file (0600).")

        previous_umask = os.umask(0o077)
        try:
            self._db = sqlite3.connect(
                str(self.db_path),
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.DatabaseError as exc:
            self._db = None
            raise ProtocolError("Could not safely open runner state database.") from exc
        finally:
            os.umask(previous_umask)

        try:
            if not existed:
                os.chmod(self.db_path, 0o600)
            info = self.db_path.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ProtocolError("Runner state database permissions or ownership are unsafe.")
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA trusted_schema=OFF")
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ProtocolError("Unsupported runner state database version.")
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    owner_uid INTEGER NOT NULL CHECK(owner_uid > 0),
                    state TEXT NOT NULL CHECK(state IN ('queued', 'cancelled')),
                    profile_id TEXT NOT NULL,
                    source_snapshot_sha256 TEXT NOT NULL,
                    approval_id TEXT NOT NULL UNIQUE,
                    release_authorized INTEGER NOT NULL DEFAULT 0 CHECK(release_authorized = 0)
                );
                CREATE TABLE IF NOT EXISTS seen_requests (
                    request_id TEXT PRIMARY KEY
                );
                """
            )
            self._db.execute("PRAGMA user_version=1")
            integrity = self._db.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise ProtocolError("Runner state database integrity check failed.")
        except Exception:
            self.close()
            raise

    @contextmanager
    def transaction(self):
        with self._lock:
            if self._db is None:
                yield
                return
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def request_seen(self, request_id):
        if self._db is None:
            return request_id in self._request_ids
        return self._db.execute(
            "SELECT 1 FROM seen_requests WHERE request_id = ?", (request_id,)
        ).fetchone() is not None

    def record_request(self, request_id):
        if self._db is None:
            self._request_ids.add(request_id)
        else:
            self._db.execute(
                "INSERT INTO seen_requests(request_id) VALUES (?)", (request_id,)
            )

    def approval_seen(self, approval_id):
        if self._db is None:
            return approval_id in self._approval_ids
        return self._db.execute(
            "SELECT 1 FROM jobs WHERE approval_id = ?", (approval_id,)
        ).fetchone() is not None

    def job_count(self):
        if self._db is None:
            return len(self._jobs)
        return self._db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]

    def request_count(self):
        if self._db is None:
            return len(self._request_ids)
        return self._db.execute("SELECT COUNT(*) FROM seen_requests").fetchone()[0]

    def get_job(self, job_id):
        if self._db is None:
            job = self._jobs.get(job_id)
            return dict(job) if job is not None else None
        row = self._db.execute(
            """SELECT owner_uid, state, profile_id, source_snapshot_sha256,
                      approval_id, release_authorized
               FROM jobs WHERE job_id = ?""",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "owner_uid": row[0],
            "state": row[1],
            "profile_id": row[2],
            "source_snapshot_sha256": row[3],
            "approval_id": row[4],
            "release_authorized": bool(row[5]),
        }

    def create_job(self, job_id, job):
        if self._db is None:
            self._jobs[job_id] = dict(job)
            self._approval_ids.add(job["approval_id"])
            return
        self._db.execute(
            """INSERT INTO jobs(
                   job_id, owner_uid, state, profile_id, source_snapshot_sha256,
                   approval_id, release_authorized
               ) VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (
                job_id,
                job["owner_uid"],
                job["state"],
                job["profile_id"],
                job["source_snapshot_sha256"],
                job["approval_id"],
            ),
        )

    def set_job_state(self, job_id, state):
        if self._db is None:
            self._jobs[job_id]["state"] = state
        else:
            self._db.execute(
                "UPDATE jobs SET state = ? WHERE job_id = ?", (state, job_id)
            )

    def close(self):
        if self._db is not None:
            self._db.close()
            self._db = None
