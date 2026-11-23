"""Test-only Unix-domain socket broker for the USC Stage 1 prototype.

Accepts validated synthetic metadata and maintains in-memory state only.
It never starts Docker, runs commands, reads source paths, or exports files.
"""
from __future__ import annotations
import errno
import json
import os
import socket
import stat
import struct
import threading
from pathlib import Path
from uuid import uuid4
from .runner_protocol import MAX_MESSAGE_BYTES, ProtocolError, authorize_peer, decode_message

MAX_JOBS = 1000
MAX_REQUESTS = 10000
CONNECTION_TIMEOUT_SECONDS = 2.0


def _read_request(connection):
    chunks = []
    total = 0
    while True:
        chunk = connection.recv(min(4096, MAX_MESSAGE_BYTES + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_MESSAGE_BYTES:
            raise ProtocolError("Protocol message exceeds the byte limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _peer_uid(connection):
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise ProtocolError("Kernel peer credentials are unavailable on this platform.")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
    except (OSError, struct.error) as exc:
        raise ProtocolError("Could not authenticate local socket peer credentials.") from exc
    return uid


def _send_response(connection, value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        payload = b'{"ok":false,"error":"Response exceeds the protocol byte limit."}'
    connection.sendall(payload)


class LocalRunnerBroker:
    """Single-threaded test broker with a private socket and in-memory job registry."""

    def __init__(self, socket_path, *, submitter_uids=frozenset(), operator_uids=frozenset(), socket_gid=None):
        self.socket_path = Path(socket_path).expanduser()
        if isinstance(socket_gid, bool) or (socket_gid is not None and (not isinstance(socket_gid, int) or socket_gid <= 0)):
            raise ValueError("socket_gid must be a positive group ID.")
        self.socket_gid = socket_gid
        self.submitter_uids = frozenset(submitter_uids)
        self.operator_uids = frozenset(operator_uids)
        self._listener = None
        self._stop = threading.Event()
        self._jobs = {}
        self._request_ids = set()
        self._approval_ids = set()

    def start(self):
        if self._listener is not None:
            raise RuntimeError("Broker is already started.")
        if os.getuid() == 0:
            raise ProtocolError("The local runner broker must not run as root.")
        parent = self.socket_path.parent
        if parent.is_symlink():
            raise ProtocolError("Socket directory must not be a symlink.")
        if self.socket_gid is None:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        elif not parent.is_dir():
            raise ProtocolError("Group-access socket directory must be pre-provisioned by an administrator.")
        parent = parent.resolve(strict=True)
        if self.socket_path.name in {"", ".", ".."}:
            raise ProtocolError("Socket filename is invalid.")
        self.socket_path = parent / self.socket_path.name
        if len(os.fsencode(self.socket_path)) > 100:
            raise ProtocolError("Unix socket path exceeds the supported length.")
        info = parent.stat(follow_symlinks=False)
        directory_mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ProtocolError("Socket directory must be owned by the broker service UID.")
        if self.socket_gid is None:
            if directory_mode != 0o700:
                raise ProtocolError("Socket directory must be private (0700).")
        elif info.st_gid != self.socket_gid or directory_mode != 0o2710:
            raise ProtocolError("Group socket directory must be broker-owned, setgid, group-traversable only (2710), and use the configured client group.")
        if self.socket_path.is_symlink():
            raise ProtocolError("Socket path must not be a symlink.")
        if self.socket_path.exists():
            existing = self.socket_path.stat(follow_symlinks=False)
            expected_mode = 0o600 if self.socket_gid is None else 0o660
            wrong_group = self.socket_gid is not None and existing.st_gid != self.socket_gid
            if (not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != os.getuid()
                    or wrong_group or stat.S_IMODE(existing.st_mode) != expected_mode):
                raise ProtocolError("Refusing to replace a non-owned or incorrectly permissioned socket path.")
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connect_result = probe.connect_ex(str(self.socket_path))
            finally:
                probe.close()
            if connect_result == 0:
                raise ProtocolError("A runner broker is already listening on this socket.")
            if connect_result not in {errno.ECONNREFUSED, errno.ENOENT}:
                raise ProtocolError("Could not safely determine whether the existing socket is stale.")
            self.socket_path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            socket_mode = 0o600 if self.socket_gid is None else 0o660
            os.chmod(self.socket_path, socket_mode)
            socket_info = self.socket_path.stat(follow_symlinks=False)
            wrong_group = self.socket_gid is not None and socket_info.st_gid != self.socket_gid
            if (not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != os.getuid()
                    or wrong_group or stat.S_IMODE(socket_info.st_mode) != socket_mode):
                raise ProtocolError("Socket permissions or ownership do not match the configured access policy.")
            listener.listen(8)
            listener.settimeout(0.2)
        except Exception:
            listener.close()
            try:
                self.socket_path.unlink()
            except OSError:
                pass
            raise
        self._listener = listener
        self._stop.clear()

    def serve_forever(self):
        if self._listener is None:
            raise RuntimeError("Broker must be started before serving.")
        while not self._stop.is_set():
            try:
                connection, _address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            with connection:
                try:
                    connection.settimeout(CONNECTION_TIMEOUT_SECONDS)
                    uid = _peer_uid(connection)
                    message = decode_message(_read_request(connection))
                    result = self._dispatch(uid, message)
                    _send_response(connection, {"ok": True, **result})
                except ProtocolError as exc:
                    _send_response(connection, {"ok": False, "error": str(exc)})
                except Exception:
                    _send_response(connection, {"ok": False, "error": "Broker internal error."})

    def _dispatch(self, peer_uid, message):
        operation = message["operation"]
        request_id = message["request_id"]
        if operation == "submit":
            authorize_peer(peer_uid, operation=operation,
                           submitter_uids=self.submitter_uids, operator_uids=self.operator_uids)
            if request_id in self._request_ids:
                raise ProtocolError("Duplicate request ID.")
            if len(self._jobs) >= MAX_JOBS:
                raise ProtocolError("Broker job capacity has been reached.")
            if len(self._request_ids) >= MAX_REQUESTS:
                raise ProtocolError("Broker request capacity has been reached.")
            job_data = message["job"]
            if job_data["approval_id"] in self._approval_ids:
                raise ProtocolError("Approval ID has already been submitted.")
            job_id = str(uuid4())
            self._jobs[job_id] = {
                "owner_uid": peer_uid, "state": "queued",
                "profile_id": job_data["profile_id"],
                "source_snapshot_sha256": job_data["source_snapshot_sha256"],
                "approval_id": job_data["approval_id"],
                "release_authorized": False,
            }
            self._approval_ids.add(job_data["approval_id"])
            self._request_ids.add(request_id)
            return {"job_id": job_id, "state": "queued"}

        job_id = message["job_id"]
        job = self._jobs.get(job_id)
        if job is None:
            raise ProtocolError("Unknown job or unauthorized operation.")
        try:
            authorize_peer(peer_uid, operation=operation, job_owner_uid=job["owner_uid"],
                           operator_uids=self.operator_uids)
        except ProtocolError as exc:
            raise ProtocolError("Unknown job or unauthorized operation.") from exc
        if request_id in self._request_ids:
            raise ProtocolError("Duplicate request ID.")
        if len(self._request_ids) >= MAX_REQUESTS:
            raise ProtocolError("Broker request capacity has been reached.")
        if operation == "cancel":
            if job["state"] == "queued":
                job["state"] = "cancelled"
            result = {"job_id": job_id, "state": job["state"]}
        elif operation == "status":
            result = {"job_id": job_id, "state": job["state"], "profile_id": job["profile_id"]}
        elif operation == "result":
            result = {"job_id": job_id, "state": job["state"], "result_available": False}
        else:
            raise ProtocolError("Unsupported operation.")
        self._request_ids.add(request_id)
        return result

    def close(self):
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        try:
            info = self.socket_path.stat(follow_symlinks=False)
            if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
                self.socket_path.unlink()
        except FileNotFoundError:
            pass


def send_local_request(socket_path, message, *, timeout=2.0):
    payload = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError("Protocol message exceeds the byte limit.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(socket_path))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        chunks = []
        total = 0
        while True:
            chunk = client.recv(min(4096, MAX_MESSAGE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MESSAGE_BYTES:
                raise ProtocolError("Broker response exceeds the byte limit.")
            chunks.append(chunk)
    try:
        response = json.loads(b"".join(chunks).decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("Broker returned an invalid response.") from exc
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise ProtocolError("Broker response has an invalid structure.")
    return response
