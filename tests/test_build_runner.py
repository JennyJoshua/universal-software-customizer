from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from customizer.build_runner import _probe_toolchain, _stage_source_snapshot, _toolchain_inventory_digest, run_isolated_build


IMAGE = "python:3.12-slim@sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def _mock_bounded_export_volume(monkeypatch):
    monkeypatch.setattr("customizer.build_runner._create_output_volume", lambda *args, **kwargs: True)
    monkeypatch.setattr("customizer.build_runner._start_export_helper", lambda *args, **kwargs: "fixture-exporter")
    monkeypatch.setattr("customizer.build_runner._cleanup_output_volume", lambda *args, **kwargs: True)


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    output.mkdir()
    return source, output


def test_build_requires_explicit_approval_and_does_not_probe_docker(tmp_path, monkeypatch):
    source, output = _paths(tmp_path)

    def unexpected_which(_name):
        raise AssertionError("Docker must not be inspected before approval.")

    monkeypatch.setattr("customizer.build_runner.shutil.which", unexpected_which)
    report = run_isolated_build(
        source, output, image=IMAGE, command=["python", "-m", "pytest"],
    )

    assert report["status"] == "blocked_approval_required"
    assert report["executed"] is False


@pytest.mark.parametrize(
    ("image", "command", "timeout"),
    [
        ("python:latest", ["python", "-m", "pytest"], 30),
        (IMAGE, ["sh", "-c", "echo unsafe"], 30),
        (IMAGE, ["python", "-m", "pytest"], 0),
        (IMAGE, ["python", "-m", "pytest", "--token=do-not-log-this"], 30),
        (IMAGE, ["python", "-m", "pytest", "https://user:pass@example.test"], 30),
    ],
)
def test_invalid_execution_profiles_are_blocked(tmp_path, image, command, timeout):
    source, output = _paths(tmp_path)
    report = run_isolated_build(
        source, output, image=image, command=command, approved=True,
        timeout_seconds=timeout,
    )
    assert report["status"] == "blocked_invalid_request"
    assert report["executed"] is False


def test_output_directory_cannot_contain_or_enclose_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    report = run_isolated_build(
        source, tmp_path, image=IMAGE, command=["python", "-m", "pytest"],
        approved=True,
    )
    assert report["status"] == "blocked_invalid_request"
    assert "ancestor or descendant" in report["errors"][0]


def test_runner_fails_closed_when_docker_is_unavailable(tmp_path, monkeypatch):
    source, output = _paths(tmp_path)
    (source / ".usc").mkdir()
    baseline = source / ".usc" / "upstream-baseline.json"
    baseline.write_text('{"baseline":"fixture"}', encoding="utf-8")
    before = baseline.read_bytes()
    monkeypatch.setattr("customizer.build_runner.shutil.which", lambda _name: None)
    report = run_isolated_build(
        source, output, image=IMAGE, command=["python", "-m", "pytest"],
        approved=True,
    )
    assert report["status"] == "blocked_isolation_unavailable"
    assert report["executed"] is False
    assert baseline.read_bytes() == before


def test_runner_uses_restricted_container_and_reports_success(tmp_path, monkeypatch):
    source, output = _paths(tmp_path)
    (source / "app").mkdir()
    (source / "app" / "main.py").write_text("print('fixture')", encoding="utf-8")
    (source / ".env").write_text("SECRET_VALUE=must-not-be-mounted", encoding="utf-8")
    (source / ".env.example").write_text("PUBLIC_VALUE=example", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("[remote]", encoding="utf-8")
    (source / ".usc").mkdir()
    (source / ".usc" / "upstream-baseline.json").write_text("{}", encoding="utf-8")
    source_before = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.rglob("*") if path.is_file()
    }
    captured = {}

    class FakeProcess:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            source_mount = next(item for item in argv if "dst=/src,readonly" in item)
            staged_root = Path(source_mount.split("src=", 1)[1].split(",dst=", 1)[0])
            captured["staged_root"] = str(staged_root)
            captured["staged_files"] = sorted(
                path.relative_to(staged_root).as_posix()
                for path in staged_root.rglob("*") if path.is_file()
            )
            captured["staged_env_example"] = (staged_root / ".env.example").read_text(encoding="utf-8")
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"fixture tests passed\\n")
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    ps_calls = {"count": 0}

    def fake_run(argv, **kwargs):
        if "-C" in argv:
            return subprocess.CompletedProcess(argv, 128, stdout=b"", stderr=b"not a Git repository")
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, stdout="27.0", stderr="")
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:" + "b" * 64, stderr="")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true", stderr="")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true", stderr="")
        if argv[1] == "cp":
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if argv[1:3] == ["ps", "-aq"]:
            ps_calls["count"] += 1
            found = "fixture-container" if ps_calls["count"] < 3 else ""
            return subprocess.CompletedProcess(argv, 0, stdout=found, stderr="")
        if argv[1:3] == ["rm", "-f"]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected host command: {argv}")

    monkeypatch.setattr("customizer.build_runner.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    monkeypatch.setattr("customizer.build_runner._probe_toolchain", lambda *args, **kwargs: [])

    report = run_isolated_build(
        source, output, image=IMAGE, command=["python", "-m", "pytest"],
        approved=True,
    )

    argv = captured["argv"]
    assert "--network=none" in argv
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges:true" in argv
    assert "--pull=never" in argv
    assert any(item.startswith("--mount=type=volume,src=usc-output-") and item.endswith(",dst=/out") for item in argv)
    assert f"--mount=type=bind,src={captured['staged_root']},dst=/src,readonly" in argv
    assert Path(captured["staged_root"]) != source.resolve()
    assert "app/main.py" in captured["staged_files"]
    assert ".env.example" in captured["staged_files"]
    assert ".env" not in captured["staged_files"]
    assert ".git/config" not in captured["staged_files"]
    assert ".usc/upstream-baseline.json" not in captured["staged_files"]
    assert captured["staged_env_example"] == "PUBLIC_VALUE=example"
    assert not any(f"src={output.resolve()}" in item for item in argv)
    assert "--env=HOME=/tmp" in argv
    assert report["status"] == "passed"
    assert report["source_read_only"] is True
    assert report["network_disabled"] is True
    assert report["container_cleanup_confirmed"] is True
    assert report["output_volume_cleanup_confirmed"] is True
    assert report["export_helper_image"].startswith("busybox@sha256:")
    assert report["export_helper_image_id"] == "sha256:" + "b" * 64
    assert report["artifact_exported"] is True
    assert report["docker_image_id"] == "sha256:" + "b" * 64
    assert report["command_sha256"] and len(report["command_sha256"]) == 64
    assert report["logs_sha256"] and len(report["logs_sha256"]) == 64
    assert report["started_at"] and report["finished_at"]
    assert report["duration_seconds"] >= 0
    assert len(report["source_snapshot_sha256"]) == 64
    assert report["source_git_commit_sha"] is None
    assert report["source_git_tree_sha"] is None
    assert report["source_worktree_clean"] is False
    assert report["source_git_identity_error"]
    assert report["excluded_source_path_count"] >= 3
    assert report["logs"] == "fixture tests passed\\n"
    source_after = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.rglob("*") if path.is_file()
    }
    assert source_after == source_before


def test_runner_marks_container_cleanup_failure_as_blocked(tmp_path, monkeypatch):
    source, output = _paths(tmp_path)
    (source / ".usc").mkdir()
    baseline = source / ".usc" / "upstream-baseline.json"
    baseline.write_text('{"baseline":"fixture"}', encoding="utf-8")
    before = baseline.read_bytes()

    class FakeProcess:
        def __init__(self, _argv, **_kwargs):
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    ps_calls = {"count": 0}

    def fake_run(argv, **kwargs):
        if "-C" in argv:
            return subprocess.CompletedProcess(argv, 128, stdout=b"", stderr=b"not a Git repository")
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, stdout="27.0", stderr="")
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:" + "b" * 64, stderr="")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true", stderr="")
        if argv[1] == "cp":
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if argv[1:3] == ["ps", "-aq"]:
            ps_calls["count"] += 1
            if ps_calls["count"] == 1:
                return subprocess.CompletedProcess(argv, 0, stdout="fixture-container", stderr="")
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="daemon error")
        if argv[1:3] == ["rm", "-f"]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected host command: {argv}")

    monkeypatch.setattr("customizer.build_runner.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    inventory = [{
        "name": "python",
        "status": "available",
        "exit_code": 0,
        "version": "Python 3.12.4",
        "output_sha256": "c" * 64,
    }]
    monkeypatch.setattr("customizer.build_runner._probe_toolchain", lambda *args, **kwargs: inventory)

    report = run_isolated_build(
        source, output, image=IMAGE, command=["python", "-m", "pytest"],
        approved=True,
    )
    assert report["toolchain_inventory"] == inventory
    assert report["toolchain_inventory_sha256"] == _toolchain_inventory_digest(inventory)
    assert report["status"] == "blocked_cleanup_failed"
    assert report["container_cleanup_confirmed"] is False
    assert baseline.read_bytes() == before



def test_runner_requires_an_empty_output_directory(tmp_path):
    source, output = _paths(tmp_path)
    (output / "existing.txt").write_text("keep", encoding="utf-8")
    report = run_isolated_build(
        source, output, image=IMAGE, command=["python", "-m", "pytest"],
        approved=True,
    )
    assert report["status"] == "blocked_invalid_request"
    assert (output / "existing.txt").read_text(encoding="utf-8") == "keep"



def test_runner_kills_container_when_log_limit_is_exceeded(tmp_path, monkeypatch):
    source, output = _paths(tmp_path)
    (source / ".usc").mkdir()
    baseline = source / ".usc" / "upstream-baseline.json"
    baseline.write_text('{"baseline":"fixture"}', encoding="utf-8")
    before = baseline.read_bytes()
    killed = {"value": False}

    class FakeProcess:
        def __init__(self, _argv, **_kwargs):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"x" * 2048)
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            killed["value"] = True
            self.returncode = -9

    ps_calls = {"count": 0}

    def fake_run(argv, **kwargs):
        if "-C" in argv:
            return subprocess.CompletedProcess(argv, 128, stdout=b"", stderr=b"not a Git repository")
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, stdout="27.0", stderr="")
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:" + "b" * 64, stderr="")
        if argv[1:3] == ["ps", "-aq"]:
            ps_calls["count"] += 1
            found = "fixture-container" if ps_calls["count"] == 1 else ""
            return subprocess.CompletedProcess(argv, 0, stdout=found, stderr="")
        if argv[1:3] == ["rm", "-f"]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected host command: {argv}")

    monkeypatch.setattr("customizer.build_runner.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    monkeypatch.setattr("customizer.build_runner._probe_toolchain", lambda *args, **kwargs: [])

    report = run_isolated_build(
        source, output, image=IMAGE, command=["python", "-m", "pytest"],
        approved=True, max_log_bytes=1024,
    )
    assert report["status"] == "output_limit_exceeded"
    assert report["log_bytes"] == 1024
    assert report["log_truncated"] is True
    assert killed["value"] is True
    assert report["container_cleanup_confirmed"] is True
    assert baseline.read_bytes() == before


def test_runner_stops_execution_at_timeout(tmp_path, monkeypatch):
    import io

    source, output = _paths(tmp_path)
    (source / ".usc").mkdir()
    baseline = source / ".usc" / "upstream-baseline.json"
    baseline.write_text('{"baseline":"fixture"}', encoding="utf-8")
    before = baseline.read_bytes()
    killed = {"value": False}

    class FakeSelector:
        def register(self, *_args, **_kwargs):
            return None

        def get_map(self):
            return {1: object()}

        def select(self, timeout=None):
            return []

        def close(self):
            return None

    class FakeProcess:
        def __init__(self, _argv, **_kwargs):
            self.stdout = io.BytesIO()
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            killed["value"] = True
            self.returncode = -9

    def fake_run(argv, **kwargs):
        if "-C" in argv:
            return subprocess.CompletedProcess(argv, 128, stdout=b"", stderr=b"not a Git repository")
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, stdout="27.0", stderr="")
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:" + "b" * 64, stderr="")
        if argv[1:3] == ["ps", "-aq"]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected host command: {argv}")

    monkeypatch.setattr("customizer.build_runner.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    monkeypatch.setattr("customizer.build_runner._probe_toolchain", lambda *args, **kwargs: [])
    monkeypatch.setattr("customizer.build_runner.selectors.DefaultSelector", FakeSelector)
    clock = iter([100.0, 102.0, 102.0])
    monkeypatch.setattr("customizer.build_runner.time.monotonic", lambda: next(clock))

    report = run_isolated_build(
        source, output, image=IMAGE, command=["python", "-m", "pytest"],
        approved=True, timeout_seconds=1,
    )
    assert report["status"] == "timed_out"
    assert killed["value"] is True
    assert report["container_cleanup_confirmed"] is True
    assert baseline.read_bytes() == before



def test_source_snapshot_hash_is_deterministic_and_excludes_known_secret_paths(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app").mkdir()
    (source / "app" / "main.py").write_text("print('hello')", encoding="utf-8")
    (source / "app" / "main.py").chmod(0o4755)
    (source / ".env").write_text("TOKEN=secret", encoding="utf-8")
    (source / ".env.example").write_text("TOKEN=example", encoding="utf-8")
    (source / ".npmrc").write_text("//registry/:_authToken=secret", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("private metadata", encoding="utf-8")
    (source / ".usc").mkdir()
    (source / ".usc" / "provenance.json").write_text("private provenance", encoding="utf-8")

    first = tmp_path / "snapshot-one"
    second = tmp_path / "snapshot-two"
    first_hash, first_excluded = _stage_source_snapshot(source, first)
    second_hash, second_excluded = _stage_source_snapshot(source, second)

    assert first_hash == second_hash
    assert len(first_hash) == 64
    assert first_excluded == second_excluded
    assert (first / "app" / "main.py").is_file()
    assert (first / "app" / "main.py").stat().st_mode & 0o7777 == 0o755
    assert (first / ".env.example").is_file()
    assert not (first / ".env").exists()
    assert not (first / ".npmrc").exists()
    assert not (first / ".git").exists()
    assert not (first / ".usc").exists()


def test_source_snapshot_rejects_symlinks(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (source / "linked.txt").symlink_to(outside)
    with pytest.raises(ValueError, match="symlinked file"):
        _stage_source_snapshot(source, tmp_path / "snapshot")



@pytest.mark.parametrize(("exit_code", "expected_status"), [(127, "failed"), (23, "failed")])
def test_runner_records_missing_command_and_nonzero_exit_without_source_mutation(
    tmp_path, monkeypatch, exit_code, expected_status,
):
    source, output = _paths(tmp_path)
    (source / "app.py").write_text("synthetic source\\n", encoding="utf-8")
    (source / ".usc").mkdir()
    baseline = source / ".usc" / "upstream-baseline.json"
    baseline.write_text('{"baseline":"fixture"}', encoding="utf-8")
    before = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.rglob("*") if path.is_file()
    }

    class FakeProcess:
        def __init__(self, _argv, **_kwargs):
            read_fd, write_fd = os.pipe()
            message = b"command not found\\n" if exit_code == 127 else b"fixture test failed\\n"
            os.write(write_fd, message)
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.returncode = exit_code

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    ps_calls = {"count": 0}

    def fake_run(argv, **kwargs):
        if "-C" in argv:
            return subprocess.CompletedProcess(argv, 128, stdout=b"", stderr=b"not a Git repository")
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, stdout="27.0", stderr="")
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:" + "b" * 64, stderr="")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true", stderr="")
        if argv[1] == "cp":
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if argv[1:3] == ["ps", "-aq"]:
            ps_calls["count"] += 1
            return subprocess.CompletedProcess(
                argv, 0, stdout="fixture-container" if ps_calls["count"] == 1 else "", stderr=""
            )
        if argv[1:3] == ["rm", "-f"]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected host command: {argv}")

    monkeypatch.setattr("customizer.build_runner.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    monkeypatch.setattr("customizer.build_runner._probe_toolchain", lambda *args, **kwargs: [])

    report = run_isolated_build(
        source, output, image=IMAGE, command=["missing-build-tool"],
        approved=True,
    )
    after = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.rglob("*") if path.is_file()
    }
    assert report["status"] == expected_status
    assert report["exit_code"] == exit_code
    assert report["container_cleanup_confirmed"] is True
    assert after == before


def test_runner_rejects_symlinked_source_directories(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside source", encoding="utf-8")
    (source / "linked-directory").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlinked directory"):
        _stage_source_snapshot(source, tmp_path / "snapshot")


def test_runner_cleans_up_after_interrupted_execution_without_mutating_source(tmp_path, monkeypatch):
    import io

    source, output = _paths(tmp_path)
    (source / "app.py").write_text("synthetic source\\n", encoding="utf-8")
    (source / ".usc").mkdir()
    baseline = source / ".usc" / "upstream-baseline.json"
    baseline.write_text('{"baseline":"fixture"}', encoding="utf-8")
    before = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.rglob("*") if path.is_file()
    }
    killed = {"value": False}
    removed = {"value": False}

    class FakeSelector:
        def register(self, *_args, **_kwargs):
            return None

        def get_map(self):
            return {1: object()}

        def select(self, timeout=None):
            raise KeyboardInterrupt()

        def close(self):
            return None

    class FakeProcess:
        def __init__(self, _argv, **_kwargs):
            self.stdout = io.BytesIO()
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            killed["value"] = True
            self.returncode = -9

    ps_calls = {"count": 0}

    def fake_run(argv, **kwargs):
        if "-C" in argv:
            return subprocess.CompletedProcess(argv, 128, stdout=b"", stderr=b"not a Git repository")
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, stdout="27.0", stderr="")
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, stdout="sha256:" + "b" * 64, stderr="")
        if argv[1:3] == ["ps", "-aq"]:
            ps_calls["count"] += 1
            found = "fixture-container" if ps_calls["count"] == 1 else ""
            return subprocess.CompletedProcess(argv, 0, stdout=found, stderr="")
        if argv[1:3] == ["rm", "-f"]:
            removed["value"] = True
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"Unexpected host command: {argv}")

    monkeypatch.setattr("customizer.build_runner.shutil.which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    monkeypatch.setattr("customizer.build_runner._probe_toolchain", lambda *args, **kwargs: [])
    monkeypatch.setattr("customizer.build_runner.selectors.DefaultSelector", FakeSelector)

    with pytest.raises(KeyboardInterrupt):
        run_isolated_build(
            source, output, image=IMAGE, command=["python", "-m", "pytest"],
            approved=True,
        )

    after = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source.rglob("*") if path.is_file()
    }
    assert killed["value"] is True
    assert removed["value"] is True
    assert after == before



def test_toolchain_probe_captures_version_in_network_disabled_disposable_container(tmp_path, monkeypatch):
    captured = []

    class FakeProcess:
        def __init__(self, argv, **_kwargs):
            captured.append(argv)
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"Python 3.12.4\n")
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    inventory = _probe_toolchain(
        "/usr/bin/docker", IMAGE, "com.usc.test=toolchain",
        probes=[("python", ("--version",))],
    )

    assert inventory == [{
        "name": "python",
        "status": "available",
        "exit_code": 0,
        "version": "Python 3.12.4",
        "output_sha256": hashlib.sha256(b"Python 3.12.4\n").hexdigest(),
    }]
    argv = captured[0]
    assert "--network=none" in argv
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    assert "--pull=never" in argv
    assert "--rm" in argv
    assert "--entrypoint" in argv
    assert "python" in argv
    assert not any(item.startswith("--mount=") for item in argv)
    assert _toolchain_inventory_digest(inventory) == hashlib.sha256(
        __import__("json").dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def test_toolchain_probe_bounds_output_and_terminates_probe(tmp_path, monkeypatch):
    killed = {"value": False}

    class FakeProcess:
        def __init__(self, _argv, **_kwargs):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"x" * 8192)
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            killed["value"] = True
            self.returncode = -9

    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    inventory = _probe_toolchain(
        "/usr/bin/docker", IMAGE, "com.usc.test=toolchain",
        probes=[("python", ("--version",))],
        max_output_bytes=1024,
    )

    assert inventory[0]["status"] == "output_limit_exceeded"
    assert inventory[0]["exit_code"] == -9
    assert len(inventory[0]["output_sha256"]) == 64
    assert killed["value"] is True


def test_toolchain_probe_times_out_and_kills_unresponsive_probe(tmp_path, monkeypatch):
    killed = {"value": False}

    class FakeProcess:
        def __init__(self, _argv, **_kwargs):
            self.read_fd, self.write_fd = os.pipe()
            self.stdout = os.fdopen(self.read_fd, "rb")
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            killed["value"] = True
            self.returncode = -9
            os.close(self.write_fd)

    monkeypatch.setattr("customizer.build_runner.subprocess.Popen", FakeProcess)
    inventory = _probe_toolchain(
        "/usr/bin/docker", IMAGE, "com.usc.test=toolchain",
        probes=[("python", ("--version",))],
        timeout_seconds=0.01,
    )

    assert inventory[0]["status"] == "timed_out"
    assert inventory[0]["exit_code"] == -9
    assert killed["value"] is True
