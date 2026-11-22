from __future__ import annotations

import os
import subprocess
from pathlib import Path

from customizer.build_runner import (
    _EXPORT_HELPER_IMAGE,
    _cleanup_output_volume,
    _create_output_volume,
    _export_container_output,
    _start_export_helper,
)


def test_output_volume_is_local_tmpfs_with_fixed_size_and_private_owner(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="usc-output-test\n", stderr="")

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    assert _create_output_volume("/usr/bin/docker", "usc-output-test", "abc123") is True
    argv = captured["argv"]
    assert argv[:3] == ["/usr/bin/docker", "volume", "create"]
    assert "--driver" in argv and "local" in argv
    assert "type=tmpfs" in argv
    assert "device=tmpfs" in argv
    options = next(item for item in argv if item.startswith("o=size="))
    assert options == f"o=size=256m,uid={os.getuid()},gid={os.getgid()},mode=0700"
    assert "com.usc.build-volume=abc123" in argv


def test_export_helper_is_pinned_unprivileged_and_keeps_volume_read_only(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="export-helper-id\n", stderr="")

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    result = _start_export_helper("/usr/bin/docker", "usc-output-test", "com.usc.build-run=abc123")
    assert result == "export-helper-id"
    argv = captured["argv"]
    assert argv[:3] == ["/usr/bin/docker", "run", "-d"]
    assert "--pull=never" in argv
    assert "--network=none" in argv
    assert "--read-only" in argv
    assert f"--user={os.getuid()}:{os.getgid()}" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges:true" in argv
    assert "--pids-limit=16" in argv
    assert "--memory=64m" in argv
    assert "--cpus=0.25" in argv
    assert "--mount=type=volume,src=usc-output-test,dst=/out,readonly" in argv
    assert f"--label=com.usc.build-run=abc123" in argv
    assert argv[-2:] == [_EXPORT_HELPER_IMAGE, "7200"]


def test_export_requires_helper_to_be_running_and_copies_from_that_container(tmp_path, monkeypatch):
    captured = []
    output = tmp_path / "artifacts"
    output.mkdir()

    def fake_run(argv, **kwargs):
        captured.append(argv)
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true\n", stderr="")
        if argv[1] == "cp":
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(argv)

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    assert _export_container_output("/usr/bin/docker", "export-helper-id", output) is True
    assert captured[0] == ["/usr/bin/docker", "inspect", "--format", "{{.State.Running}}", "export-helper-id"]
    assert captured[1] == ["/usr/bin/docker", "cp", "export-helper-id:/out/.", str(output)]


def test_export_refuses_a_stopped_helper(tmp_path, monkeypatch):
    output = tmp_path / "artifacts"
    output.mkdir()
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="false\n", stderr="")

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    assert _export_container_output("/usr/bin/docker", "stopped-helper", output) is False
    assert len(calls) == 1


def test_output_volume_cleanup_reports_docker_failure(monkeypatch):
    monkeypatch.setattr(
        "customizer.build_runner.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, stdout="", stderr="volume busy"),
    )
    assert _cleanup_output_volume("/usr/bin/docker", "usc-output-test") is False
