from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

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
    identity = (output.stat().st_dev, output.stat().st_ino)

    def fake_run(argv, **kwargs):
        captured.append(argv)
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true\n", stderr="")
        if argv[1] == "cp":
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(argv)

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    assert _export_container_output("/usr/bin/docker", "export-helper-id", output, identity) is True
    assert captured[0] == ["/usr/bin/docker", "inspect", "--format", "{{.State.Running}}", "export-helper-id"]
    assert captured[1][:3] == ["/usr/bin/docker", "cp", "export-helper-id:/out/."]
    staged_target = Path(captured[1][3])
    assert staged_target.parent == output.parent
    assert staged_target.name.startswith(".usc-export-")


def test_export_refuses_a_stopped_helper(tmp_path, monkeypatch):
    output = tmp_path / "artifacts"
    output.mkdir()
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="false\n", stderr="")

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    assert _export_container_output("/usr/bin/docker", "stopped-helper", output, (output.stat().st_dev, output.stat().st_ino)) is False
    assert len(calls) == 1


def test_output_volume_cleanup_reports_docker_failure(monkeypatch):
    monkeypatch.setattr(
        "customizer.build_runner.subprocess.run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1, stdout="", stderr="volume busy"),
    )
    assert _cleanup_output_volume("/usr/bin/docker", "usc-output-test") is False



def test_export_refuses_output_directory_changed_during_build(tmp_path, monkeypatch):
    output = tmp_path / "artifacts"
    output.mkdir()
    identity = (output.stat().st_dev, output.stat().st_ino)
    moved = tmp_path / "artifacts-original"
    output.rename(moved)
    output.mkdir()
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="true\\n", stderr="")

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    assert _export_container_output("/usr/bin/docker", "export-helper", output, identity) is False
    assert calls == []


def test_export_refuses_nonempty_output_directory_before_copy(tmp_path, monkeypatch):
    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "concurrent.txt").write_text("external", encoding="utf-8")
    identity = (output.stat().st_dev, output.stat().st_ino)
    calls = []

    monkeypatch.setattr(
        "customizer.build_runner.subprocess.run",
        lambda argv, **kwargs: calls.append(argv) or subprocess.CompletedProcess(argv, 0, stdout="true\\n", stderr=""),
    )
    assert _export_container_output("/usr/bin/docker", "export-helper", output, identity) is False
    assert calls == []


def test_export_rechecks_output_after_docker_copy(tmp_path, monkeypatch):
    output = tmp_path / "artifacts"
    output.mkdir()
    identity = (output.stat().st_dev, output.stat().st_ino)

    def fake_run(argv, **kwargs):
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true\\n", stderr="")
        if argv[1] == "cp":
            (output / "concurrent.txt").write_text("concurrent", encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(argv)

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    assert _export_container_output("/usr/bin/docker", "export-helper", output, identity) is False
    assert (output / "concurrent.txt").read_text(encoding="utf-8") == "concurrent"


def test_export_propagates_interrupt_during_copy_for_runner_cleanup(tmp_path, monkeypatch):
    output = tmp_path / "artifacts"
    output.mkdir()
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, stdout="true\\n", stderr="")
        if argv[1] == "cp":
            raise KeyboardInterrupt()
        raise AssertionError(argv)

    monkeypatch.setattr("customizer.build_runner.subprocess.run", fake_run)
    with pytest.raises(KeyboardInterrupt):
        _export_container_output(
            "/usr/bin/docker", "export-helper", output,
            (output.stat().st_dev, output.stat().st_ino),
        )
    assert len(calls) == 2
