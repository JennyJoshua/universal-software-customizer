from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from customizer.build_approval import (
    approve_build_request,
    consume_build_approval,
    create_build_approval_request,
)

IMAGE = "python:3.12-slim@sha256:" + "a" * 64


def _git_source(path):
    path.mkdir()
    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=path, check=True, text=True, capture_output=True,
        ).stdout.strip()
    git("init", "-q")
    git("config", "user.email", "usc-test@example.invalid")
    git("config", "user.name", "USC approval tests")
    (path / "test_sample.py").write_text("def test_fixture():\n    assert True\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "fixture")
    return git


def _state(tmp_path):
    state = tmp_path / "usc-state"
    state.mkdir(mode=0o700)
    return state


def _request(tmp_path, source, *, now=None):
    request = create_build_approval_request(
        source, image=IMAGE, profile="python-pytest",
        timeout_seconds=120, expires_in_seconds=600, now=now,
    )
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    return path, request


def test_request_binds_clean_git_revision_image_profile_and_limits(tmp_path):
    source = tmp_path / "source"
    git = _git_source(source)
    request = create_build_approval_request(
        source, image=IMAGE, profile="python-pytest", timeout_seconds=120,
    )
    assert request["source_git_commit_sha"] == git("rev-parse", "HEAD")
    assert request["source_git_tree_sha"] == git("rev-parse", "HEAD^{tree}")
    assert request["command_argv"] == ["python", "-m", "pytest", "-q"]
    assert request["release_authorized"] is False
    assert request["timeout_seconds"] == 120


def test_request_rejects_dirty_non_git_unknown_profile_and_unpinned_image(tmp_path):
    source = tmp_path / "source"
    _git_source(source)
    (source / "dirty.txt").write_text("uncommitted", encoding="utf-8")
    with pytest.raises(ValueError, match="clean Git source"):
        create_build_approval_request(source, image=IMAGE, profile="python-pytest")

    clean = tmp_path / "clean"
    _git_source(clean)
    with pytest.raises(ValueError, match="Unknown build profile"):
        create_build_approval_request(clean, image=IMAGE, profile="arbitrary")
    with pytest.raises(ValueError, match="sha256 digest"):
        create_build_approval_request(clean, image="python:latest", profile="python-pytest")


def test_approval_requires_explicit_flag_and_issues_receipt(tmp_path):
    source = tmp_path / "source"
    _git_source(source)
    request_path, request = _request(tmp_path, source)
    state = _state(tmp_path)

    with pytest.raises(ValueError, match="--approve"):
        approve_build_request(request_path, approved=False, state_dir=state)

    receipt = approve_build_request(request_path, approved=True, state_dir=state)
    assert receipt["request"] == request
    assert receipt["operation"] == "usc_build_approval_receipt"
    assert len(receipt["hmac_sha256"]) == 64


def test_receipt_is_bound_and_consumed_once(tmp_path):
    source = tmp_path / "source"
    _git_source(source)
    request_path, _ = _request(tmp_path, source)
    state = _state(tmp_path)
    receipt = approve_build_request(request_path, approved=True, state_dir=state)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "artifacts"
    output.mkdir()

    result = consume_build_approval(
        receipt_path, source_path=source, output_path=output, state_dir=state,
    )
    assert result["command"] == ["python", "-m", "pytest", "-q"]
    assert result["image"] == IMAGE
    assert result["output_path"] == str(output.resolve())

    with pytest.raises(ValueError, match="already been used"):
        consume_build_approval(
            receipt_path, source_path=source, output_path=output, state_dir=state,
        )


def test_receipt_tampering_and_wrong_source_are_rejected(tmp_path):
    source = tmp_path / "source"
    git = _git_source(source)
    request_path, _ = _request(tmp_path, source)
    state = _state(tmp_path)
    receipt = approve_build_request(request_path, approved=True, state_dir=state)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "artifacts"
    output.mkdir()

    tampered = dict(receipt)
    tampered["request"] = dict(receipt["request"], image="other@sha256:" + "b" * 64)
    receipt_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="authentication failed"):
        consume_build_approval(receipt_path, source_path=source, output_path=output, state_dir=state)

    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    (source / "new.txt").write_text("changed", encoding="utf-8")
    git("add", ".")
    git("commit", "-qm", "changed")
    with pytest.raises(ValueError, match="does not match the approved revision"):
        consume_build_approval(receipt_path, source_path=source, output_path=output, state_dir=state)


def test_expired_request_and_receipt_are_rejected(tmp_path):
    source = tmp_path / "source"
    _git_source(source)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    request_path, _ = _request(tmp_path, source, now=now)
    state = _state(tmp_path)
    with pytest.raises(ValueError, match="expired"):
        approve_build_request(
            request_path, approved=True, state_dir=state,
            now=now + timedelta(seconds=601),
        )

    receipt = approve_build_request(request_path, approved=True, state_dir=state, now=now)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "artifacts"
    output.mkdir()
    with pytest.raises(ValueError, match="expired"):
        consume_build_approval(
            receipt_path, source_path=source, output_path=output, state_dir=state,
            now=now + timedelta(seconds=601),
        )


def test_cli_build_request_and_approval_commands(tmp_path, capsys, monkeypatch):
    from customizer.cli import main
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr("pathlib.Path.home", lambda: home)

    source = tmp_path / "source"
    _git_source(source)
    request_path = tmp_path / "request.json"
    assert main([
        "build-request", "--path", str(source), "--image", IMAGE,
        "--profile", "python-pytest", "--output", str(request_path),
    ]) == 0
    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert request["operation"] == "usc_build_approval_request"

    receipt_path = tmp_path / "receipt.json"
    assert main([
        "build-approve", "--request", str(request_path),
        "--output", str(receipt_path),
    ]) == 2
    assert "--approve" in capsys.readouterr().err

    assert main([
        "build-approve", "--request", str(request_path),
        "--output", str(receipt_path), "--approve",
    ]) == 0
    assert json.loads(receipt_path.read_text(encoding="utf-8"))["operation"] == "usc_build_approval_receipt"


def test_cli_build_run_consumes_receipt_and_calls_only_approved_profile(tmp_path, monkeypatch, capsys):
    from customizer.cli import main

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    source = tmp_path / "source"
    _git_source(source)
    request_path, _ = _request(tmp_path, source)
    receipt_path = tmp_path / "receipt.json"
    receipt = approve_build_request(request_path, approved=True)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "artifacts"
    output.mkdir()
    captured = {}

    def fake_runner(source_path, output_path, **kwargs):
        captured.update({"source": source_path, "output": output_path, **kwargs})
        return {"status": "passed", "operation": "isolated_build", "executed": True}

    monkeypatch.setattr("customizer.cli.execute_approved_build", fake_runner)
    report_path = tmp_path / "evidence.json"
    assert main([
        "build-run", "--approval", str(receipt_path), "--path", str(source),
        "--output-dir", str(output), "--report", str(report_path),
    ]) == 0
    assert captured["receipt_path"] == str(receipt_path)
    assert captured["source_path"] == source
    assert captured["output_path"] == output
    assert json.loads(report_path.read_text(encoding="utf-8"))["status"] == "passed"

    with pytest.raises(ValueError, match="already been used"):
        consume_build_approval(
            receipt_path, source_path=source, output_path=output,
        )



def test_container_smoke_profile_is_fixed_and_allowlisted():
    from customizer.build_approval import available_build_profiles

    profiles = available_build_profiles()
    assert "python-container-smoke" in profiles
    command = profiles["python-container-smoke"]["command"]
    assert command[:2] == ["python", "-c"]
    assert "os.geteuid()!=0" in command[2]
    assert "'/src'" in command[2]
    assert "'/out'" in command[2]
    assert "connect_ex" in command[2]



def test_nonempty_artifact_directory_does_not_consume_approval(tmp_path):
    source = tmp_path / "source"
    _git_source(source)
    request_path, _ = _request(tmp_path, source)
    state = _state(tmp_path)
    receipt = approve_build_request(request_path, approved=True, state_dir=state)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "keep.txt").write_text("existing", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        consume_build_approval(
            receipt_path, source_path=source, output_path=output, state_dir=state,
        )

    (output / "keep.txt").unlink()
    result = consume_build_approval(
        receipt_path, source_path=source, output_path=output, state_dir=state,
    )
    assert result["approval_id"] == receipt["request"]["approval_id"]



def test_supported_execution_api_requires_a_valid_consumable_receipt(tmp_path, monkeypatch):
    from customizer.build_approval import execute_approved_build

    source = tmp_path / "source"
    _git_source(source)
    output = tmp_path / "artifacts"
    output.mkdir()
    invalid_receipt = tmp_path / "invalid-receipt.json"
    invalid_receipt.write_text("{}", encoding="utf-8")
    called = {"value": False}

    def forbidden_runner(*args, **kwargs):
        called["value"] = True
        raise AssertionError("Low-level runner must not be reached for an invalid receipt.")

    monkeypatch.setattr("customizer.build_runner._run_isolated_build", forbidden_runner)
    with pytest.raises(ValueError, match="invalid structure"):
        execute_approved_build(
            invalid_receipt, source_path=source, output_path=output,
            state_dir=_state(tmp_path),
        )
    assert called["value"] is False


def test_supported_execution_api_consumes_receipt_before_runner(tmp_path, monkeypatch):
    from customizer.build_approval import execute_approved_build

    source = tmp_path / "source"
    _git_source(source)
    request_path, _ = _request(tmp_path, source)
    state = _state(tmp_path)
    receipt = approve_build_request(request_path, approved=True, state_dir=state)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "artifacts"
    output.mkdir()
    captured = {}

    def fake_runner(source_path, output_path, **kwargs):
        captured.update({"source": source_path, "output": output_path, **kwargs})
        return {"status": "passed", "operation": "isolated_build", "executed": True}

    monkeypatch.setattr("customizer.build_runner._run_isolated_build", fake_runner)
    result = execute_approved_build(
        receipt_path, source_path=source, output_path=output, state_dir=state,
    )
    assert result["status"] == "passed"
    assert captured["command"] == ["python", "-m", "pytest", "-q"]
    assert captured["approved"] is True
    with pytest.raises(ValueError, match="already been used"):
        execute_approved_build(
            receipt_path, source_path=source, output_path=output, state_dir=state,
        )
