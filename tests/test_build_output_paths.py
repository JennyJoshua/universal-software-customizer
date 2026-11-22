from __future__ import annotations

import pytest

from customizer.build_runner import _validate_request

IMAGE = "python:3.12-slim@sha256:" + "a" * 64
COMMAND = ["python", "-c", "print('synthetic')"]


def _validate(source, output):
    return _validate_request(
        source, output, IMAGE, COMMAND, timeout_seconds=60, max_log_bytes=4096,
    )


def test_output_must_be_outside_source_tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    nested = source / "output"
    nested.mkdir()
    with pytest.raises(ValueError, match="separate"):
        _validate(source, nested)


def test_output_must_not_be_an_ancestor_of_source(tmp_path):
    output = tmp_path / "root"
    source = output / "source"
    source.mkdir(parents=True)
    with pytest.raises(ValueError, match="separate"):
        _validate(source, output)


def test_output_must_not_traverse_a_symlinked_parent(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    output = linked_parent / "output"
    output.mkdir()
    with pytest.raises(ValueError, match="symlink"):
        _validate(source, output)


def test_output_must_not_be_a_symlink(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    actual_output = tmp_path / "actual-output"
    actual_output.mkdir()
    linked_output = tmp_path / "linked-output"
    linked_output.symlink_to(actual_output, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        _validate(source, linked_output)


def test_output_directory_must_be_empty_before_execution(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    (output / "external.txt").write_text("outside", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        _validate(source, output)
