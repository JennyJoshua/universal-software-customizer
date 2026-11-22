from __future__ import annotations

from customizer.source_secret_scan import SourceSecretScanner


def test_detects_high_confidence_credentials_without_returning_values():
    scanner = SourceSecretScanner()
    access_key = b"AKIA" + b"ABCDEFGHIJKLMNOP"
    scanner.feed(b"config = '" + access_key + b"'")
    assert scanner.findings == {"aws_access_key_id"}


def test_detects_private_key_header():
    scanner = SourceSecretScanner()
    scanner.feed(b"-----BEGIN " + b"OPENSSH " + b"PRIVATE KEY-----")
    assert scanner.findings == {"private_key_pem"}


def test_detects_tokens_split_across_chunks():
    scanner = SourceSecretScanner()
    scanner.feed(b"prefix " + b"ghp_" + b"AbCdEfGhIjKlMnOp")
    scanner.feed(b"QrStUvWxYz0123456789abcdef suffix")
    assert scanner.findings == {"github_token"}


def test_scanner_does_not_match_placeholder_or_common_example_values():
    scanner = SourceSecretScanner()
    scanner.feed(b"API_KEY=your-api-key-here\nTOKEN=example-token\n")
    assert scanner.findings == set()


def test_scanner_reports_only_rule_ids_not_secret_values():
    value = b"ghp_" + b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef"
    scanner = SourceSecretScanner()
    scanner.feed(value)
    assert scanner.findings == {"github_token"}
    assert value.decode() not in repr(scanner.findings)


def test_source_snapshot_blocks_detected_credentials_without_echoing_value(tmp_path):
    import pytest
    from customizer.build_runner import _stage_source_snapshot

    source = tmp_path / "source"
    source.mkdir()
    token = b"ghp_" + b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef"
    (source / "config.txt").write_bytes(b"token=" + token)
    with pytest.raises(ValueError, match="github_token") as error:
        _stage_source_snapshot(source, tmp_path / "snapshot")
    assert token.decode() not in str(error.value)


def test_source_snapshot_keeps_known_secret_paths_excluded_from_content_scan(tmp_path):
    from customizer.build_runner import _stage_source_snapshot

    source = tmp_path / "source"
    source.mkdir()
    secret = b"AKIA" + b"ABCDEFGHIJKLMNOP"
    (source / ".env").write_bytes(b"AWS_ACCESS_KEY_ID=" + secret)
    destination = tmp_path / "snapshot"
    _stage_source_snapshot(source, destination)
    assert not (destination / ".env").exists()
