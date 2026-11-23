"""High-confidence, content-based secret checks for staged source files.

This is a defence-in-depth scanner, not a complete secret detector. It reports rule
identifiers and paths only; matched credential values are never included in errors.
"""
from __future__ import annotations

import re


_SECRET_PATTERNS = (
    ("private_key_pem", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("aws_access_key_id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("gitlab_token", re.compile(rb"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("google_oauth_client_secret", re.compile(rb"\bGOCSPX-[A-Za-z0-9_-]{20,}\b")),
    ("stripe_live_secret", re.compile(rb"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    ("openai_api_key", re.compile(rb"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_api_key", re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("huggingface_token", re.compile(rb"\bhf_[A-Za-z0-9]{20,}\b")),
    ("npm_token", re.compile(rb"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("pypi_token", re.compile(rb"\bpypi-[A-Za-z0-9_-]{30,}\b")),
)
_OVERLAP_BYTES = 4096


class SourceSecretScanner:
    """Incrementally scan bounded file chunks without retaining credential contents."""

    def __init__(self) -> None:
        self._tail = b""
        self.findings: set[str] = set()

    def feed(self, chunk: bytes) -> None:
        if not isinstance(chunk, bytes):
            raise TypeError("Secret scanner input must be bytes.")
        window = self._tail + chunk
        for rule_id, pattern in _SECRET_PATTERNS:
            if pattern.search(window):
                self.findings.add(rule_id)
        self._tail = window[-_OVERLAP_BYTES:]
