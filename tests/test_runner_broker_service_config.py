from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_systemd_example_is_explicitly_guarded_and_hardened():
    unit = (ROOT / "deploy/systemd/usc-runner-broker.service.example").read_text(encoding="utf-8")
    required = [
        "ConditionPathExists=/etc/usc-runner/ENABLE_SYNTHETIC_ONLY",
        "User=usc-runner",
        "Group=usc-clients",
        "RuntimeDirectoryMode=2710",
        "StateDirectoryMode=0700",
        "Restart=no",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateNetwork=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "RestrictAddressFamilies=AF_UNIX",
        "CapabilityBoundingSet=",
        "ReadWritePaths=/run/usc-runner /var/lib/usc-runner",
    ]
    for setting in required:
        assert setting in unit
    assert "docker.sock" not in unit
    assert "publish" not in unit.lower()
    assert "deploy" not in unit.lower()


def test_broker_environment_example_contains_no_active_placeholder_values():
    env = (ROOT / "deploy/systemd/broker.env.example").read_text(encoding="utf-8")
    assert "USC_CLIENT_GID=<" in env
    assert "USC_CONTROL_UID=<" in env
    assert not any(line.startswith("USC_CLIENT_GID=") for line in env.splitlines())
    assert not any(line.startswith("USC_CONTROL_UID=") for line in env.splitlines())
