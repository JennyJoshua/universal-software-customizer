import argparse
import pytest

from customizer.local_runner_broker import _positive_int


@pytest.mark.parametrize("value", ["0", "-1", "not-a-number"])
def test_cli_uid_and_gid_arguments_require_positive_integers(value):
    with pytest.raises(argparse.ArgumentTypeError):
        _positive_int(value)


@pytest.mark.parametrize("value,expected", [("1", 1), ("10042", 10042)])
def test_cli_uid_and_gid_arguments_accept_positive_integers(value, expected):
    assert _positive_int(value) == expected
